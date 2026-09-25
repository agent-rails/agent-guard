from __future__ import annotations

import pytest

from agent_guard import (
    ApprovalGrant,
    BlockedError,
    CallableJudge,
    Decision,
    Guard,
    JudgeRequest,
    MemoryAuditSink,
    PolicyModule,
    PolicyRegistry,
    clamp,
)


def raw_dispatch(tool: str, args: dict) -> str:
    return f"ran:{tool}"


def build_registry() -> PolicyRegistry:
    org = PolicyModule.from_dict(
        {
            "name": "org-base",
            "namespace": "*",
            "layer": 100,
            "rules": [
                {
                    "id": "org-no-drop",
                    "decision": "deny",
                    "tools": ["sql"],
                    "arg_patterns": [r"(?i)drop table"],
                    "reason": "org bans destructive sql",
                }
            ],
        }
    )
    provider = PolicyModule.from_dict(
        {
            "name": "sql-provider-defaults",
            "namespace": "sql*",
            "layer": 0,
            "rules": [
                {"id": "sql-allow-read", "decision": "allow", "tools": ["sql"], "reason": "provider default: reads ok"}
            ],
        }
    )
    return PolicyRegistry(default=Decision.DENY).register(org).register(provider)


def test_higher_layer_wins():
    compiled = build_registry().compile()
    drop = compiled.evaluate("sql", {"q": "DROP TABLE users"})
    assert drop.decision is Decision.DENY
    assert drop.module == "org-base"
    assert drop.layer == 100


def test_lower_layer_applies_when_higher_does_not_match():
    compiled = build_registry().compile()
    read = compiled.evaluate("sql", {"q": "SELECT 1"})
    assert read.decision is Decision.ALLOW
    assert read.module == "sql-provider-defaults"


def test_namespace_scopes_module():
    compiled = build_registry().compile()
    other = compiled.evaluate("http_get", {"url": "x"})
    assert other.decision is Decision.DENY
    assert other.reason.endswith("registry default")


def test_verdict_trace_is_explainable():
    compiled = build_registry().compile()
    v = compiled.evaluate("sql", {"q": "DROP TABLE x"})
    assert "org-base#org-no-drop@L100" in v.trace()


def test_registry_default_required():
    registry = PolicyRegistry(default=Decision.DENY)
    compiled = registry.compile()
    assert compiled.evaluate("anything", {}).decision is Decision.DENY


def test_clamp_never_exceeds_ceiling():
    assert clamp(Decision.ALLOW, Decision.REQUIRE_HUMAN) is Decision.REQUIRE_HUMAN
    assert clamp(Decision.DENY, Decision.REQUIRE_HUMAN) is Decision.DENY
    assert clamp(Decision.REQUIRE_HUMAN, Decision.ALLOW) is Decision.REQUIRE_HUMAN


def judge_registry() -> PolicyRegistry:
    mod = PolicyModule.from_dict(
        {
            "name": "ambiguous",
            "namespace": "*",
            "rules": [
                {
                    "id": "judge-writes",
                    "decision": "require_human",
                    "tools": ["write"],
                    "judge": True,
                    "judge_ceiling": "require_human",
                    "reason": "ambiguous write; ask the judge",
                }
            ],
        }
    )
    return PolicyRegistry(default=Decision.ALLOW).register(mod)


def test_judge_can_tighten_to_deny():
    audit = MemoryAuditSink()
    judge = CallableJudge(lambda req: (Decision.DENY, "looks destructive"))
    guard = Guard(judge_registry().compile(), audit=audit, agent_id="a", judge=judge)
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "write", {"path": "/etc/passwd"})
    assert audit.records[-1].executed is False


def test_judge_allow_is_clamped_to_ceiling():
    audit = MemoryAuditSink()
    judge = CallableJudge(lambda req: (Decision.ALLOW, "looks fine"))
    guard = Guard(
        judge_registry().compile(),
        audit=audit,
        agent_id="a",
        judge=judge,
        approver=lambda r: ApprovalGrant(r.call_id, r.call_digest),
    )
    result = guard.call(raw_dispatch, "write", {"path": "/tmp/x"})
    assert result == "ran:write"
    assert audit.records[-1].decision == "require_human"


def test_judge_missing_fails_closed_to_fallback():
    audit = MemoryAuditSink()
    guard = Guard(judge_registry().compile(), audit=audit, agent_id="a")
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "write", {"path": "/tmp/x"})
    assert "fail-closed" in audit.records[-1].reason


def test_judge_error_fails_closed():
    audit = MemoryAuditSink()

    def boom(req: JudgeRequest):
        raise RuntimeError("model timeout")

    guard = Guard(judge_registry().compile(), audit=audit, agent_id="a", judge=CallableJudge(boom))
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "write", {"path": "/tmp/x"})
    assert "judge error" in audit.records[-1].reason
