from __future__ import annotations

import pytest

from agent_guard import (
    BlockedError,
    Guard,
    InMemoryVelocityLimiter,
    MemoryAuditSink,
    Policy,
    VelocityRule,
)


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def raw_dispatch(tool: str, args: dict) -> str:
    return f"ran:{tool}"


def allow_all_policy() -> Policy:
    return Policy.from_dict({"default": "allow", "rules": []})


def limiter(*rules: VelocityRule, clock: FakeClock | None = None) -> InMemoryVelocityLimiter:
    return InMemoryVelocityLimiter(rules=rules, clock=clock or FakeClock())


def test_rule_rejects_nonpositive_window():
    with pytest.raises(ValueError, match="window_seconds"):
        VelocityRule(tools=("*",), max_calls=1, window_seconds=0)


def test_rule_rejects_zero_max_calls():
    with pytest.raises(ValueError, match="max_calls"):
        VelocityRule(tools=("*",), max_calls=0, window_seconds=10)


def test_rule_rejects_empty_tools():
    with pytest.raises(ValueError, match="at least one tool pattern"):
        VelocityRule(tools=(), max_calls=1, window_seconds=10)


def test_calls_under_limit_are_allowed():
    lim = limiter(VelocityRule(tools=("*",), max_calls=3, window_seconds=10))
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None


def test_call_exactly_at_limit_is_the_last_allowed():
    lim = limiter(VelocityRule(tools=("*",), max_calls=3, window_seconds=10))
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None
    breach = lim.check("a", "sql")
    assert breach is not None
    assert "velocity limit exceeded" in breach


def test_window_expiry_resets_the_counter():
    clock = FakeClock()
    lim = limiter(VelocityRule(tools=("*",), max_calls=2, window_seconds=10), clock=clock)
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is not None
    clock.advance(11)
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None


def test_partial_window_slide_frees_one_slot_at_a_time():
    clock = FakeClock()
    lim = limiter(VelocityRule(tools=("*",), max_calls=2, window_seconds=10), clock=clock)
    assert lim.check("a", "sql") is None
    clock.advance(6)
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is not None
    clock.advance(5)
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is not None


def test_per_agent_isolation():
    lim = limiter(VelocityRule(tools=("*",), max_calls=2, window_seconds=10))
    assert lim.check("agent-a", "sql") is None
    assert lim.check("agent-a", "sql") is None
    assert lim.check("agent-a", "sql") is not None
    assert lim.check("agent-b", "sql") is None
    assert lim.check("agent-b", "sql") is None


def test_tool_pattern_scopes_the_limit():
    lim = limiter(VelocityRule(tools=("sql",), max_calls=1, window_seconds=10))
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is not None
    assert lim.check("a", "http_get") is None
    assert lim.check("a", "http_get") is None


def test_glob_tool_pattern_matches_family():
    lim = limiter(VelocityRule(tools=("db_*",), max_calls=1, window_seconds=10))
    assert lim.check("a", "db_write") is None
    assert lim.check("a", "db_write") is not None
    assert lim.check("a", "db_read") is not None
    assert lim.check("a", "cache_read") is None


def test_multiple_rules_all_enforced():
    lim = limiter(
        VelocityRule(tools=("*",), max_calls=5, window_seconds=10, id="global"),
        VelocityRule(tools=("sql",), max_calls=2, window_seconds=10, id="sql-specific"),
    )
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is None
    breach = lim.check("a", "sql")
    assert breach is not None
    assert "sql-specific" in breach


def test_denied_call_consumes_no_budget_on_any_matching_rule():
    lim = limiter(
        VelocityRule(tools=("*",), max_calls=10, window_seconds=10, id="global"),
        VelocityRule(tools=("sql",), max_calls=1, window_seconds=10, id="sql-specific"),
    )
    assert lim.check("a", "sql") is None
    assert lim.check("a", "sql") is not None
    assert lim.check("a", "sql") is not None
    assert lim.check("a", "http_get") is None
    assert lim.check("a", "http_get") is None


def test_empty_window_is_evicted_not_retained():
    clock = FakeClock()
    lim = limiter(VelocityRule(tools=("sql",), max_calls=1, window_seconds=10), clock=clock)
    assert lim.check("a", "sql") is None
    clock.advance(11)
    assert lim.check("a", "sql") is None
    assert len(lim._windows) == 1


def test_guard_without_limiter_is_unchanged():
    audit = MemoryAuditSink()
    guard = Guard(allow_all_policy(), audit=audit, agent_id="a")
    for _ in range(100):
        assert guard.call(raw_dispatch, "sql", {"q": "SELECT 1"}) == "ran:sql"


def test_guard_denies_once_velocity_exceeded_and_audits_as_deny():
    audit = MemoryAuditSink()
    guard = Guard(
        allow_all_policy(),
        audit=audit,
        agent_id="a",
        velocity=limiter(VelocityRule(tools=("*",), max_calls=2, window_seconds=10)),
    )
    assert guard.call(raw_dispatch, "sql", {"q": "SELECT 1"}) == "ran:sql"
    assert guard.call(raw_dispatch, "sql", {"q": "SELECT 1"}) == "ran:sql"
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "sql", {"q": "SELECT 1"})
    denied = audit.records[-1]
    assert denied.decision == "deny"
    assert denied.rule_id == "velocity-limit"
    assert denied.executed is False


class BoomLimiter:
    def check(self, agent_id: str, tool: str) -> str | None:
        raise RuntimeError("limiter backend unreachable")


def test_limiter_exception_fails_closed_to_deny():
    audit = MemoryAuditSink()
    guard = Guard(allow_all_policy(), audit=audit, agent_id="a", velocity=BoomLimiter())
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "sql", {"q": "SELECT 1"})
    denied = audit.records[-1]
    assert denied.decision == "deny"
    assert denied.rule_id == "velocity-limit"
    assert "fail-closed" in denied.reason
    assert denied.executed is False


def test_rejected_human_gate_does_not_consume_velocity_budget():
    audit = MemoryAuditSink()
    policy = Policy.from_dict(
        {
            "default": "allow",
            "rules": [{"id": "gate", "decision": "require_human", "tools": ["deploy"], "reason": "needs human"}],
        }
    )
    lim = limiter(VelocityRule(tools=("deploy",), max_calls=1, window_seconds=10))
    guard = Guard(policy, audit=audit, agent_id="a", approver=lambda req: False, velocity=lim)
    for _ in range(5):
        with pytest.raises(BlockedError):
            guard.call(raw_dispatch, "deploy", {})
    assert lim.check("a", "deploy") is None


def test_approved_human_gate_consumes_velocity_budget():
    audit = MemoryAuditSink()
    policy = Policy.from_dict(
        {
            "default": "allow",
            "rules": [{"id": "gate", "decision": "require_human", "tools": ["deploy"], "reason": "needs human"}],
        }
    )
    lim = limiter(VelocityRule(tools=("deploy",), max_calls=2, window_seconds=10))
    guard = Guard(policy, audit=audit, agent_id="a", approver=lambda req: True, velocity=lim)
    assert guard.call(raw_dispatch, "deploy", {}) == "ran:deploy"
    assert guard.call(raw_dispatch, "deploy", {}) == "ran:deploy"
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "deploy", {})


def test_huggingface_shape_individually_in_policy_calls_denied_on_accumulation():
    """The HF-intrusion shape (17,600 individually-mundane actions): every call passes
    static policy, yet the run is stopped once it accumulates past the velocity budget.
    This is the exact gap this feature exists to close — no single call is exotic."""
    audit = MemoryAuditSink()
    budget = 100
    guard = Guard(
        allow_all_policy(),
        audit=audit,
        agent_id="intruder",
        velocity=limiter(VelocityRule(tools=("*",), max_calls=budget, window_seconds=60)),
    )

    allowed = 0
    blocked = 0
    for index in range(17_600):
        try:
            guard.call(raw_dispatch, "list_repo", {"page": index})
            allowed += 1
        except BlockedError:
            blocked += 1

    assert allowed == budget
    assert blocked == 17_600 - budget
    assert audit.records[-1].rule_id == "velocity-limit"
