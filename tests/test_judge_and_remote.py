from __future__ import annotations

import pytest

from agent_guard import (
    BlockedError,
    Decision,
    Guard,
    JudgeRequest,
    LLMJudge,
    MemoryAuditSink,
    Policy,
    PolicyModule,
    PolicyRegistry,
    ReferenceJudge,
    parse_verdict,
)
from agent_guard.judge import build_prompt
from agentguard_identity import Broker, ProviderAttestor, RemoteSandbox
from agentguard_identity.pop import verify_pop
from agentguard_identity.token import sign


def raw_dispatch(tool: str, args: dict) -> str:
    return f"ran:{tool}"


def judge_policy():
    mod = PolicyModule.from_dict(
        {
            "name": "band",
            "rules": [
                {
                    "id": "judge-writes",
                    "decision": "require_human",
                    "tools": ["write"],
                    "judge": True,
                    "judge_ceiling": "require_human",
                    "reason": "ambiguous",
                }
            ],
        }
    )
    return PolicyRegistry(default=Decision.ALLOW).register(mod).compile()


def test_parse_verdict_reads_all_three():
    assert parse_verdict("VERDICT: DENY — bad")[0] is Decision.DENY
    assert parse_verdict("VERDICT: ALLOW — fine")[0] is Decision.ALLOW
    assert parse_verdict("VERDICT: REQUIRE_HUMAN — check")[0] is Decision.REQUIRE_HUMAN


def test_parse_verdict_fails_closed_on_garbage():
    assert parse_verdict("the model rambled with no verdict")[0] is Decision.DENY


def test_build_prompt_includes_ceiling_and_tool():
    req = JudgeRequest("a", "write", {"path": "/etc"}, "ambiguous", Decision.REQUIRE_HUMAN)
    prompt = build_prompt(req)
    assert "write" in prompt and "require_human" in prompt


def test_llm_judge_denies_on_model_deny():
    judge = LLMJudge(complete=lambda p: "VERDICT: DENY — destructive")
    audit = MemoryAuditSink()
    guard = Guard(judge_policy(), audit=audit, agent_id="a", judge=judge)
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "write", {"path": "/etc/passwd"})


def test_llm_judge_allow_is_clamped_to_ceiling():
    judge = LLMJudge(complete=lambda p: "VERDICT: ALLOW — fine")
    audit = MemoryAuditSink()
    guard = Guard(judge_policy(), audit=audit, agent_id="a", judge=judge, approver=lambda r: True)
    assert guard.call(raw_dispatch, "write", {"path": "/tmp/x"}) == "ran:write"
    assert audit.records[-1].decision == "require_human"


def test_llm_judge_fails_closed_on_exception():
    def boom(_):
        raise RuntimeError("model down")

    audit = MemoryAuditSink()
    guard = Guard(judge_policy(), audit=audit, agent_id="a", judge=LLMJudge(complete=boom))
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "write", {"path": "/tmp/x"})


def test_reference_judge_denies_destructive():
    decision, _ = ReferenceJudge().evaluate(JudgeRequest("a", "write", {"cmd": "DROP TABLE t"}, "x", Decision.ALLOW))
    assert decision is Decision.DENY


def test_reference_judge_defers_otherwise():
    decision, _ = ReferenceJudge().evaluate(JudgeRequest("a", "write", {"cmd": "echo hi"}, "x", Decision.ALLOW))
    assert decision is Decision.REQUIRE_HUMAN


class FakeRemoteClient:
    id = "sbx-remote-1"
    template = "trusted-template"

    def run(self, cmd: str) -> str:
        return f"remote-ran:{cmd}"

    def kill(self) -> None:
        pass


def test_remote_sandbox_attests_as_gvisor_not_microvm():
    sandbox = RemoteSandbox(FakeRemoteClient())
    att = sandbox.attest()
    assert att.runtime_kind == "remote.gvisor"


def test_provider_attestor_gates_on_template():
    att = RemoteSandbox(FakeRemoteClient()).attest()
    ok = ProviderAttestor({"trusted-template"}).verify(att)
    assert ok.verified is True and ok.trust_tier == "remote.gvisor"
    bad = ProviderAttestor({"other"}).verify(att)
    assert bad.verified is False


def test_judge_cannot_escalate_past_rule_decision():
    """A rule authored decision=deny + judge_ceiling=allow must never let a judge
    escalate the final decision past DENY -- the rule's own decision is the hard
    boundary static policy set; judge_ceiling can only narrow it further."""
    from agent_guard.policy import Policy, Rule

    rule = Rule(id="r", decision=Decision.DENY, tools=["*"], judge=True, judge_ceiling=Decision.ALLOW)
    policy = Policy(default=Decision.DENY, rules=[rule])
    always_allow = LLMJudge(complete=lambda p: "VERDICT: ALLOW — fine")
    guard = Guard(policy, audit=MemoryAuditSink(), agent_id="a", judge=always_allow)
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "anything", {})


def test_rule_from_dict_rejects_ceiling_above_decision():
    with pytest.raises(ValueError, match="more permissive"):
        PolicyModule.from_dict(
            {
                "name": "bad",
                "rules": [{"id": "r", "decision": "deny", "tools": ["*"], "judge": True, "judge_ceiling": "allow"}],
            }
        )


def test_remote_end_to_end_with_broker():
    sandbox = RemoteSandbox(FakeRemoteClient())
    result = ProviderAttestor({"trusted-template"}).verify(sandbox.attest())
    token = Broker(secret=b"k").mint(result, "human:x", {"exec"}, {"exec"})
    assert token.trust_tier == "remote.gvisor"
    assert sandbox.dispatch("shell", {"cmd": "ls"}) == "remote-ran:ls"


def test_remote_sandbox_pop_disabled_by_default():
    sandbox = RemoteSandbox(FakeRemoteClient())
    assert sandbox.pop_thumbprint() is None
    with pytest.raises(RuntimeError, match="PoP not enabled"):
        sandbox.prove_possession("some-encoded-token")


def test_remote_sandbox_pop_enabled_generates_a_usable_keypair():
    sandbox = RemoteSandbox(FakeRemoteClient(), pop_enabled=True)
    thumbprint = sandbox.pop_thumbprint()
    assert thumbprint is not None
    proof = sandbox.prove_possession("some-encoded-token")
    assert verify_pop(proof, "some-encoded-token", thumbprint) is True


def test_remote_end_to_end_with_pop():
    sandbox = RemoteSandbox(FakeRemoteClient(), pop_enabled=True)
    result = ProviderAttestor({"trusted-template"}).verify(sandbox.attest())
    token = Broker(secret=b"k").mint(result, "human:x", {"exec"}, {"exec"}, pop_thumbprint=sandbox.pop_thumbprint())
    encoded = sign(token, b"k")
    proof = sandbox.prove_possession(encoded)
    policy = Policy.from_dict({"default": "allow", "rules": []})
    guard = Guard.from_token(encoded, b"k", policy, audit=MemoryAuditSink(), pop_proof=proof)
    guarded = guard.wrap(sandbox.dispatch)
    assert guarded("shell", {"cmd": "ls"}) == "remote-ran:ls"
