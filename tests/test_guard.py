from __future__ import annotations

import pytest

from agent_guard import BlockedError, Decision, Guard, MemoryAuditSink, Policy
from agentguard_identity import Attestation, AttestationResult, Broker
from agentguard_identity.pop import PoPKeypair
from agentguard_identity.token import Token, sign


def raw_dispatch(tool: str, args: dict) -> str:
    return f"ran:{tool}"


class StubAttestor:
    def __init__(self, result: AttestationResult) -> None:
        self._result = result

    def verify(self, attestation: Attestation) -> AttestationResult:
        return self._result


def make_policy(default: str = "allow") -> Policy:
    return Policy.from_dict(
        {
            "default": default,
            "rules": [
                {
                    "id": "block-drop",
                    "decision": "deny",
                    "tools": ["sql"],
                    "arg_patterns": [r"(?i)\bdrop\s+table\b"],
                    "reason": "no destructive sql",
                },
                {
                    "id": "gate-push",
                    "decision": "require_human",
                    "tools": ["git", "shell"],
                    "arg_patterns": [r"git\s+push\b.*--force"],
                    "reason": "force push needs a human",
                },
            ],
        }
    )


def make_guard(default: str = "allow", approver=None) -> tuple[Guard, MemoryAuditSink]:
    audit = MemoryAuditSink()
    kwargs = {"approver": approver} if approver else {}
    guard = Guard(make_policy(default), audit=audit, agent_id="agent-test", **kwargs)
    return guard, audit


def test_missing_default_is_rejected():
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": []})


def test_allow_passes_through_and_audits():
    guard, audit = make_guard()
    result = guard.call(raw_dispatch, "sql", {"query": "SELECT 1"})
    assert result == "ran:sql"
    assert audit.records[-1].executed is True
    assert audit.records[-1].decision == "allow"


def test_allowed_dispatch_failure_is_audited():
    guard, audit = make_guard()

    def failing_dispatch(tool: str, args: dict) -> str:
        raise RuntimeError("dispatch failed")

    with pytest.raises(RuntimeError, match="dispatch failed"):
        guard.call(failing_dispatch, "sql", {"query": "SELECT 1"})
    assert audit.records[-1].executed is True
    assert audit.records[-1].decision == "allow"
    assert audit.records[-1].error == "dispatch failed"


def test_deny_blocks_and_does_not_execute():
    guard, audit = make_guard()
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "sql", {"query": "DROP TABLE users"})
    assert audit.records[-1].executed is False
    assert audit.records[-1].rule_id == "block-drop"


def test_require_human_blocks_when_denied():
    guard, audit = make_guard(approver=lambda req: False)
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "git", {"cmd": "git push --force origin main"})
    assert audit.records[-1].executed is False


def test_require_human_runs_when_approved():
    guard, audit = make_guard(approver=lambda req: True)
    result = guard.call(raw_dispatch, "git", {"cmd": "git push --force origin main"})
    assert result == "ran:git"
    assert audit.records[-1].executed is True
    assert audit.records[-1].decision == "require_human"


def test_require_human_defaults_to_deny():
    guard, audit = make_guard()
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "shell", {"cmd": "git push --force"})
    assert audit.records[-1].executed is False


def test_default_deny_blocks_unmatched():
    guard, _ = make_guard(default="deny")
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "unknown_tool", {})


def test_arg_pattern_scopes_the_match():
    policy = make_policy()
    assert policy.evaluate("sql", {"q": "SELECT 1"}).decision is Decision.ALLOW
    assert policy.evaluate("sql", {"q": "drop table x"}).decision is Decision.DENY


def test_tool_glob_matches():
    policy = Policy.from_dict({"default": "allow", "rules": [{"id": "r", "decision": "deny", "tools": ["db_*"]}]})
    assert policy.evaluate("db_write", {}).decision is Decision.DENY
    assert policy.evaluate("cache_write", {}).decision is Decision.ALLOW


def tier_policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "deny",
            "rules": [
                {
                    "id": "prod-write-needs-microvm",
                    "decision": "allow",
                    "tools": ["prod_write"],
                    "min_trust_tier": "remote.microvm",
                    "reason": "prod writes only from a hardware-attested runtime",
                }
            ],
        }
    )


def test_tier_sufficient_allows():
    verdict = tier_policy().evaluate("prod_write", {}, trust_tier="remote.microvm")
    assert verdict.decision is Decision.ALLOW


def test_tier_insufficient_denies():
    verdict = tier_policy().evaluate("prod_write", {}, trust_tier="local.container")
    assert verdict.decision is Decision.DENY
    assert "requires trust tier" in verdict.reason


def test_guard_carries_trust_tier():
    audit = MemoryAuditSink()
    guard = Guard(tier_policy(), audit=audit, agent_id="a", trust_tier="local.process")
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "prod_write", {})
    assert audit.records[-1].executed is False


def test_unknown_tier_is_rejected():
    with pytest.raises(ValueError):
        tier_policy().evaluate("prod_write", {}, trust_tier="not-a-tier")


SECRET = b"k"


def mint_encoded(trust_tier: str, secret: bytes = SECRET, ttl_seconds: int = 300, now: float | None = None) -> str:
    result = AttestationResult(verified=True, trust_tier=trust_tier, sandbox_id="s1", reason="test-stub")
    attestation = Attestation(runtime_kind=trust_tier, code_digest="test", sandbox_id="s1")
    token = Broker(secret=secret, ttl_seconds=ttl_seconds).mint(
        StubAttestor(result), attestation, "human:x", {"*"}, {"*"}, now=now
    )
    return sign(token, secret)


def mint_scoped_encoded(scopes: set[str]) -> str:
    result = AttestationResult(verified=True, trust_tier="local.process", sandbox_id="s1", reason="test-stub")
    attestation = Attestation(runtime_kind="local.process", code_digest="test", sandbox_id="s1")
    token = Broker(secret=SECRET).mint(StubAttestor(result), attestation, "human:x", scopes, scopes)
    return sign(token, SECRET)


def test_from_token_enforces_scopes_before_allow_policy():
    encoded = mint_scoped_encoded({"read"})
    audit = MemoryAuditSink()
    policy = Policy.from_dict({"default": "allow", "rules": []})
    guard = Guard.from_token(encoded, SECRET, policy, audit=audit)

    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "write", {})

    assert audit.records[-1].decision == "deny"
    assert audit.records[-1].rule_id == "token-scope"
    assert audit.records[-1].executed is False
    assert guard.call(raw_dispatch, "read", {}) == "ran:read"
    assert audit.records[-1].executed is True


def test_from_token_binds_trust_tier_not_a_typed_string():
    encoded = mint_encoded("remote.microvm")
    audit = MemoryAuditSink()
    guard = Guard.from_token(encoded, SECRET, tier_policy(), audit=audit)
    result = guard.call(raw_dispatch, "prod_write", {})
    assert result == "ran:prod_write"
    assert audit.records[-1].decision == "allow"


def test_from_token_denies_when_tokens_tier_insufficient():
    encoded = mint_encoded("local.process")
    audit = MemoryAuditSink()
    guard = Guard.from_token(encoded, SECRET, tier_policy(), audit=audit)
    with pytest.raises(BlockedError):
        guard.call(raw_dispatch, "prod_write", {})
    assert audit.records[-1].executed is False


def test_from_token_binds_agent_id_from_the_token():
    encoded = mint_encoded("remote.microvm")
    audit = MemoryAuditSink()
    guard = Guard.from_token(encoded, SECRET, tier_policy(), audit=audit)
    guard.call(raw_dispatch, "prod_write", {})
    assert audit.records[-1].agent_id == "agent:s1"


def test_from_token_rejects_expired_token():
    encoded = mint_encoded("remote.microvm", ttl_seconds=1, now=1000.0)
    with pytest.raises(ValueError):
        Guard.from_token(encoded, SECRET, tier_policy(), audit=MemoryAuditSink(), now=2000.0)


# Adversarial: these reproduce the exact bypasses a prior version of from_token allowed,
# and assert they're now rejected. Passing tests here is what "verified" means, not
# assuming the fix works because the happy-path tests above pass.


def test_from_token_rejects_a_hand_constructed_token_object():
    forged = Token(
        subject="human:x",
        agent_id="agent:forged",
        sandbox_id="s1",
        trust_tier="remote.microvm",
        scopes=(),
        exp=10**12,
    )
    with pytest.raises(TypeError):
        Guard.from_token(forged, SECRET, tier_policy(), audit=MemoryAuditSink())


def test_from_token_rejects_a_tampered_signature():
    encoded = mint_encoded("local.process")
    body, _, sig = encoded.rpartition(".")
    tampered = f"{body}.{sig[:-4]}AAAA"
    with pytest.raises(ValueError):
        Guard.from_token(tampered, SECRET, tier_policy(), audit=MemoryAuditSink())


def test_from_token_rejects_a_token_signed_with_a_different_secret():
    encoded = mint_encoded("remote.microvm", secret=b"attacker-controlled-secret")
    with pytest.raises(ValueError):
        Guard.from_token(encoded, SECRET, tier_policy(), audit=MemoryAuditSink())


# Proof-of-possession (holder-bound tokens, agentguard_identity/pop.py). These tests exist
# specifically to demonstrate the property PoP adds beyond what from_token already
# checked above: a leaked/stolen ENCODED TOKEN STRING alone, with no other change,
# must not be enough to use a holder-bound token.


def mint_pop_bound(trust_tier: str = "remote.microvm") -> tuple[str, PoPKeypair]:
    keypair = PoPKeypair.generate()
    result = AttestationResult(verified=True, trust_tier=trust_tier, sandbox_id="s1", reason="test-stub")
    attestation = Attestation(runtime_kind=trust_tier, code_digest="test", sandbox_id="s1")
    token = Broker(secret=SECRET).mint(
        StubAttestor(result), attestation, "human:x", {"*"}, {"*"}, pop_thumbprint=keypair.thumbprint()
    )
    return sign(token, SECRET), keypair


def test_from_token_succeeds_with_a_valid_matching_proof():
    encoded, keypair = mint_pop_bound()
    proof = keypair.prove(encoded)
    audit = MemoryAuditSink()
    guard = Guard.from_token(encoded, SECRET, tier_policy(), audit=audit, pop_proof=proof)
    result = guard.call(raw_dispatch, "prod_write", {})
    assert result == "ran:prod_write"


def test_from_token_rejects_holder_bound_token_with_no_proof_at_all():
    # The exact scenario PoP exists for: someone has the encoded bearer string (e.g.
    # captured from a log or a network hop) but not the private key.
    encoded, _keypair = mint_pop_bound()
    with pytest.raises(ValueError, match="no pop_proof"):
        Guard.from_token(encoded, SECRET, tier_policy(), audit=MemoryAuditSink())


def test_from_token_rejects_proof_from_the_wrong_keypair():
    encoded, _real_keypair = mint_pop_bound()
    attacker_keypair = PoPKeypair.generate()
    forged_proof = attacker_keypair.prove(encoded)
    with pytest.raises(ValueError, match="pop_proof failed"):
        Guard.from_token(encoded, SECRET, tier_policy(), audit=MemoryAuditSink(), pop_proof=forged_proof)


def test_from_token_rejects_a_stale_proof():
    encoded, keypair = mint_pop_bound()
    stale_proof = keypair.prove(encoded, now=1000.0)
    with pytest.raises(ValueError, match="pop_proof failed"):
        Guard.from_token(encoded, SECRET, tier_policy(), audit=MemoryAuditSink(), pop_proof=stale_proof, now=2000.0)


def test_plain_bearer_token_without_cnf_still_works_with_no_proof():
    # Backward compatibility: PoP is opt-in per token via Broker's pop_thumbprint param.
    # A token minted without it behaves exactly as before PoP existed.
    encoded = mint_encoded("remote.microvm")
    audit = MemoryAuditSink()
    guard = Guard.from_token(encoded, SECRET, tier_policy(), audit=audit)
    result = guard.call(raw_dispatch, "prod_write", {})
    assert result == "ran:prod_write"
