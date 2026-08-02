from __future__ import annotations

import pytest

from agent_guard import Guard, MemoryAuditSink, Policy
from agentguard_identity import (
    Attestation,
    Broker,
    LocalAttestor,
    LocalRuntime,
    RefusedError,
    RuntimeSpec,
    sign,
    verify,
)
from agentguard_identity.pop import verify_pop


def attestor() -> LocalAttestor:
    return LocalAttestor(allowlist={"digest-ok"})


def test_allowlisted_local_runtime_verifies():
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    result = attestor().verify(att)
    assert result.verified is True
    assert result.trust_tier == "local.container"


def test_unknown_digest_fails_closed():
    att = Attestation(runtime_kind="local.container", code_digest="rogue", sandbox_id="s1")
    assert attestor().verify(att).verified is False


def test_local_attestor_refuses_remote_claims():
    att = Attestation(runtime_kind="remote.microvm", code_digest="digest-ok", sandbox_id="s1")
    result = attestor().verify(att)
    assert result.verified is False
    assert "cannot vouch" in result.reason


def test_broker_refuses_unverified_attestation():
    att = Attestation(runtime_kind="remote.microvm", code_digest="digest-ok", sandbox_id="s1")
    result = attestor().verify(att)
    with pytest.raises(RefusedError):
        Broker(secret=b"k").mint(result, "human:x", {"a"}, {"a"})


def test_broker_requires_secret():
    with pytest.raises(ValueError):
        Broker(secret=b"")


def test_mint_intersects_scopes():
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    result = attestor().verify(att)
    token = Broker(secret=b"k").mint(result, "human:x", {"read", "write", "admin"}, {"read", "write"})
    assert set(token.scopes) == {"read", "write"}
    assert token.agent_id == "agent:s1"
    assert token.trust_tier == "local.container"


def test_token_sign_and_verify_roundtrip():
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    token = Broker(secret=b"k").mint(attestor().verify(att), "human:x", {"read"}, {"read"})
    encoded = sign(token, b"k")
    restored = verify(encoded, b"k")
    assert restored.agent_id == token.agent_id
    assert set(restored.scopes) == {"read"}


def test_sign_rejects_empty_secret():
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    token = Broker(secret=b"k").mint(attestor().verify(att), "human:x", {"read"}, {"read"})
    with pytest.raises(ValueError):
        sign(token, b"")


def test_verify_rejects_empty_secret():
    # Guards against a real bypass: sign()/verify() previously accepted b"" silently,
    # so anyone could self-sign a top-tier token with no Broker involved at all,
    # reopening the exact hand-typed-tier escalation from_token exists to close.
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    token = Broker(secret=b"k").mint(attestor().verify(att), "human:x", {"read"}, {"read"})
    encoded = sign(token, b"k")
    with pytest.raises(ValueError):
        verify(encoded, b"")


def test_tampered_token_is_rejected():
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    token = Broker(secret=b"k").mint(attestor().verify(att), "human:x", {"read"}, {"read"})
    encoded = sign(token, b"k")
    with pytest.raises(ValueError):
        verify(encoded, b"wrong-secret")


def test_expired_token_is_rejected():
    att = Attestation(runtime_kind="local.container", code_digest="digest-ok", sandbox_id="s1")
    token = Broker(secret=b"k", ttl_seconds=1).mint(attestor().verify(att), "human:x", {"read"}, {"read"}, now=1000.0)
    encoded = sign(token, b"k")
    with pytest.raises(ValueError):
        verify(encoded, b"k", now=2000.0)


def test_runtime_spawns_and_dispatches():
    runtime = LocalRuntime(tool_fn=lambda tool, args: f"ok:{tool}")
    sandbox = runtime.spawn(RuntimeSpec(code_digest="digest-ok"))
    assert sandbox.dispatch("t", {}) == "ok:t"
    sandbox.close()
    with pytest.raises(RuntimeError):
        sandbox.dispatch("t", {})


def test_sandbox_without_pop_enabled_has_no_thumbprint_and_refuses_to_prove():
    runtime = LocalRuntime(tool_fn=lambda tool, args: "ok")
    sandbox = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=False))
    assert sandbox.pop_thumbprint() is None
    with pytest.raises(RuntimeError, match="PoP not enabled"):
        sandbox.prove_possession("some-encoded-token")


def test_sandbox_with_pop_enabled_generates_a_usable_keypair():
    runtime = LocalRuntime(tool_fn=lambda tool, args: "ok")
    sandbox = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=True))
    thumbprint = sandbox.pop_thumbprint()
    assert thumbprint is not None
    proof = sandbox.prove_possession("some-encoded-token")
    assert verify_pop(proof, "some-encoded-token", thumbprint) is True


def test_two_pop_enabled_sandboxes_get_different_keypairs():
    runtime = LocalRuntime(tool_fn=lambda tool, args: "ok")
    a = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=True))
    b = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=True))
    assert a.pop_thumbprint() != b.pop_thumbprint()


def test_end_to_end_spawn_attest_mint_prove_dispatch_with_pop():
    # This is the full flow agentguard_identity/pop.py's module docstring and the design doc
    # describe: spawn -> attest -> mint (holder-bound) -> prove -> authorize -> dispatch.
    # It's the test that proves PoP is actually wired up, not just a correct primitive
    # sitting unused.
    runtime = LocalRuntime(tool_fn=lambda tool, args: f"ran:{tool}")
    sandbox = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=True))

    attestation_result = attestor().verify(sandbox.attest())
    assert attestation_result.verified is True

    token = Broker(secret=b"k").mint(
        attestation_result, "human:x", {"prod_write"}, {"prod_write"}, pop_thumbprint=sandbox.pop_thumbprint()
    )
    encoded = sign(token, b"k")
    proof = sandbox.prove_possession(encoded)

    policy = Policy.from_dict(
        {
            "default": "deny",
            "rules": [{"id": "r", "decision": "allow", "tools": ["prod_write"], "min_trust_tier": "local.container"}],
        }
    )
    guard = Guard.from_token(encoded, b"k", policy, audit=MemoryAuditSink(), pop_proof=proof)
    guarded = guard.wrap(sandbox.dispatch)
    assert guarded("prod_write", {}) == "ran:prod_write"


def test_end_to_end_a_second_sandboxs_proof_cannot_use_the_first_sandboxs_token():
    # The actual attack this whole feature is for: two sandboxes exist, an attacker
    # controls the second one and captures the first sandbox's encoded token (e.g. from
    # a shared log), but cannot produce a proof the first token's cnf will accept.
    runtime = LocalRuntime(tool_fn=lambda tool, args: "ran")
    victim_sandbox = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=True))
    attacker_sandbox = runtime.spawn(RuntimeSpec(code_digest="digest-ok", pop_enabled=True))

    attestation_result = attestor().verify(victim_sandbox.attest())
    token = Broker(secret=b"k").mint(
        attestation_result, "human:x", {"a"}, {"a"}, pop_thumbprint=victim_sandbox.pop_thumbprint()
    )
    encoded = sign(token, b"k")

    forged_proof = attacker_sandbox.prove_possession(encoded)

    policy = Policy.from_dict({"default": "allow", "rules": []})
    with pytest.raises(ValueError, match="pop_proof failed"):
        Guard.from_token(encoded, b"k", policy, audit=MemoryAuditSink(), pop_proof=forged_proof)
