from __future__ import annotations

import pytest

from identity import (
    Attestation,
    Broker,
    LocalAttestor,
    LocalRuntime,
    RefusedError,
    RuntimeSpec,
    sign,
    verify,
)


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
