from __future__ import annotations

import base64
import json
import math
from dataclasses import replace

import pytest

from agentguard_identity import AttestationResult, Broker
from agentguard_identity.pop import PoPKeypair, PoPProof, public_key_thumbprint, verify_pop
from agentguard_identity.token import sign, verify


def test_generate_and_thumbprint_are_deterministic_for_the_same_key():
    keypair = PoPKeypair.generate()
    assert keypair.thumbprint() == keypair.thumbprint()


def test_two_keypairs_have_different_thumbprints():
    a, b = PoPKeypair.generate(), PoPKeypair.generate()
    assert a.thumbprint() != b.thumbprint()


def test_valid_proof_verifies():
    keypair = PoPKeypair.generate()
    proof = keypair.prove("some-encoded-token")
    assert verify_pop(proof, "some-encoded-token", keypair.thumbprint()) is True


def test_proof_from_wrong_keypair_fails():
    # This is the core property: a stolen bearer token is useless without the key.
    real_keypair = PoPKeypair.generate()
    attacker_keypair = PoPKeypair.generate()
    proof = attacker_keypair.prove("stolen-encoded-token")
    assert verify_pop(proof, "stolen-encoded-token", real_keypair.thumbprint()) is False


def test_proof_bound_to_a_different_token_fails():
    keypair = PoPKeypair.generate()
    proof = keypair.prove("token-a")
    assert verify_pop(proof, "token-b", keypair.thumbprint()) is False


def test_tampered_signature_fails():
    keypair = PoPKeypair.generate()
    proof = keypair.prove("some-encoded-token")
    tampered = replace(proof, signature=proof.signature[:-4] + "AAAA")
    assert verify_pop(tampered, "some-encoded-token", keypair.thumbprint()) is False


def test_tampered_public_key_fails():
    attacker_keypair = PoPKeypair.generate()
    real_keypair = PoPKeypair.generate()
    proof = real_keypair.prove("some-encoded-token")
    # Attacker swaps in their own public key but keeps the real signature — the
    # signature won't verify against a public key it wasn't produced with.
    forged = replace(proof, public_key=attacker_keypair._public_key_b64())
    assert verify_pop(forged, "some-encoded-token", real_keypair.thumbprint()) is False


def test_stale_proof_outside_freshness_window_fails():
    keypair = PoPKeypair.generate()
    proof = keypair.prove("some-encoded-token", now=1000.0)
    assert verify_pop(proof, "some-encoded-token", keypair.thumbprint(), now=1200.0, max_age_seconds=60.0) is False


def test_fresh_proof_within_window_succeeds():
    keypair = PoPKeypair.generate()
    proof = keypair.prove("some-encoded-token", now=1000.0)
    assert verify_pop(proof, "some-encoded-token", keypair.thumbprint(), now=1030.0, max_age_seconds=60.0) is True


def test_public_key_thumbprint_matches_keypair_thumbprint():
    keypair = PoPKeypair.generate()
    assert public_key_thumbprint(keypair._public_key_b64()) == keypair.thumbprint()


def test_generate_raises_clearly_without_cryptography(monkeypatch):
    import agentguard_identity.pop as pop_module

    def broken_import():
        raise ImportError("simulated: cryptography not installed")

    monkeypatch.setattr(pop_module, "_cryptography_ed25519", broken_import)
    with pytest.raises(ImportError, match="simulated"):
        PoPKeypair.generate()


# verify_pop's own contract is "never raises, always returns bool" — every field on a
# PoPProof is attacker-controlled, so malformed input must fail closed, not crash the
# caller. These reproduce inputs that previously bypassed try/except and raised instead.


def test_malformed_base64_public_key_fails_closed_not_raises():
    bad = PoPProof(public_key="A", token_binding="x", iat=1000.0, signature="y")
    assert verify_pop(bad, "some-token", "expected-thumbprint") is False


def test_non_ascii_token_binding_fails_closed_not_raises():
    thumbprint = public_key_thumbprint("AAAA")
    bad = PoPProof(public_key="AAAA", token_binding="☃notascii", iat=1000.0, signature="y")
    assert verify_pop(bad, "x", thumbprint) is False


def test_nan_iat_does_not_bypass_the_freshness_window():
    keypair = PoPKeypair.generate()
    # A NaN iat would make `abs(now - iat) > max_age` evaluate False (NaN comparisons
    # are always False), silently skipping the staleness gate if unguarded. The proof
    # must be VALIDLY SIGNED with iat=nan (not mutated after signing via replace() —
    # that breaks the signature and fails at the signature check instead, testing
    # nothing about the freshness gate specifically).
    proof = keypair.prove("some-encoded-token", now=math.nan)
    assert verify_pop(proof, "some-encoded-token", keypair.thumbprint(), now=2000.0) is False


def test_cnf_cannot_be_stripped_to_downgrade_a_holder_bound_token_to_bearer():
    # The load-bearing invariant: cnf lives inside the HMAC-signed payload, so it
    # can't be removed/altered without invalidating the signature. If a future refactor
    # ever excluded cnf from the signed body, this is the test that would catch it.
    keypair = PoPKeypair.generate()
    attestation = AttestationResult(verified=True, trust_tier="remote.microvm", sandbox_id="s1", reason="test")
    token = Broker(secret=b"k").mint(attestation, "human:x", {"a"}, {"a"}, pop_thumbprint=keypair.thumbprint())
    encoded = sign(token, b"k")

    body_b64, mac_b64 = encoded.split(".", 1)
    body = json.loads(base64.urlsafe_b64decode(body_b64))
    assert body.get("cnf") is not None, "cnf must be present in the signed payload for this test to be meaningful"
    del body["cnf"]
    stripped_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    downgraded = base64.urlsafe_b64encode(stripped_body).decode() + "." + mac_b64

    with pytest.raises(ValueError, match="signature invalid"):
        verify(downgraded, b"k")
