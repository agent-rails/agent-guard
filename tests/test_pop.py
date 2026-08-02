from __future__ import annotations

from dataclasses import replace

import pytest

from identity.pop import PoPKeypair, public_key_thumbprint, verify_pop


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
    import identity.pop as pop_module

    def broken_import():
        raise ImportError("simulated: cryptography not installed")

    monkeypatch.setattr(pop_module, "_cryptography_ed25519", broken_import)
    with pytest.raises(ImportError, match="simulated"):
        PoPKeypair.generate()
