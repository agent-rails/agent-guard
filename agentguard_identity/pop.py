from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass, replace


def _cryptography_ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as err:
        raise ImportError(
            "proof-of-possession requires the 'cryptography' package; `pip install agentguard[pop]`"
        ) from err
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def public_key_thumbprint(public_key_b64: str) -> str:
    return _b64u(hashlib.sha256(_b64u_decode(public_key_b64)).digest())


@dataclass(frozen=True)
class PoPProof:
    """A fresh, single-token-scoped proof that the presenter holds the private key
    matching a token's `cnf` claim. `public_key` travels in the proof (not just its
    thumbprint) so a verifier that has never seen this key before can still check it —
    the verifier hashes it and compares against the token's `cnf` to confirm it's the
    same key the token was minted against, then verifies the signature against it."""

    public_key: str
    token_binding: str
    iat: float
    signature: str = ""

    def _signable_body(self) -> bytes:
        payload = {"public_key": self.public_key, "token_binding": self.token_binding, "iat": self.iat}
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class PoPKeypair:
    """A per-sandbox Ed25519 keypair. The private key never leaves whoever generates
    it — only the public key's thumbprint travels, embedded in the Token's `cnf` claim
    by the Broker. Proving possession means signing a fresh proof with the private key;
    a bearer token alone, without this key, cannot produce a valid proof."""

    def __init__(self, private_key) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> PoPKeypair:
        ed25519_private, _, _ = _cryptography_ed25519()
        return cls(ed25519_private.generate())

    def _public_key_b64(self) -> str:
        return _b64u(self._private_key.public_key().public_bytes_raw())

    def thumbprint(self) -> str:
        return public_key_thumbprint(self._public_key_b64())

    def prove(self, encoded_token: str, now: float | None = None) -> PoPProof:
        token_binding = _b64u(hashlib.sha256(encoded_token.encode("utf-8")).digest())
        unsigned = PoPProof(
            public_key=self._public_key_b64(),
            token_binding=token_binding,
            iat=now if now is not None else time.time(),
        )
        signature = _b64u(self._private_key.sign(unsigned._signable_body()))
        return replace(unsigned, signature=signature)


class PoPCapableSandbox:
    """Mixin for Sandbox implementations (agentguard_identity/runtime.py, agentguard_identity/remote.py) that
    can optionally generate a PoPKeypair at spawn time and prove possession of it later.
    A concrete sandbox calls `self._init_pop(spec.pop_enabled)` once in `__init__`, then
    gets `pop_thumbprint()`/`prove_possession()` for free. Keeps the "generate a keypair
    at spawn, thumbprint feeds Broker.mint, prove() feeds Guard.from_token" flow in one
    place instead of duplicated per sandbox backend."""

    _pop_keypair: PoPKeypair | None

    def _init_pop(self, enabled: bool) -> None:
        self._pop_keypair = PoPKeypair.generate() if enabled else None

    def pop_thumbprint(self) -> str | None:
        return self._pop_keypair.thumbprint() if self._pop_keypair is not None else None

    def prove_possession(self, encoded_token: str) -> PoPProof:
        if self._pop_keypair is None:
            raise RuntimeError("PoP not enabled for this sandbox; spawn with RuntimeSpec(pop_enabled=True)")
        return self._pop_keypair.prove(encoded_token)


def verify_pop(
    proof: PoPProof,
    encoded_token: str,
    expected_thumbprint: str,
    now: float | None = None,
    max_age_seconds: float = 60.0,
) -> bool:
    """Fail-closed: any check failing (wrong key, wrong token, stale, tampered
    signature, or a malformed/adversarial proof field) returns False — never raises,
    never partially trusts a proof. Every field here is attacker-controlled input."""
    try:
        if public_key_thumbprint(proof.public_key) != expected_thumbprint:
            return False
        expected_binding = _b64u(hashlib.sha256(encoded_token.encode("utf-8")).digest())
        if not hmac.compare_digest(proof.token_binding, expected_binding):
            return False
    except (binascii.Error, ValueError, TypeError):
        return False
    now = now if now is not None else time.time()
    if not math.isfinite(proof.iat) or abs(now - proof.iat) > max_age_seconds:
        return False
    _, ed25519_public, invalid_signature = _cryptography_ed25519()
    try:
        public_key = ed25519_public.from_public_bytes(_b64u_decode(proof.public_key))
        public_key.verify(_b64u_decode(proof.signature), proof._signable_body())
    except (invalid_signature, ValueError, TypeError, binascii.Error):
        return False
    return True
