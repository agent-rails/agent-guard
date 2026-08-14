from __future__ import annotations

import time

from .attestation import Attestation, AttestationResult, Attestor
from .token import Token


class RefusedError(Exception):
    pass


class Broker:
    def __init__(self, secret: bytes, ttl_seconds: int = 300) -> None:
        if not secret:
            raise ValueError("broker requires a non-empty signing secret")
        self._secret = secret
        self._ttl = ttl_seconds

    def mint(
        self,
        attestor: Attestor,
        attestation: Attestation,
        subject: str,
        human_grant: set[str],
        task_scope: set[str],
        now: float | None = None,
        pop_thumbprint: str | None = None,
    ) -> Token:
        """`pop_thumbprint` (optional): a PoPKeypair.thumbprint() (agentguard_identity/pop.py) the
        caller holds the private key for. When given, the minted Token is holder-bound
        via its `cnf` claim — presenting the encoded token alone won't be enough to use
        it, a fresh PoPProof signed by that key is also required. Omit for a plain
        bearer token, unchanged from before PoP existed."""
        if isinstance(attestor, AttestationResult):
            raise TypeError("mint expects an Attestor and raw Attestation, not an AttestationResult")
        result = attestor.verify(attestation)
        if not result.verified:
            raise RefusedError(f"unverified attestation, no token minted: {result.reason}")
        now = now if now is not None else time.time()
        scopes = human_grant & task_scope
        return Token(
            subject=subject,
            agent_id=f"agent:{result.sandbox_id}",
            sandbox_id=result.sandbox_id,
            trust_tier=result.trust_tier,
            scopes=tuple(sorted(scopes)),
            exp=now + self._ttl,
            cnf=pop_thumbprint,
        )
