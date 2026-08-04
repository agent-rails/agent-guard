from __future__ import annotations

import time

from .attestation import AttestationResult
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
        attestation: AttestationResult,
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
        if not attestation.verified:
            raise RefusedError(f"unverified attestation, no token minted: {attestation.reason}")
        now = now if now is not None else time.time()
        scopes = human_grant & task_scope
        return Token(
            subject=subject,
            agent_id=f"agent:{attestation.sandbox_id}",
            sandbox_id=attestation.sandbox_id,
            trust_tier=attestation.trust_tier,
            scopes=tuple(sorted(scopes)),
            exp=now + self._ttl,
            cnf=pop_thumbprint,
        )
