from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

LOCAL_KINDS = {"local.process", "local.container"}
REMOTE_KINDS = {"remote.gvisor", "remote.microvm"}


@dataclass(frozen=True)
class Attestation:
    runtime_kind: str
    code_digest: str
    sandbox_id: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttestationResult:
    verified: bool
    trust_tier: str
    sandbox_id: str
    reason: str


class Attestor(Protocol):
    def verify(self, attestation: Attestation) -> AttestationResult: ...


class LocalAttestor:
    def __init__(self, allowlist: set[str]) -> None:
        self._allowlist = allowlist

    def verify(self, attestation: Attestation) -> AttestationResult:
        if attestation.runtime_kind not in LOCAL_KINDS:
            return AttestationResult(
                verified=False,
                trust_tier="local.process",
                sandbox_id=attestation.sandbox_id,
                reason=f"local attestor cannot vouch for '{attestation.runtime_kind}'; needs a remote/TEE attestor",
            )
        if attestation.code_digest not in self._allowlist:
            return AttestationResult(
                verified=False,
                trust_tier="local.process",
                sandbox_id=attestation.sandbox_id,
                reason=f"code digest '{attestation.code_digest}' not in allowlist",
            )
        return AttestationResult(
            verified=True,
            trust_tier=attestation.runtime_kind,
            sandbox_id=attestation.sandbox_id,
            reason="digest allowlisted; local runtime",
        )
