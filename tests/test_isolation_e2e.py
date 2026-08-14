from __future__ import annotations

import pytest

from agent_guard import (
    BlockedError,
    Decision,
    Guard,
    MemoryAuditSink,
    PolicyModule,
    PolicyRegistry,
)
from agentguard_identity import Broker, E2BRuntime, ProviderAttestor


class _FakeClient:
    """Offline stand-in for a hosted micro-sandbox client (E2B-shaped)."""

    def __init__(self, template: str) -> None:
        self._template = template
        self.ran: list[str] = []

    def run(self, cmd: str) -> str:
        self.ran.append(cmd)
        return f"ran:{cmd}"

    def kill(self) -> None:
        pass

    @property
    def id(self) -> str:
        return "sbx-fake"

    @property
    def template(self) -> str:
        return self._template


def _policy():
    module = PolicyModule.from_dict(
        {
            "name": "tiers",
            "namespace": "*",
            "layer": 0,
            "rules": [
                {
                    "id": "shell-ok-from-gvisor",
                    "decision": "allow",
                    "tools": ["shell"],
                    "min_trust_tier": "remote.gvisor",
                    "reason": "shell allowed from gvisor tier and above",
                },
                {
                    "id": "exec-needs-microvm",
                    "decision": "allow",
                    "tools": ["exec"],
                    "min_trust_tier": "remote.microvm",
                    "reason": "exec requires a hardware-attested microVM",
                },
            ],
        }
    )
    return PolicyRegistry(default=Decision.DENY).register(module).compile()


def test_isolation_e2e_gvisor_tier_gates_authorization():
    # WHERE: spawn a remote sandbox through an injected offline client
    runtime = E2BRuntime(template="base-gvisor", client_factory=lambda t: _FakeClient(t))
    sandbox = runtime.spawn()

    # WHO: attest the runtime, mint a scoped identity at the attested tier
    attestor = ProviderAttestor(template_allowlist={"base-gvisor"})
    attestation = sandbox.attest()
    result = attestor.verify(attestation)
    assert result.verified
    assert result.trust_tier == "remote.gvisor"

    token = Broker(secret=b"test-secret", ttl_seconds=300).mint(
        attestor,
        attestation,
        subject="human:test",
        human_grant={"shell", "exec"},
        task_scope={"shell", "exec"},
    )
    assert token.trust_tier == "remote.gvisor"

    # WHAT + DID: guard authorizes on the minted tier and audits every call
    audit = MemoryAuditSink()
    guard = Guard(_policy(), audit=audit, agent_id=token.agent_id, trust_tier=token.trust_tier)
    guarded = guard.wrap(sandbox.dispatch)

    # allowed: shell needs remote.gvisor; the identity meets it -> dispatched for real
    assert "ran:" in guarded("shell", {"cmd": "echo hi"})

    # denied: exec needs remote.microvm; gvisor < microvm -> blocked, no self-elevation
    with pytest.raises(BlockedError):
        guarded("exec", {"cmd": "echo nope"})

    sandbox.close()

    executed = [r for r in audit.records if r.executed]
    blocked = [r for r in audit.records if not r.executed]
    assert len(executed) == 1
    assert len(blocked) == 1
