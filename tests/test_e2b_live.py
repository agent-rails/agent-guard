from __future__ import annotations

import os

import pytest

from identity import E2BRuntime, ProviderAttestor

pytestmark = pytest.mark.skipif(
    not os.getenv("E2B_API_KEY"),
    reason="needs a live E2B account (E2B_API_KEY); runs only in the e2b CI job",
)


def test_e2b_live_spawn_exec_and_attest():
    """Live check of the E2B (Firecracker micro-VM) backend.

    Provider-asserted, so the honest attested tier is remote.gvisor, NOT
    remote.microvm — E2B is a real micro-VM but the adapter has no hardware/TEE
    quote to prove it, and claiming a tier it can't prove would be false safety.
    Whether provider assertion should grant remote.microvm is an open trust-model
    decision, deliberately left to a human.
    """
    runtime = E2BRuntime(template="base")
    sandbox = runtime.spawn()
    try:
        result = ProviderAttestor(template_allowlist={"base"}).verify(sandbox.attest())
        assert result.verified
        assert result.trust_tier == "remote.gvisor"
        out = sandbox.dispatch("shell", {"cmd": "echo hello-from-e2b"})
        assert "hello-from-e2b" in out
    finally:
        sandbox.close()
