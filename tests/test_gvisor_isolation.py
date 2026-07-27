from __future__ import annotations

import shutil

import pytest

from identity.runtime import ContainerRuntime, RuntimeSpec

pytestmark = pytest.mark.skipif(
    shutil.which("runsc") is None or shutil.which("docker") is None,
    reason="requires docker + gVisor (runsc); runs in the CI gvisor job",
)


def test_gvisor_spawns_and_denies_egress():
    """Wiring check for the remote.gvisor tier.

    Asserts what agent-guard controls: the sandbox actually runs under runsc
    (honest attestation) and egress is denied deterministically by the network
    boundary. Kernel-escape resistance itself is gVisor's guarantee (user-space
    kernel, see gvisor.dev/security) — not something we re-test by exploit here.
    """
    runtime = ContainerRuntime()
    spec = RuntimeSpec(kind="remote.gvisor", runtime="runsc", image="busybox", network=False)
    sbx = runtime.spawn(spec)
    try:
        assert sbx.attest().runtime_kind == "remote.gvisor"
        out = sbx.dispatch(
            "shell", {"cmd": "wget -T3 -q -O- http://example.com 2>&1 || echo BLOCKED"}
        )
        assert "BLOCKED" in out
        assert sbx.dispatch("shell", {"cmd": "echo alive"}).strip() == "alive"
    finally:
        sbx.close()
