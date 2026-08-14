from __future__ import annotations

import shutil
import subprocess

import pytest

from agentguard_identity import Broker, ContainerRuntime, LocalAttestor, RuntimeSpec

IMAGE = "alpine:latest"


def _docker_up() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _docker_up(), reason="docker daemon not available")


def test_container_spawn_attest_dispatch():
    sandbox = ContainerRuntime().spawn(RuntimeSpec(kind="local.container", image=IMAGE))
    try:
        attestation = sandbox.attest()
        assert attestation.runtime_kind == "local.container"
        assert attestation.code_digest
        assert sandbox.dispatch("shell", {"cmd": "echo hi"}).strip() == "hi"
    finally:
        sandbox.close()


def test_container_network_none_blocks_egress():
    sandbox = ContainerRuntime().spawn(RuntimeSpec(kind="local.container", image=IMAGE, network=False))
    try:
        out = sandbox.dispatch("shell", {"cmd": "wget -T2 -q -O- http://example.com 2>/dev/null || echo BLOCKED"})
        assert "BLOCKED" in out
    finally:
        sandbox.close()


def test_container_identity_mints_local_container_tier():
    sandbox = ContainerRuntime().spawn(RuntimeSpec(kind="local.container", image=IMAGE))
    try:
        attestation = sandbox.attest()
        attestor = LocalAttestor(allowlist={attestation.code_digest})
        token = Broker(secret=b"k").mint(attestor, attestation, "human:x", {"exec"}, {"exec"})
        assert token.trust_tier == "local.container"
        assert token.sandbox_id == attestation.sandbox_id
    finally:
        sandbox.close()
