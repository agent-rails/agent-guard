from __future__ import annotations

import pytest

import identity.runtime as rt
from identity.egress import EgressPolicy
from identity.runtime import ContainerRuntime, RuntimeSpec


@pytest.fixture
def captured(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> str:
        calls.append(argv)
        return "container123" if "run" in argv else "sha256:img"

    monkeypatch.setattr(rt, "_run", fake_run)
    return calls


def test_gvisor_without_runsc_fails_loud(monkeypatch, captured):
    monkeypatch.setattr(rt, "_runsc_available", lambda: False)
    runtime = ContainerRuntime(engine="docker")
    with pytest.raises(RuntimeError, match="runsc"):
        runtime.spawn(RuntimeSpec(kind="remote.gvisor", image="busybox"))


def test_gvisor_adds_runtime_flag_and_attests_gvisor(monkeypatch, captured):
    monkeypatch.setattr(rt, "_runsc_available", lambda: True)
    runtime = ContainerRuntime(engine="docker")
    sbx = runtime.spawn(RuntimeSpec(kind="remote.gvisor", image="busybox", egress=EgressPolicy.allow_all()))
    run_argv = captured[0]
    assert "--runtime" in run_argv
    assert "runsc" in run_argv
    assert sbx.attest().runtime_kind == "remote.gvisor"


def test_deny_egress_adds_network_none(monkeypatch, captured):
    monkeypatch.setattr(rt, "_runsc_available", lambda: True)
    runtime = ContainerRuntime(engine="docker")
    runtime.spawn(RuntimeSpec(image="busybox"))
    assert "--network=none" in captured[0]


def test_non_gvisor_attests_local_container(captured):
    runtime = ContainerRuntime(engine="docker")
    sbx = runtime.spawn(RuntimeSpec(image="busybox", network=True))
    assert sbx.attest().runtime_kind == "local.container"


def test_network_bool_maps_to_egress():
    assert RuntimeSpec(network=False).resolved_egress().default == "deny"
    assert RuntimeSpec(network=True).resolved_egress().default == "allow"
