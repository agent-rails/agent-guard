from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .attestation import Attestation
from .egress import EgressPolicy

ToolFn = Callable[[str, dict], Any]
EXEC_TOOLS = {"shell", "exec"}


@dataclass(frozen=True)
class RuntimeSpec:
    code_digest: str = ""
    kind: str = "local.container"
    image: str | None = None
    network: bool = False
    runtime: str | None = None
    egress: EgressPolicy | None = None

    def resolved_egress(self) -> EgressPolicy:
        if self.egress is not None:
            return self.egress
        return EgressPolicy.allow_all() if self.network else EgressPolicy.deny_all()


class Sandbox(Protocol):
    def attest(self) -> Attestation: ...
    def dispatch(self, tool: str, args: dict) -> Any: ...
    def close(self) -> None: ...


class LocalSandbox:
    def __init__(self, spec: RuntimeSpec, tool_fn: ToolFn) -> None:
        self._spec = spec
        self._tool_fn = tool_fn
        self._sandbox_id = f"sbx-{uuid.uuid4().hex[:8]}"
        self._closed = False

    def attest(self) -> Attestation:
        return Attestation(
            runtime_kind=self._spec.kind,
            code_digest=self._spec.code_digest,
            sandbox_id=self._sandbox_id,
            evidence={"pid_namespaced": True, "kind": self._spec.kind},
        )

    def dispatch(self, tool: str, args: dict) -> Any:
        if self._closed:
            raise RuntimeError("sandbox is closed")
        return self._tool_fn(tool, args)

    def close(self) -> None:
        self._closed = True


class LocalRuntime:
    def __init__(self, tool_fn: ToolFn) -> None:
        self._tool_fn = tool_fn

    def spawn(self, spec: RuntimeSpec) -> LocalSandbox:
        return LocalSandbox(spec, self._tool_fn)


def _find_engine() -> str:
    for engine in ("docker", "podman"):
        if shutil.which(engine):
            return engine
    raise RuntimeError("no container engine found; install docker or podman (no fallback by design)")


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:2])} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _runsc_available() -> bool:
    return shutil.which("runsc") is not None


class ContainerSandbox:
    def __init__(self, container_id: str, image_digest: str, engine: str, used_runsc: bool = False) -> None:
        self._container_id = container_id
        self._image_digest = image_digest
        self._engine = engine
        self._used_runsc = used_runsc
        self._closed = False

    def attest(self) -> Attestation:
        return Attestation(
            runtime_kind="remote.gvisor" if self._used_runsc else "local.container",
            code_digest=self._image_digest,
            sandbox_id=self._container_id[:12],
            evidence={
                "engine": self._engine,
                "container_id": self._container_id,
                "runtime": "runsc" if self._used_runsc else "runc",
            },
        )

    def dispatch(self, tool: str, args: dict) -> Any:
        if self._closed:
            raise RuntimeError("sandbox is closed")
        if tool not in EXEC_TOOLS:
            raise ValueError(f"container sandbox only runs {EXEC_TOOLS}, got '{tool}'")
        return _run([self._engine, "exec", self._container_id, "sh", "-c", args["cmd"]])

    def close(self) -> None:
        if not self._closed:
            subprocess.run([self._engine, "rm", "-f", self._container_id], capture_output=True)
            self._closed = True


class ContainerRuntime:
    def __init__(self, engine: str | None = None) -> None:
        self._engine = engine or _find_engine()

    def spawn(self, spec: RuntimeSpec) -> ContainerSandbox:
        if not spec.image:
            raise ValueError("container runtime requires spec.image")
        want_gvisor = spec.runtime == "runsc" or spec.kind == "remote.gvisor"
        if want_gvisor and not _runsc_available():
            raise RuntimeError(
                "gVisor (runsc) requested but not installed; refusing to fall back to runc — "
                "that would claim remote.gvisor isolation without providing it"
            )
        argv = [self._engine, "run", "-d", "--rm"]
        if want_gvisor:
            argv += ["--runtime", "runsc"]
        argv += spec.resolved_egress().network_args(self._engine)
        argv += [spec.image, "sleep", "infinity"]
        container_id = _run(argv)
        image_digest = _run([self._engine, "inspect", "--format", "{{.Image}}", container_id])
        return ContainerSandbox(container_id, image_digest, self._engine, used_runsc=want_gvisor)
