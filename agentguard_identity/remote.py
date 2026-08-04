from __future__ import annotations

from typing import Any, Callable, Protocol

from .attestation import Attestation, AttestationResult
from .pop import PoPCapableSandbox

EXEC_TOOLS = {"shell", "exec"}


class RemoteClient(Protocol):
    def run(self, cmd: str) -> str: ...
    def kill(self) -> None: ...
    @property
    def id(self) -> str: ...
    @property
    def template(self) -> str: ...


class RemoteSandbox(PoPCapableSandbox):
    """Adapter over a hosted micro-sandbox provider (E2B / Daytona / Modal). The client
    is injected, so this is testable offline and vendor-neutral. Attestation here is
    provider-asserted (the provider vouches for the template), not hardware-rooted — so
    the honest tier is remote.gvisor, not remote.microvm. See the trust gradient doc."""

    def __init__(self, client: RemoteClient, pop_enabled: bool = False) -> None:
        self._client = client
        self._closed = False
        self._init_pop(pop_enabled)

    def attest(self) -> Attestation:
        if self._closed:
            raise RuntimeError("cannot attest a closed sandbox")
        return Attestation(
            runtime_kind="remote.gvisor",
            code_digest=self._client.template,
            sandbox_id=self._client.id,
            evidence={"provider_asserted": True, "template": self._client.template},
        )

    def dispatch(self, tool: str, args: dict) -> Any:
        if self._closed:
            raise RuntimeError("sandbox is closed")
        if tool not in EXEC_TOOLS:
            raise ValueError(f"remote sandbox only runs {EXEC_TOOLS}, got '{tool}'")
        return self._client.run(args["cmd"])

    def close(self) -> None:
        if not self._closed:
            self._client.kill()
            self._closed = True


class ProviderAttestor:
    """Verifies a remote sandbox against an allowlist of trusted template digests.
    Grants remote.gvisor at most — provider assertion is not a TEE quote."""

    def __init__(self, template_allowlist: set[str]) -> None:
        self._allow = template_allowlist

    def verify(self, attestation: Attestation) -> AttestationResult:
        if attestation.code_digest not in self._allow:
            return AttestationResult(
                False, "local.process", attestation.sandbox_id, f"template '{attestation.code_digest}' not allowlisted"
            )
        return AttestationResult(
            True, "remote.gvisor", attestation.sandbox_id, "template allowlisted (provider-asserted)"
        )


class E2BRuntime:
    """Spawns E2B sandboxes (Firecracker micro-VMs). Fails loud if the SDK/key is
    missing — no fallback. LIVE-UNVERIFIED in this repo's CI (needs an E2B account);
    the adapter shape follows the E2B Python SDK. Inject `client_factory` to test."""

    def __init__(self, template: str = "base", client_factory: Callable[[str], RemoteClient] | None = None) -> None:
        self._template = template
        self._client_factory = client_factory or _default_e2b_factory

    def spawn(self, spec=None) -> RemoteSandbox:
        pop_enabled = spec.pop_enabled if spec is not None else False
        return RemoteSandbox(self._client_factory(self._template), pop_enabled=pop_enabled)


def _default_e2b_factory(template: str) -> RemoteClient:
    try:
        from e2b import Sandbox
    except ImportError as err:
        raise RuntimeError("E2B SDK not installed; `pip install e2b` (no fallback by design)") from err

    class _E2BClient:
        def __init__(self) -> None:
            self._sbx = Sandbox(template=template)

        def run(self, cmd: str) -> str:
            result = self._sbx.commands.run(cmd)
            if result.exit_code != 0:
                # Discarding stderr/exit_code here made a failed remote command
                # indistinguishable from a successful one that happened to print
                # nothing to stdout -- raise instead of returning a misleadingly
                # empty/partial success.
                raise RuntimeError(f"remote command failed (exit {result.exit_code}): {result.stderr}")
            return result.stdout

        def kill(self) -> None:
            self._sbx.kill()

        @property
        def id(self) -> str:
            return self._sbx.sandbox_id

        @property
        def template(self) -> str:
            return template

    return _E2BClient()
