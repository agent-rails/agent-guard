from __future__ import annotations

from dataclasses import dataclass

_MODES = ("deny", "allow")


@dataclass(frozen=True)
class EgressPolicy:
    """Network egress rule for a sandbox, enforced at the container boundary.

    Deterministic and fail-closed by design: the agent inside the sandbox cannot
    influence it. Default is deny (no network). A host allowlist is modelled but
    needs an egress proxy to enforce, which the MVP does not ship — so
    ``network_args`` fails loud rather than silently granting full network.
    """

    default: str = "deny"
    allow_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.default not in _MODES:
            raise ValueError(f"egress default must be one of {_MODES}, got {self.default!r}")

    @classmethod
    def deny_all(cls) -> EgressPolicy:
        return cls(default="deny")

    @classmethod
    def allow_all(cls) -> EgressPolicy:
        return cls(default="allow")

    def allows(self, host: str) -> bool:
        if self.allow_hosts:
            # network_args() refuses to build a container for any policy that sets
            # allow_hosts (no egress proxy ships in the MVP to enforce it) — allows()
            # must fail the same way instead of claiming a host is usable when no
            # container could ever actually be spawned to enforce that claim.
            raise NotImplementedError("host allowlist needs an egress proxy; not in MVP — use deny_all or allow_all")
        return self.default == "allow"

    def network_args(self, engine: str) -> list[str]:
        if self.allow_hosts:
            raise NotImplementedError("host allowlist needs an egress proxy; not in MVP — use deny_all or allow_all")
        if self.default == "deny":
            return ["--network=none"]
        return []
