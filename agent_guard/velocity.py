from __future__ import annotations

import fnmatch
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class VelocityRule:
    tools: tuple[str, ...]
    max_calls: int
    window_seconds: float
    id: str = "velocity"

    def __post_init__(self) -> None:
        if not self.tools:
            raise ValueError(f"velocity rule '{self.id}' must match at least one tool pattern")
        if self.max_calls < 1:
            raise ValueError(f"velocity rule '{self.id}' requires max_calls >= 1, got {self.max_calls}")
        if self.window_seconds <= 0:
            raise ValueError(f"velocity rule '{self.id}' requires window_seconds > 0, got {self.window_seconds}")

    def matches(self, tool: str) -> bool:
        return any(fnmatch.fnmatch(tool, pattern) for pattern in self.tools)


class VelocityLimiter(Protocol):
    def check(self, agent_id: str, tool: str) -> str | None:
        """Return None if the call is within every matching velocity rule (recording it),
        or a human-readable reason string if any matching rule is exceeded (recording nothing)."""
        ...


@dataclass
class InMemoryVelocityLimiter:
    """Per-agent, per-tool call-count velocity over a sliding time window, held in memory.

    Sits downstream of the deterministic policy engine: it does not decide what a call
    IS, only whether an already-allowed call arrives too fast. A call is checked against
    every velocity rule whose tool pattern matches; if any matching rule's window is full
    the call is denied and consumes no budget on any rule, so a denied call never extends
    a window (no self-inflicted permanent lockout).

    In-memory only: a process restart resets every counter. An attacker who can restart
    the host resets their own velocity budget — a real, disclosed residual, not a solved
    problem. Swap in a durable `VelocityLimiter` (Redis, etc.) to close it without touching
    `Guard`.

    Memory: one deque per (agent_id, rule) that has in-window activity, each holding at
    most `max_calls` timestamps (pruned every check; denied calls are never recorded, so a
    window can never exceed `max_calls`). Empty windows are evicted on their next touch. For
    the primary usage — one `Guard`, one `agent_id` — the tracked-key count is bounded by
    the number of rules. A single limiter shared across an unbounded, never-repeating set of
    `agent_id`s is the durable-backend case and an explicit non-goal here.
    """

    rules: tuple[VelocityRule, ...]
    clock: Callable[[], float] = time.monotonic
    _windows: dict[tuple[str, int], deque[float]] = field(default_factory=dict, init=False, repr=False)

    def check(self, agent_id: str, tool: str) -> str | None:
        now = self.clock()
        matching = [(index, rule) for index, rule in enumerate(self.rules) if rule.matches(tool)]
        if not matching:
            return None
        for index, rule in matching:
            key = (agent_id, index)
            stamps = self._windows.get(key)
            if stamps is None:
                continue
            cutoff = now - rule.window_seconds
            while stamps and stamps[0] <= cutoff:
                stamps.popleft()
            if not stamps:
                del self._windows[key]
            elif len(stamps) >= rule.max_calls:
                return (
                    f"velocity limit exceeded for tool '{tool}': rule '{rule.id}' allows "
                    f"{rule.max_calls} call(s) per {rule.window_seconds:g}s"
                )
        for index, _rule in matching:
            self._windows.setdefault((agent_id, index), deque()).append(now)
        return None
