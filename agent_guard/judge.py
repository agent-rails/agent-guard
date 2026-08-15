from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .decision import Decision

Complete = Callable[[str], str]

JUDGE_PROMPT = """You are a security judge for an AI agent's tool call. Decide whether to allow it.

Tool: {tool}
Arguments: {args}
Why this call needs review: {reason}

You may return one of exactly three verdicts:
- DENY — the call is unsafe or destructive.
- REQUIRE_HUMAN — plausibly fine but needs a human to approve.
- ALLOW — clearly safe.

The most permissive verdict allowed here is {ceiling}; never exceed it.
Respond with a single line: VERDICT: <DENY|REQUIRE_HUMAN|ALLOW> — <one-sentence reason>."""


@dataclass
class JudgeRequest:
    agent_id: str
    tool: str
    args: dict[str, Any]
    reason: str
    ceiling: Decision


class Judge(Protocol):
    def evaluate(self, request: JudgeRequest) -> tuple[Decision, str]: ...


class CallableJudge:
    def __init__(self, fn: Callable[[JudgeRequest], tuple[Decision, str]]) -> None:
        self._fn = fn

    def evaluate(self, request: JudgeRequest) -> tuple[Decision, str]:
        return self._fn(request)


def build_prompt(request: JudgeRequest) -> str:
    return JUDGE_PROMPT.format(
        tool=request.tool,
        args=json.dumps(request.args, default=str),
        reason=request.reason,
        ceiling=request.ceiling.value,
    )


def parse_verdict(text: str) -> tuple[Decision, str]:
    if not isinstance(text, str):
        return Decision.DENY, "non-string judge output, fail-closed"
    upper = text.upper()
    for token, decision in (
        ("DENY", Decision.DENY),
        ("REQUIRE_HUMAN", Decision.REQUIRE_HUMAN),
        ("ALLOW", Decision.ALLOW),
    ):
        if re.search(rf"\b{token}\b", upper):
            reason = text.split("—", 1)[-1].strip() if "—" in text else text.strip()
            return decision, reason[:200] or f"judge said {token}"
    return Decision.DENY, f"unparseable judge output, fail-closed: {text.strip()[:120]}"


class LLMJudge:
    """Provider-agnostic judge. Wraps any text-in/text-out `complete` callable, so you
    bring your own model family (use a *different* vendor than the agent for real
    reasoning diversity). Fail-closed: any error yields DENY, never a silent allow."""

    def __init__(self, complete: Complete) -> None:
        self._complete = complete

    def evaluate(self, request: JudgeRequest) -> tuple[Decision, str]:
        try:
            raw = self._complete(build_prompt(request))
        except Exception as err:  # noqa: BLE001 - the model call is an untrusted edge; fail closed
            return Decision.DENY, f"judge call failed, fail-closed: {err}"
        return parse_verdict(raw)


class ReferenceJudge:
    """Deterministic offline judge for tests and air-gapped defaults. Denies on obvious
    destructive markers, otherwise defers to require_human. Never returns ALLOW."""

    DESTRUCTIVE = (r"(?i)drop\s+table", r"\brm\s+-rf\b", r"(?i)truncate", r"(?i)delete\s+from")

    def evaluate(self, request: JudgeRequest) -> tuple[Decision, str]:
        blob = json.dumps(request.args, default=str)
        for pattern in self.DESTRUCTIVE:
            if re.search(pattern, blob):
                return Decision.DENY, f"reference judge: destructive marker {pattern}"
        return Decision.REQUIRE_HUMAN, "reference judge: no clear signal, defer to human"
