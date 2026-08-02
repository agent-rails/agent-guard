from __future__ import annotations

import functools
from dataclasses import replace
from typing import Any, Callable

from identity.pop import PoPProof, verify_pop
from identity.token import verify as verify_token

from .audit import AuditSink, build_record
from .decision import Decision, Verdict, clamp
from .judge import Judge, JudgeRequest
from .policy import Policy
from .tiers import TRUST_TIERS

ToolDispatch = Callable[[str, dict], Any]
HumanApprover = Callable[["ApprovalRequest"], bool]


class BlockedError(Exception):
    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"blocked tool call '{tool}': {reason}")
        self.tool = tool
        self.reason = reason


class ApprovalRequest:
    def __init__(self, agent_id: str, tool: str, args: dict[str, Any], reason: str) -> None:
        self.agent_id = agent_id
        self.tool = tool
        self.args = args
        self.reason = reason


def deny_by_default(_: ApprovalRequest) -> bool:
    return False


class Guard:
    """`agent_id` and `trust_tier` are trusted as given — the plain constructor is for
    local/no-identity use, where the caller IS the authority. Once a `Broker` is in the
    picture, construct via `from_token` instead, so trust_tier can only come from a
    verified attestation and not from a hand-typed string."""

    def __init__(
        self,
        policy: Policy,
        audit: AuditSink,
        agent_id: str,
        approver: HumanApprover = deny_by_default,
        trust_tier: str = TRUST_TIERS[0],
        judge: Judge | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._agent_id = agent_id
        self._approver = approver
        self._trust_tier = trust_tier
        self._judge = judge

    @classmethod
    def from_token(
        cls,
        encoded_token: str,
        secret: bytes,
        policy: Policy,
        audit: AuditSink,
        approver: HumanApprover = deny_by_default,
        judge: Judge | None = None,
        now: float | None = None,
        pop_proof: PoPProof | None = None,
    ) -> Guard:
        """Bind agent_id and trust_tier to a token that verifies against `secret` — the
        same HMAC `identity.token.sign`/`Broker` use. Takes the encoded string, not a
        bare `Token` object: `Token` is a plain public dataclass, so accepting one
        directly would let a caller hand-construct `Token(trust_tier="remote.microvm",
        ...)` and grant themselves the top tier without ever going through a Broker —
        exactly the hand-typed-tier bypass this method exists to close. Requiring the
        encoded+signed form means producing a valid one requires `secret`.

        If the token is holder-bound (`token.cnf` set — see identity/pop.py), a fresh
        `pop_proof` from the matching PoPKeypair is REQUIRED and verified against the
        exact `encoded_token` presented; without it (or with a wrong/stale/tampered
        one) this raises, even though `secret` and the token signature both check out.
        This is what stops a leaked/stolen encoded token from being usable on its own —
        the bearer string alone is no longer sufficient once `cnf` is set."""
        if not isinstance(encoded_token, str):
            raise TypeError(
                "from_token expects an encoded, signed token string (identity.token.sign(token, secret)), "
                "not a bare Token object — a Token can be hand-constructed with any trust_tier and carries "
                "no signature on its own"
            )
        token = verify_token(encoded_token, secret, now)
        if token.cnf is not None:
            if pop_proof is None:
                raise ValueError("token is holder-bound (cnf set) but no pop_proof was provided")
            if not verify_pop(pop_proof, encoded_token, token.cnf, now):
                raise ValueError("pop_proof failed verification against token.cnf")
        return cls(
            policy=policy,
            audit=audit,
            agent_id=token.agent_id,
            approver=approver,
            trust_tier=token.trust_tier,
            judge=judge,
        )

    def wrap(self, dispatch: ToolDispatch) -> ToolDispatch:
        def guarded(tool: str, args: dict[str, Any]) -> Any:
            return self.call(dispatch, tool, args)

        return guarded

    def decide(self, tool: str, args: dict[str, Any]) -> tuple[bool, Verdict]:
        """Pure decision: returns (allowed, verdict). Runs policy + judge + human gate but
        does not dispatch or audit. `verdict.decision` keeps its original tier
        (allow/deny/require_human) for the audit record; `allowed` is the gate outcome."""
        verdict = self._policy.evaluate(tool, args, self._trust_tier)
        if verdict.needs_judge:
            verdict = self._consult_judge(verdict, tool, args)
        if verdict.decision is Decision.DENY:
            return False, verdict
        if verdict.decision is Decision.REQUIRE_HUMAN:
            approved = self._approver(ApprovalRequest(self._agent_id, tool, args, verdict.reason))
            return approved, verdict
        return True, verdict

    def record(self, tool: str, args: dict[str, Any], verdict: Verdict, executed: bool) -> None:
        self._audit.write(build_record(self._agent_id, tool, args, verdict, executed))

    def call(self, dispatch: ToolDispatch, tool: str, args: dict[str, Any]) -> Any:
        allowed, verdict = self.decide(tool, args)
        if not allowed:
            self.record(tool, args, verdict, executed=False)
            reason = verdict.reason if verdict.decision is Decision.DENY else f"human approval denied: {verdict.reason}"
            raise BlockedError(tool, reason)
        result = dispatch(tool, args)
        self.record(tool, args, verdict, executed=True)
        return result

    def _consult_judge(self, verdict: Verdict, tool: str, args: dict[str, Any]) -> Verdict:
        fallback = verdict.decision
        if self._judge is None:
            return replace(verdict, reason=f"judge required, none configured; fail-closed to {fallback.value}")
        try:
            decision, why = self._judge.evaluate(
                JudgeRequest(self._agent_id, tool, args, verdict.reason, verdict.judge_ceiling)
            )
        except Exception as err:  # noqa: BLE001 - judge is an untrusted edge; fail closed to the rule fallback
            return replace(verdict, reason=f"judge error ({err}); fail-closed to {fallback.value}")
        final = clamp(decision, verdict.judge_ceiling)
        return replace(
            verdict, decision=final, reason=f"judge->{final.value} (ceiling {verdict.judge_ceiling.value}): {why}"
        )


def guarded(guard: Guard, tool_name: str | None = None) -> Callable:
    """Decorator: protect a plain tool function. The function's keyword arguments are the
    tool args the policy sees. Raises BlockedError if policy denies.

        @guarded(guard, "run_sql")
        def run_sql(query): ...
    """

    def decorate(fn: Callable) -> Callable:
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            allowed, verdict = guard.decide(name, kwargs)
            if not allowed:
                guard.record(name, kwargs, verdict, executed=False)
                reason = (
                    verdict.reason if verdict.decision is Decision.DENY else f"human approval denied: {verdict.reason}"
                )
                raise BlockedError(name, reason)
            result = fn(*args, **kwargs)
            guard.record(name, kwargs, verdict, executed=True)
            return result

        return wrapper

    return decorate
