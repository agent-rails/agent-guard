from __future__ import annotations

import copy
import fnmatch
import functools
import hashlib
import inspect
import json
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import Any

from agentguard_identity.pop import PoPProof, verify_pop
from agentguard_identity.token import verify as verify_token

from .audit import AuditSink, build_record
from .decision import Decision, Verdict, clamp
from .judge import Judge, JudgeRequest
from .policy import Policy
from .tiers import TRUST_TIERS
from .velocity import VelocityLimiter

ToolDispatch = Callable[[str, dict], Any]
HumanApprover = Callable[["ApprovalRequest"], "ApprovalGrant | None"]


class BlockedError(Exception):
    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"blocked tool call '{tool}': {reason}")
        self.tool = tool
        self.reason = reason


@dataclass(frozen=True)
class ApprovalRequest:
    """One approval prompt, bound to this exact call and its policy verdict."""

    agent_id: str
    tool: str
    args: dict[str, Any]
    reason: str
    call_id: str
    call_digest: str
    rule_id: str | None
    module: str | None
    layer: int | None
    trust_tier: str


@dataclass(frozen=True)
class ApprovalGrant:
    """Approval bound to one request; stale or cross-call grants are rejected."""

    call_id: str
    call_digest: str


def deny_by_default(_: ApprovalRequest) -> ApprovalGrant | None:
    return None


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
        scopes: tuple[str, ...] | None = None,
        velocity: VelocityLimiter | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._agent_id = agent_id
        self._approver = approver
        self._trust_tier = trust_tier
        self._judge = judge
        self._scopes = scopes
        self._velocity = velocity

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
        velocity: VelocityLimiter | None = None,
    ) -> Guard:
        """Bind agent_id and trust_tier to a token that verifies against `secret` — the
        same HMAC `agentguard_identity.token.sign`/`Broker` use. Takes the encoded string, not a
        bare `Token` object: `Token` is a plain public dataclass, so accepting one
        directly would let a caller hand-construct `Token(trust_tier="remote.microvm",
        ...)` and grant themselves the top tier without ever going through a Broker —
        exactly the hand-typed-tier bypass this method exists to close. Requiring the
        encoded+signed form means producing a valid one requires `secret`.

        If the token is holder-bound (`token.cnf` set — see agentguard_identity/pop.py), a fresh
        `pop_proof` from the matching PoPKeypair is REQUIRED and verified against the
        exact `encoded_token` presented; without it (or with a wrong/stale/tampered
        one) this raises, even though `secret` and the token signature both check out.
        This is what stops a leaked/stolen encoded token from being usable on its own —
        the bearer string alone is no longer sufficient once `cnf` is set."""
        if not isinstance(encoded_token, str):
            raise TypeError(
                "from_token expects an encoded, signed token string (agentguard_identity.token.sign(token, secret)), "
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
            scopes=token.scopes,
            velocity=velocity,
        )

    def wrap(self, dispatch: ToolDispatch) -> ToolDispatch:
        def guarded(tool: str, args: dict[str, Any]) -> Any:
            return self.call(dispatch, tool, args)

        return guarded

    def decide(self, tool: str, args: dict[str, Any]) -> tuple[bool, Verdict]:
        """Decision: returns (allowed, verdict). Runs policy + judge + human gate, then the
        velocity limiter; does not dispatch or audit. `verdict.decision` keeps its original
        tier (allow/deny/require_human) for the audit record; `allowed` is the gate outcome.

        When a `velocity` limiter is configured this method is no longer side-effect-free:
        resolving a would-be-allowed call records it against the limiter's window, because
        rate IS part of the decision. Velocity is consulted only once a call would otherwise
        proceed — after policy+judge resolve to allow, and (for `require_human`) only after a
        human actually approves — so a denied or rejected call never consumes velocity budget.
        """
        try:
            call_args = _canonical_args(args)
        except _UNCANONICAL_ERRORS as err:
            return False, _uncanonical_verdict(err)
        return self._decide(tool, call_args, uuid.uuid4().hex)[:2]

    def _decide(
        self,
        tool: str,
        args: dict[str, Any],
        call_id: str,
        before_approval: Callable[[Verdict, str], None] | None = None,
    ) -> tuple[bool, Verdict, str]:
        if self._scopes is not None and not any(fnmatch.fnmatch(tool, scope) for scope in self._scopes):
            verdict = Verdict(
                decision=Decision.DENY,
                reason=f"tool '{tool}' is outside token scopes",
                rule_id="token-scope",
            )
            return False, verdict, _call_digest(self._agent_id, tool, args, verdict, self._trust_tier)
        verdict = self._policy.evaluate(tool, args, self._trust_tier)
        if verdict.needs_judge:
            verdict = self._consult_judge(verdict, tool, copy.deepcopy(args))
        digest = _call_digest(self._agent_id, tool, args, verdict, self._trust_tier)
        if verdict.decision is Decision.DENY:
            return False, verdict, digest
        if verdict.decision is Decision.REQUIRE_HUMAN:
            if before_approval is not None:
                before_approval(verdict, digest)
            # The approver receives a detached copy. If it mutates what it displayed,
            # reject the approval instead of dispatching arguments different from the
            # approval request. The dispatch snapshot itself is never exposed here.
            approval_args = copy.deepcopy(args)
            request = ApprovalRequest(
                self._agent_id,
                tool,
                approval_args,
                verdict.reason,
                call_id,
                digest,
                verdict.rule_id,
                verdict.module,
                verdict.layer,
                self._trust_tier,
            )
            approval = self._approver(request)
            if _call_digest(self._agent_id, tool, approval_args, verdict, self._trust_tier) != digest:
                return False, replace(verdict, reason="approval request arguments changed; fail-closed to deny"), digest
            if not isinstance(approval, ApprovalGrant) or approval.call_id != call_id or approval.call_digest != digest:
                return False, verdict, digest
            allowed, final_verdict = self._apply_velocity(tool, verdict)
            if not allowed:
                digest = _call_digest(self._agent_id, tool, args, final_verdict, self._trust_tier)
            return allowed, final_verdict, digest
        allowed, final_verdict = self._apply_velocity(tool, verdict)
        if not allowed:
            digest = _call_digest(self._agent_id, tool, args, final_verdict, self._trust_tier)
        return allowed, final_verdict, digest

    def record(
        self,
        tool: str,
        args: dict[str, Any],
        verdict: Verdict,
        executed: bool,
        error: str | None = None,
        *,
        event: str | None = None,
        call_id: str | None = None,
        call_digest: str | None = None,
        outcome: str | None = None,
    ) -> None:
        if verdict.rule_id == ARGS_NOT_CANONICAL_RULE_ID:
            args = {}
        self._audit.write(
            build_record(
                self._agent_id,
                tool,
                args,
                verdict,
                executed,
                error=error,
                event=event,
                call_id=call_id,
                call_digest=call_digest,
                outcome=outcome,
            )
        )

    def call(self, dispatch: ToolDispatch, tool: str, args: dict[str, Any]) -> Any:
        call_id = uuid.uuid4().hex
        try:
            call_args = _canonical_args(args)
        except _UNCANONICAL_ERRORS as err:
            verdict = _uncanonical_verdict(err)
            self.record(
                tool,
                {},
                verdict,
                executed=False,
                event="decision",
                call_id=call_id,
                call_digest=_call_digest(self._agent_id, tool, {}, verdict, self._trust_tier),
                outcome="blocked",
            )
            raise BlockedError(tool, verdict.reason) from err
        allowed, verdict, digest = self._decide(
            tool,
            call_args,
            call_id,
            before_approval=lambda approval_verdict, approval_digest: self.record(
                tool,
                copy.deepcopy(call_args),
                approval_verdict,
                executed=False,
                event="decision",
                call_id=call_id,
                call_digest=approval_digest,
                outcome="approval_requested",
            ),
        )
        if not allowed:
            self.record(
                tool,
                call_args,
                verdict,
                executed=False,
                event="decision",
                call_id=call_id,
                call_digest=digest,
                outcome="blocked",
            )
            reason = verdict.reason if verdict.decision is Decision.DENY else f"human approval denied: {verdict.reason}"
            raise BlockedError(tool, reason)

        try:
            self.record(
                tool,
                copy.deepcopy(call_args),
                verdict,
                executed=True,
                event="release",
                call_id=call_id,
                call_digest=digest,
                outcome="pending",
            )
        except BaseException:
            self._record_not_dispatched(tool, call_args, verdict, call_id, digest)
            raise
        audit_args = copy.deepcopy(call_args)
        try:
            result = dispatch(tool, call_args)
        except Exception as err:
            try:
                self.record(
                    tool,
                    audit_args,
                    verdict,
                    executed=True,
                    error=str(err),
                    event="terminal",
                    call_id=call_id,
                    call_digest=digest,
                    outcome="raised",
                )
            except Exception as audit_err:
                _chain_audit_failure(err, audit_err)
                raise err from err.__cause__
            raise
        except BaseException as err:
            try:
                self.record(
                    tool,
                    audit_args,
                    verdict,
                    executed=True,
                    error=f"{type(err).__name__}: dispatch did not return; side-effect outcome unknown",
                    event="terminal",
                    call_id=call_id,
                    call_digest=digest,
                    outcome="unknown",
                )
            except BaseException as audit_err:
                _chain_audit_failure(err, audit_err)
                raise err from err.__cause__
            raise
        self.record(
            tool,
            audit_args,
            verdict,
            executed=True,
            event="terminal",
            call_id=call_id,
            call_digest=digest,
            outcome="returned",
        )
        return result

    def _record_not_dispatched(
        self, tool: str, call_args: dict[str, Any], verdict: Verdict, call_id: str, digest: str
    ) -> None:
        with suppress(Exception):
            self.record(
                tool,
                copy.deepcopy(call_args),
                verdict,
                executed=False,
                error="release audit write failed; dispatch not called",
                event="terminal",
                call_id=call_id,
                call_digest=digest,
                outcome="not_dispatched",
            )

    def _apply_velocity(self, tool: str, verdict: Verdict) -> tuple[bool, Verdict]:
        if self._velocity is None:
            return True, verdict
        try:
            breach = self._velocity.check(self._agent_id, tool)
        except Exception as err:  # noqa: BLE001 - the limiter is a fallible edge; fail closed, never silently allow
            return False, Verdict(
                decision=Decision.DENY,
                reason=f"velocity limiter error ({err}); fail-closed to deny",
                rule_id="velocity-limit",
            )
        if breach is not None:
            return False, Verdict(decision=Decision.DENY, reason=breach, rule_id="velocity-limit")
        return True, verdict

    def _consult_judge(self, verdict: Verdict, tool: str, args: dict[str, Any]) -> Verdict:
        fallback = verdict.decision
        # A rule's own `decision` is the hard boundary static policy already set; the
        # authored judge_ceiling can only narrow that further, never widen past it --
        # otherwise a rule authored as decision=deny + judge_ceiling=allow would let a
        # judge escalate a static DENY all the way to ALLOW, which DESIGN.md's stated
        # invariant ("advisory within hard bounds set by static policy, never the
        # boundary itself") explicitly rules out.
        ceiling = clamp(verdict.judge_ceiling, verdict.decision)
        if self._judge is None:
            return replace(verdict, reason=f"judge required, none configured; fail-closed to {fallback.value}")
        try:
            decision, why = self._judge.evaluate(JudgeRequest(self._agent_id, tool, args, verdict.reason, ceiling))
        except Exception as err:  # noqa: BLE001 - judge is an untrusted edge; fail closed to the rule fallback
            return replace(verdict, reason=f"judge error ({err}); fail-closed to {fallback.value}")
        final = clamp(decision, ceiling)
        return replace(verdict, decision=final, reason=f"judge->{final.value} (ceiling {ceiling.value}): {why}")


def guarded(guard: Guard, tool_name: str | None = None) -> Callable:
    """Decorator: protect a plain tool function. Positional and keyword arguments are bound
    to the function's parameter names; those named arguments are the tool args the policy
    sees, the approver is shown, and the audit record carries. The function runs on the
    canonical JSON copy of those arguments, not the caller's objects. Raises BlockedError
    if policy denies or an argument is not JSON-serializable.

        @guarded(guard, "run_sql")
        def run_sql(query): ...
    """

    def decorate(fn: Callable) -> Callable:
        name = tool_name or fn.__name__
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            return guard.call(_dispatch_bound(fn, bound), name, _flatten_bound(bound))

        return wrapper

    return decorate


def _flatten_bound(bound: inspect.BoundArguments) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for param_name, value in bound.arguments.items():
        if bound.signature.parameters[param_name].kind is not inspect.Parameter.VAR_KEYWORD:
            flat[param_name] = value
            continue
        shadowed = flat.keys() & value.keys()
        if shadowed:
            raise TypeError(f"keyword arguments {sorted(shadowed)} collide with named parameters")
        flat.update(value)
    return flat


def _dispatch_bound(fn: Callable, bound: inspect.BoundArguments) -> ToolDispatch:
    var_keyword = next(
        (n for n, p in bound.signature.parameters.items() if p.kind is inspect.Parameter.VAR_KEYWORD), None
    )

    def dispatch(_tool: str, call_args: dict[str, Any]) -> Any:
        arguments = {n: call_args[n] for n in bound.arguments if n != var_keyword}
        if var_keyword in bound.arguments:
            arguments[var_keyword] = {key: call_args[key] for key in bound.arguments[var_keyword]}
        bound.arguments = arguments
        return fn(*bound.args, **bound.kwargs)

    return dispatch


MAX_ARGS_DEPTH = 64
ARGS_NOT_CANONICAL_RULE_ID = "args-not-canonical"
_UNCANONICAL_ERRORS = (TypeError, ValueError, RecursionError)


def _uncanonical_verdict(err: Exception) -> Verdict:
    return Verdict(
        decision=Decision.DENY,
        reason=f"arguments are not canonical JSON; fail-closed to deny: {err}",
        rule_id=ARGS_NOT_CANONICAL_RULE_ID,
    )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _canonical_args(args: dict[str, Any]) -> dict[str, Any]:
    canonical = json.loads(_canonical_json(args))
    if _nesting_depth(canonical) > MAX_ARGS_DEPTH:
        raise ValueError(f"arguments nest deeper than {MAX_ARGS_DEPTH} levels")
    return canonical


def _nesting_depth(value: Any) -> int:
    deepest = 0
    pending = [(value, 1)]
    while pending:
        node, level = pending.pop()
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        deepest = max(deepest, level)
        pending.extend((child, level + 1) for child in children)
    return deepest


def _causes(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    while exc.__cause__ is not None and exc.__cause__ not in chain:
        exc = exc.__cause__
        chain.append(exc)
    return chain


def _chain_audit_failure(err: BaseException, audit_err: BaseException) -> None:
    if audit_err is err or audit_err in _causes(err) or err in _causes(audit_err):
        return
    if audit_err.__cause__ is None:
        audit_err.__cause__ = err.__cause__
    err.__cause__ = audit_err


def _call_digest(agent_id: str, tool: str, args: dict[str, Any], verdict: Verdict, trust_tier: str) -> str:
    body = {
        "agent_id": agent_id,
        "tool": tool,
        "args": args,
        "trust_tier": trust_tier,
        "verdict": {
            "decision": verdict.decision.value,
            "reason": verdict.reason,
            "rule_id": verdict.rule_id,
            "module": verdict.module,
            "layer": verdict.layer,
            "needs_judge": verdict.needs_judge,
            "judge_ceiling": verdict.judge_ceiling.value,
        },
    }
    return hashlib.sha256(_canonical_json(body)).hexdigest()
