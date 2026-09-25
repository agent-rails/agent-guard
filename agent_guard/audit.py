from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Protocol

from .decision import Verdict

Poster = Callable[[str, bytes, dict, float], None]


@dataclass(frozen=True)
class AuditRecord:
    """One decision, and whether the guard released the call to the tool.

    `executed` means the guard released the call — NOT that the tool completed.
    The guard is an authorization boundary, not a tool runtime: in the MCP proxy
    (`agent_guard.mcp`) the record is written when the allowed `tools/call` is
    released for forwarding to the server, and the proxy never learns the outcome, so
    completion is structurally unknowable there. `cli check` is the mirror case — it records
    `executed=False` because it never releases the call; the caller acts on the
    exit code instead.

    `error` carries the failure detail when a released call did not return cleanly.
    A call terminated by a `BaseException` (for example `KeyboardInterrupt` or
    `SystemExit`) is still recorded with `executed=True` and a typed error saying the
    side-effect outcome is unknown."""

    ts: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    decision: str
    reason: str
    rule_id: str | None
    executed: bool
    sig: str | None = None
    error: str | None = None
    # Optional lifecycle fields. When absent, _signable_body omits them so records
    # signed by older versions keep verifying after an in-memory upgrade.
    event: str | None = None
    call_id: str | None = None
    call_digest: str | None = None
    outcome: str | None = None


class AuditSink(Protocol):
    def write(self, record: AuditRecord) -> None: ...


class JsonlAuditSink:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: AuditRecord) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(record)) + "\n")


class MemoryAuditSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)


class WebhookAuditSink:
    """Ships each audit record to a SIEM / webhook (Splunk HEC, generic collector).
    Audit is load-bearing: a failed delivery raises — it never silently drops a record.
    Wrap in your own best-effort layer if you accept lossy audit. `poster` is injectable
    for tests so the default suite needs no network."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
        poster: Poster | None = None,
    ) -> None:
        self._url = url
        self._headers = {"Content-Type": "application/json", **(headers or {})}
        self._timeout = timeout
        self._post = poster or _urllib_post

    def write(self, record: AuditRecord) -> None:
        body = json.dumps(asdict(record)).encode("utf-8")
        self._post(self._url, body, self._headers, self._timeout)


def _urllib_post(url: str, body: bytes, headers: dict, timeout: float) -> None:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status // 100 != 2:
                raise RuntimeError(f"audit webhook returned HTTP {response.status}")
    except urllib.error.URLError as err:
        raise RuntimeError(f"audit webhook POST to {url} failed: {err}") from err


class CallableAuditSink:
    """Wraps any `emit(record)` callable — the escape hatch for OpenTelemetry, statsd,
    a message queue, or a custom pipeline, without agent-guard depending on any of them.

        sink = CallableAuditSink(lambda r: otel_logger.emit(body=asdict(r)))
    """

    def __init__(self, emit: Callable[[AuditRecord], None]) -> None:
        self._emit = emit

    def write(self, record: AuditRecord) -> None:
        self._emit(record)


def _signable_body(record: AuditRecord) -> bytes:
    payload = asdict(replace(record, sig=None))
    for field in ("event", "call_id", "call_digest", "outcome"):
        if payload[field] is None:
            payload.pop(field)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_record(record: AuditRecord, secret: bytes) -> str:
    mac = hmac.new(secret, _signable_body(record), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode()


def verify_record(record: AuditRecord, secret: bytes) -> bool:
    if record.sig is None:
        return False
    try:
        provided = base64.urlsafe_b64decode(record.sig)
    except (binascii.Error, ValueError):
        return False
    expected = hmac.new(secret, _signable_body(record), hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


class SigningAuditSink:
    """Wraps another sink and attaches an HMAC over each record before writing it.

    Defends against tampering AFTER a record leaves this process: a party that does
    NOT hold `secret` (a downstream store, a network hop, a differently-privileged
    service) cannot forge or edit a record without `verify_record` catching it.

    Does NOT defend against a compromised producer — this process holds `secret` to
    sign in the first place, so a compromised producer signs a forged record just as
    validly as a real one. It also does not detect suppression: a producer that simply
    never calls `write()` for an action leaves no gap here. Defending either of those
    needs a different mechanism (e.g. a verify-only secret the producer can't reach,
    plus sequence numbers or a hash chain across records) — not implemented here.

    Verify with `verify_record` against the same secret at the consuming end."""

    def __init__(self, inner: AuditSink, secret: bytes) -> None:
        if not secret:
            raise ValueError("SigningAuditSink requires a non-empty secret")
        self._inner = inner
        self._secret = secret

    def write(self, record: AuditRecord) -> None:
        self._inner.write(replace(record, sig=sign_record(record, self._secret)))


class MultiAuditSink:
    """Fan-out to several sinks (e.g. local JSONL + remote SIEM). An ordinary sink
    failure never aborts the fan-out — every remaining sink is still attempted, so
    durable local audit survives a flaky remote — and an aggregate is raised once the
    fan-out completes if any sink failed, never a silent drop. Terminating signals are
    the only thing that can cut a fan-out short, under the two rules below.

    An operator signal — `KeyboardInterrupt` (Ctrl-C) or `SystemExit` — raised by one
    sink (one landing inside `WebhookAuditSink`'s blocking POST is the realistic case)
    does not abort the fan-out: the remaining sinks are still attempted, so the durable
    local sink still gets the record. The signal is NOT collected into the
    ordinary-error aggregate — wrapping a terminating signal in a `RuntimeError` would
    swallow it — and is re-raised as itself once the fan-out completes.

    A SECOND operator signal aborts the fan-out immediately and the sinks after it are
    not attempted: a repeated Ctrl-C is an unambiguous instruction to stop, and holding
    it would leave the operator with no way to end a fan-out over slow sinks. The FIRST
    signal is what propagates, so a later sink can never replace the exception type or
    the `SystemExit` code; the second instance is not propagated, but is attached to the
    first as `__context__` so it stays visible in a traceback. This covers signals raised
    out of a sink's `write`, which is where a blocking sink spends its time; one landing
    in the narrow gap between two sink calls is outside the `try` and simply propagates
    as itself, abandoning any held signal and any errors collected so far.

    Only `KeyboardInterrupt` and `SystemExit` are held this way. Every other
    `BaseException` — `asyncio.CancelledError` and `GeneratorExit` in particular —
    propagates immediately with the remaining sinks unattempted, because holding a
    cancellation across a later blocking sink write is how cooperative cancellation and
    `Task.cancel()` timeouts get broken. On that path the record does not reach the
    remaining sinks and ordinary sink errors collected so far are not reported: prompt
    cancellation is worth more than a complete fan-out, and the caller is unwinding
    anyway.

    Ordinary sink errors from the same fan-out are chained onto the propagating signal
    as `__cause__`, nested above any cause the signal already carried so that nothing
    already on the exception is destroyed. That aggregate is synthetic: it summarises
    errors raised elsewhere and so carries no traceback of its own."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = sinks

    def write(self, record: AuditRecord) -> None:
        errors: list[Exception] = []
        terminating: BaseException | None = None
        for sink in self._sinks:
            try:
                sink.write(record)
            except Exception as err:  # noqa: BLE001 - fan-out must attempt every sink before failing
                errors.append(err)
            except (KeyboardInterrupt, SystemExit) as err:
                if terminating is not None:
                    self._raise_terminating(terminating, errors)
                terminating = err
        if terminating is not None:
            self._raise_terminating(terminating, errors)
        if errors:
            raise self._aggregate(errors)

    def _raise_terminating(self, terminating: BaseException, errors: list[Exception]) -> NoReturn:
        if errors:
            aggregate = self._aggregate(errors)
            aggregate.__cause__ = terminating.__cause__
            terminating.__cause__ = aggregate
        raise terminating

    def _aggregate(self, errors: list[Exception]) -> RuntimeError:
        return RuntimeError(f"{len(errors)} of {len(self._sinks)} audit sink(s) failed: {errors}")


def build_record(
    agent_id: str,
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
) -> AuditRecord:
    return AuditRecord(
        ts=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        tool=tool,
        args=args,
        decision=verdict.decision.value,
        reason=verdict.reason,
        rule_id=verdict.rule_id,
        executed=executed,
        error=error,
        event=event,
        call_id=call_id,
        call_digest=call_digest,
        outcome=outcome,
    )


def unresolved_releases(records: Iterable[AuditRecord]) -> list[AuditRecord]:
    """Return released calls with no terminal event in the supplied audit stream.

    This detects a missing terminal record only when the corresponding release
    record is present. It cannot detect a producer that suppresses both events or
    an operator that deletes/replaces the whole stream. It groups records but does
    not authenticate them; verify signatures before relying on signed audit input.
    """
    materialized = list(records)
    terminal_keys = {
        (record.call_id, record.call_digest)
        for record in materialized
        if record.event == "terminal"
        and record.executed
        and record.outcome in {"returned", "raised", "unknown"}
        and record.call_id
        and record.call_digest
    }
    return [
        record
        for record in materialized
        if record.event == "release" and record.call_id and (record.call_id, record.call_digest) not in terminal_keys
    ]
