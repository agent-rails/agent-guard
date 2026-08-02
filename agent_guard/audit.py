from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from .decision import Verdict

Poster = Callable[[str, bytes, dict, float], None]


@dataclass(frozen=True)
class AuditRecord:
    ts: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    decision: str
    reason: str
    rule_id: str | None
    executed: bool
    sig: str | None = None


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
    """Fan-out to several sinks (e.g. local JSONL + remote SIEM). Attempts every sink
    even if one fails, so durable local audit survives a flaky remote, then raises an
    aggregate if any sink failed — never a silent drop."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = sinks

    def write(self, record: AuditRecord) -> None:
        errors = []
        for sink in self._sinks:
            try:
                sink.write(record)
            except Exception as err:  # noqa: BLE001 - fan-out must attempt every sink before failing
                errors.append(err)
        if errors:
            raise RuntimeError(f"{len(errors)} of {len(self._sinks)} audit sink(s) failed: {errors}")


def build_record(agent_id: str, tool: str, args: dict[str, Any], verdict: Verdict, executed: bool) -> AuditRecord:
    return AuditRecord(
        ts=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        tool=tool,
        args=args,
        decision=verdict.decision.value,
        reason=verdict.reason,
        rule_id=verdict.rule_id,
        executed=executed,
    )
