from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .evidence_log import EvidenceError, EvidenceLog, Row, to_utc, trust_line
from .inventory import DECISION_EVENTS

FIRST_TOOL_USE = "first_tool_use"
FIRST_RESOURCE_USE = "first_resource_use"
RATE_ABOVE_BASELINE = "rate_above_baseline"
OUTSIDE_USUAL_HOURS = "outside_usual_hours"
ALERT_KINDS = (FIRST_TOOL_USE, FIRST_RESOURCE_USE, RATE_ABOVE_BASELINE, OUTSIDE_USUAL_HOURS)
DEPTH_SKIPPED = "delegation depth check skipped: the audit schema has no delegation depth field"
SECONDS_PER_HOUR = 3600


class DetectError(Exception):
    pass


@dataclass(frozen=True)
class DetectConfig:
    """Baseline window is [baseline_from, evaluate_from); evaluation window is [evaluate_from, evaluate_until).
    Open ends default to the earliest and latest row. `usual_hours` is a set of UTC hours; None disables the
    off-hours check."""

    evaluate_from: datetime
    baseline_from: datetime | None = None
    evaluate_until: datetime | None = None
    rate_multiplier: float = 3.0
    min_rate_events: int = 5
    usual_hours: frozenset[int] | None = None

    def __post_init__(self) -> None:
        for name in ("evaluate_from", "baseline_from", "evaluate_until"):
            value = getattr(self, name)
            if value is None:
                continue
            converted = to_utc(value)
            if converted is None:
                raise DetectError(f"{name} must be a timezone-aware time representable in UTC")
            object.__setattr__(self, name, converted)
        if self.rate_multiplier <= 0:
            raise DetectError("rate_multiplier must be positive")
        if self.min_rate_events < 1:
            raise DetectError("min_rate_events must be at least 1")
        if self.usual_hours is not None and (not self.usual_hours or not all(0 <= h <= 23 for h in self.usual_hours)):
            raise DetectError("usual_hours must be a non-empty set of UTC hours 0-23")


@dataclass(frozen=True)
class Alert:
    kind: str
    persona: str
    tenant_id: str | None
    ts: str
    detail: str
    count: int = 1
    task_roots: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectResult:
    audit_path: str
    rows: int
    malformed: int
    baseline_rows: int
    evaluated_rows: int
    alerts: list[Alert]
    untrusted: int = 0
    verified: bool = False
    skipped: list[str] = field(default_factory=list)


Persona = tuple[str, str | None]


def persona_of(row: Row) -> Persona:
    return (row.data.get("purpose") or row.actor), row.tenant_id


def parse_usual_hours(text: str) -> frozenset[int]:
    """Parse `START-END` as UTC hours, START inclusive and END exclusive, wrapping past midnight."""
    try:
        start_text, end_text = text.split("-")
        start, end = int(start_text), int(end_text)
    except ValueError as err:
        raise DetectError(f"usual hours must look like 8-18, got {text!r}") from err
    if not (0 <= start <= 23 and 0 <= end <= 24) or start == end:
        raise DetectError(f"usual hours out of range: {text!r}")
    hours = range(start, end) if start < end else [*range(start, 24), *range(0, end % 24)]
    return frozenset(hours)


def _resource(row: dict) -> str | None:
    args = row.get("args")
    value = args.get("resource") if isinstance(args, dict) else None
    return value if isinstance(value, str) and value else None


def _task_roots(rows: list[dict]) -> tuple[str, ...]:
    return tuple(
        sorted({row["task_root"] for row in rows if isinstance(row.get("task_root"), str) and row["task_root"]})
    )


def _hour_bucket(stamp: datetime) -> datetime:
    return stamp.replace(minute=0, second=0, microsecond=0)


def detect_file(
    audit_path: Path, config: DetectConfig, secret: bytes | None = None, allow_unsigned: bool = False
) -> DetectResult:
    try:
        log = EvidenceLog(audit_path, secret, allow_unsigned)
    except EvidenceError as err:
        raise DetectError(str(err)) from err
    sequence = sorted(
        ((row.ts, persona_of(row), row.data) for row in log.rows() if row.data.get("event") in DECISION_EVENTS),
        key=lambda item: item[0],
    )
    start, boundary, until = config.baseline_from, config.evaluate_from, config.evaluate_until
    baseline = [item for item in sequence if (start is None or item[0] >= start) and item[0] < boundary]
    evaluated = [item for item in sequence if item[0] >= boundary and (until is None or item[0] < until)]

    alerts = [
        *_first_use(baseline, evaluated),
        *_rate(baseline, evaluated, config, start or (baseline[0][0] if baseline else boundary), boundary),
        *_off_hours(evaluated, config),
    ]
    alerts.sort(key=lambda alert: (alert.ts, alert.kind, alert.persona))
    return DetectResult(
        str(audit_path),
        log.rows_read,
        log.malformed,
        len(baseline),
        len(evaluated),
        alerts,
        log.untrusted,
        log.verified,
        [DEPTH_SKIPPED],
    )


def _first_use(baseline: list, evaluated: list) -> list[Alert]:
    known_tools: dict[Persona, set[str]] = defaultdict(set)
    known_resources: dict[Persona, set[str]] = defaultdict(set)
    for _stamp, persona, row in baseline:
        known_tools[persona].add(row["tool"])
        if (resource := _resource(row)) is not None:
            known_resources[persona].add(resource)
    alerts: list[Alert] = []
    for stamp, persona, row in evaluated:
        if row["tool"] not in known_tools[persona]:
            known_tools[persona].add(row["tool"])
            alerts.append(
                Alert(
                    FIRST_TOOL_USE,
                    persona[0],
                    persona[1],
                    stamp.isoformat(),
                    f"tool {row['tool']!r}",
                    task_roots=_task_roots([row]),
                )
            )
        resource = _resource(row)
        if resource is not None and resource not in known_resources[persona]:
            known_resources[persona].add(resource)
            alerts.append(
                Alert(
                    FIRST_RESOURCE_USE,
                    persona[0],
                    persona[1],
                    stamp.isoformat(),
                    f"resource {resource!r}",
                    task_roots=_task_roots([row]),
                )
            )
    return alerts


def _hourly(evaluated: list, keep=lambda stamp: True) -> list[tuple[Persona, datetime, list[dict]]]:
    grouped: dict[tuple[Persona, datetime], list[dict]] = defaultdict(list)
    for stamp, persona, row in evaluated:
        if keep(stamp):
            grouped[(persona, _hour_bucket(stamp))].append(row)
    ordered = sorted(grouped.items(), key=lambda item: (item[0][1], item[0][0][0], item[0][0][1] or ""))
    return [(persona, bucket, rows) for (persona, bucket), rows in ordered]


def _rate(baseline: list, evaluated: list, config: DetectConfig, start: datetime, boundary: datetime) -> list[Alert]:
    baseline_hours = (boundary - start).total_seconds() / SECONDS_PER_HOUR
    if baseline_hours <= 0:
        return []
    baseline_counts = Counter(persona for _stamp, persona, _row in baseline)
    alerts: list[Alert] = []
    for persona, bucket, rows in _hourly(evaluated):
        count = len(rows)
        if persona not in baseline_counts or count < config.min_rate_events:
            continue
        baseline_rate = baseline_counts[persona] / baseline_hours
        if count > config.rate_multiplier * baseline_rate:
            detail = (
                f"{count} events in the hour vs baseline {baseline_rate:.2f}/hour (limit {config.rate_multiplier}x)"
            )
            alerts.append(
                Alert(RATE_ABOVE_BASELINE, persona[0], persona[1], bucket.isoformat(), detail, count, _task_roots(rows))
            )
    return alerts


def _off_hours(evaluated: list, config: DetectConfig) -> list[Alert]:
    if config.usual_hours is None:
        return []
    return [
        Alert(
            OUTSIDE_USUAL_HOURS,
            persona[0],
            persona[1],
            bucket.isoformat(),
            f"{len(rows)} events at UTC hour {bucket.hour}",
            len(rows),
            _task_roots(rows),
        )
        for persona, bucket, rows in _hourly(evaluated, lambda stamp: stamp.hour not in config.usual_hours)
    ]


def render_detect(result: DetectResult) -> str:
    lines = [
        f"audit: {result.audit_path}",
        trust_line(result.verified, result.untrusted),
        f"rows read: {result.rows}",
        f"malformed lines: {result.malformed}",
        f"baseline rows: {result.baseline_rows}",
        f"evaluated rows: {result.evaluated_rows}",
        *(f"skipped: {note}" for note in result.skipped),
        f"alerts ({len(result.alerts)}):",
    ]
    for alert in result.alerts:
        lines.append(
            f"  [{alert.kind}] persona={alert.persona} tenant={alert.tenant_id or '-'} at {alert.ts}: {alert.detail}"
        )
    return "\n".join(lines)
