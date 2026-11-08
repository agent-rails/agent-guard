from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .inventory import DECISION_EVENTS, row_identity
from .report import read_audit

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
            if value is not None and value.tzinfo is None:
                raise DetectError(f"{name} must be timezone-aware")
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


@dataclass(frozen=True)
class DetectResult:
    audit_path: str
    rows: int
    malformed: int
    baseline_rows: int
    evaluated_rows: int
    alerts: list[Alert]
    skipped: list[str] = field(default_factory=list)


Persona = tuple[str, str | None]


def persona_of(row: dict) -> Persona | None:
    identity = row_identity(row)
    if identity is None:
        return None
    purpose = row.get("purpose")
    if purpose is not None and not (isinstance(purpose, str) and purpose):
        return None
    return (purpose or identity[0]), identity[1]


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


def _hour_bucket(stamp: datetime) -> datetime:
    return stamp.replace(minute=0, second=0, microsecond=0)


def detect_rows(audit_path: str, rows: list[dict], malformed: int, config: DetectConfig) -> DetectResult:
    sequence: list[tuple[datetime, Persona, dict]] = []
    for row in rows:
        persona = persona_of(row)
        if persona is None:
            malformed += 1
            continue
        if row.get("event") not in DECISION_EVENTS:
            continue
        sequence.append((datetime.fromisoformat(row["ts"]).astimezone(timezone.utc), persona, row))
    sequence.sort(key=lambda item: item[0])

    start = config.baseline_from.astimezone(timezone.utc) if config.baseline_from else None
    boundary = config.evaluate_from.astimezone(timezone.utc)
    until = config.evaluate_until.astimezone(timezone.utc) if config.evaluate_until else None
    baseline = [item for item in sequence if (start is None or item[0] >= start) and item[0] < boundary]
    evaluated = [item for item in sequence if item[0] >= boundary and (until is None or item[0] < until)]

    alerts = [
        *_first_use(baseline, evaluated),
        *_rate(baseline, evaluated, config, start or (baseline[0][0] if baseline else boundary), boundary),
        *_off_hours(evaluated, config),
    ]
    alerts.sort(key=lambda alert: (alert.ts, alert.kind, alert.persona))
    return DetectResult(audit_path, len(rows), malformed, len(baseline), len(evaluated), alerts, [DEPTH_SKIPPED])


def detect_file(audit_path: Path, config: DetectConfig) -> DetectResult:
    if not audit_path.exists():
        raise DetectError(f"audit file {audit_path} does not exist")
    rows, malformed = read_audit(audit_path)
    return detect_rows(str(audit_path), rows, malformed, config)


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
            alerts.append(Alert(FIRST_TOOL_USE, persona[0], persona[1], stamp.isoformat(), f"tool {row['tool']!r}"))
        resource = _resource(row)
        if resource is not None and resource not in known_resources[persona]:
            known_resources[persona].add(resource)
            alerts.append(
                Alert(FIRST_RESOURCE_USE, persona[0], persona[1], stamp.isoformat(), f"resource {resource!r}")
            )
    return alerts


def _rate(baseline: list, evaluated: list, config: DetectConfig, start: datetime, boundary: datetime) -> list[Alert]:
    baseline_hours = (boundary - start).total_seconds() / SECONDS_PER_HOUR
    if baseline_hours <= 0:
        return []
    baseline_counts = Counter(persona for _stamp, persona, _row in baseline)
    buckets: Counter = Counter((persona, _hour_bucket(stamp)) for stamp, persona, _row in evaluated)
    alerts: list[Alert] = []
    for (persona, bucket), count in sorted(buckets.items(), key=lambda item: (item[0][1], item[0][0][0])):
        if persona not in baseline_counts or count < config.min_rate_events:
            continue
        baseline_rate = baseline_counts[persona] / baseline_hours
        if count > config.rate_multiplier * baseline_rate:
            detail = (
                f"{count} events in the hour vs baseline {baseline_rate:.2f}/hour (limit {config.rate_multiplier}x)"
            )
            alerts.append(Alert(RATE_ABOVE_BASELINE, persona[0], persona[1], bucket.isoformat(), detail, count))
    return alerts


def _off_hours(evaluated: list, config: DetectConfig) -> list[Alert]:
    if config.usual_hours is None:
        return []
    buckets: Counter = Counter()
    for stamp, persona, _row in evaluated:
        if stamp.hour not in config.usual_hours:
            buckets[(persona, _hour_bucket(stamp))] += 1
    return [
        Alert(
            OUTSIDE_USUAL_HOURS,
            persona[0],
            persona[1],
            bucket.isoformat(),
            f"{count} events at UTC hour {bucket.hour}",
            count,
        )
        for (persona, bucket), count in sorted(buckets.items(), key=lambda item: (item[0][1], item[0][0][0]))
    ]


def render_detect(result: DetectResult) -> str:
    lines = [
        f"audit: {result.audit_path}",
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
