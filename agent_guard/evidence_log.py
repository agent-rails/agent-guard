from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

KNOWN_EVENTS = (None, "decision", "release", "terminal", "fault")


class EvidenceError(Exception):
    pass


@dataclass(frozen=True)
class Row:
    ts: datetime
    data: dict
    actor: str
    tenant_id: str | None


def to_utc(stamp: datetime) -> datetime | None:
    """UTC form of a timezone-aware datetime, or None when it is naive or cannot be represented."""
    if stamp.tzinfo is None:
        return None
    try:
        return stamp.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def parse_stamp(text: object) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    return to_utc(stamp)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def row_identity(data: dict) -> tuple[str, str | None] | None:
    actor = _text(data.get("actor")) or _text(data.get("agent_id"))
    tenant = data.get("tenant_id")
    if actor is None or not isinstance(data.get("tool"), str) or (tenant is not None and not _text(tenant)):
        return None
    return actor, tenant


def parse_row(line: str) -> Row | None:
    try:
        data = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    stamp = parse_stamp(data.get("ts"))
    identity = row_identity(data)
    purpose = data.get("purpose")
    if stamp is None or identity is None or data.get("event") not in KNOWN_EVENTS:
        return None
    if purpose is not None and not _text(purpose):
        return None
    return Row(stamp, data, identity[0], identity[1])


class EvidenceLog:
    """Streams an audit JSONL file one line at a time. Lines that are not valid rows are counted in `malformed`,
    never skipped silently. The counters are complete only after `rows()` has been exhausted."""

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise EvidenceError(f"audit file {path} does not exist")
        self._path = path
        self.rows_read = 0
        self.malformed = 0

    def rows(self) -> Iterator[Row]:
        with self._path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = parse_row(line)
                if row is None:
                    self.malformed += 1
                    continue
                self.rows_read += 1
                yield row
