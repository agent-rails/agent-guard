from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path

from agentguard_identity.credentials import IssuanceRecord

from .evidence_log import EvidenceError, EvidenceLog

DECISION_EVENTS = (None, "decision", "release")
LIMIT_TEXT = "only agents whose effects passed a guard or credential injector appear here"
ISSUANCE_FIELDS = frozenset(item.name for item in fields(IssuanceRecord))
ISSUANCE_TIMES = ("issued_at", "expires_at")
ISSUANCE_STRINGS = (
    "issuance_id",
    "op_id",
    "tenant_id",
    "task_id",
    "tool",
    "request_digest",
    "executor_key_id",
    "audience",
)


@dataclass
class AgentEntry:
    actor: str
    tenant_id: str | None
    first_seen: datetime
    last_seen: datetime
    tools: set[str] = field(default_factory=set)
    grant_hashes: set[str] = field(default_factory=set)
    decisions: Counter = field(default_factory=Counter)
    without_grant_hash: int = 0


@dataclass
class TenantIssuance:
    tenant_id: str
    issuances: int = 0
    tools: set[str] = field(default_factory=set)
    task_ids: set[str] = field(default_factory=set)
    first_issued: datetime | None = None
    last_issued: datetime | None = None


@dataclass(frozen=True)
class Inventory:
    audit_path: str
    rows: int
    malformed: int
    not_counted: int
    agents: list[AgentEntry]
    issuance_path: str | None = None
    issuance_rows: int = 0
    issuance_malformed: int = 0
    tenants: list[TenantIssuance] = field(default_factory=list)


class InventoryError(Exception):
    pass


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _grant_hash(row: dict) -> str | None:
    value = row.get("grant_hash")
    return value if isinstance(value, str) and value else None


def build_inventory(audit_path: Path, issuance_path: Path | None = None) -> Inventory:
    try:
        log = EvidenceLog(audit_path)
    except EvidenceError as err:
        raise InventoryError(str(err)) from err
    entries: dict[tuple[str, str | None], AgentEntry] = {}
    not_counted = 0
    for item in log.rows():
        row = item.data
        identity = (item.actor, item.tenant_id)
        if row.get("event") not in DECISION_EVENTS:
            not_counted += 1
            continue
        seen = item.ts
        entry = entries.get(identity)
        if entry is None:
            entry = entries[identity] = AgentEntry(identity[0], identity[1], seen, seen)
        entry.first_seen = min(entry.first_seen, seen)
        entry.last_seen = max(entry.last_seen, seen)
        entry.tools.add(row["tool"])
        entry.decisions[str(row.get("decision"))] += 1
        grant_hash = _grant_hash(row)
        if grant_hash is None:
            entry.without_grant_hash += 1
        else:
            entry.grant_hashes.add(grant_hash)
    agents = sorted(entries.values(), key=lambda item: (item.actor, item.tenant_id or ""))
    result = Inventory(str(audit_path), log.rows_read, log.malformed, not_counted, agents)
    if issuance_path is None:
        return result
    tenants, issuance_rows, issuance_malformed = _read_issuance(issuance_path)
    return Inventory(
        result.audit_path,
        result.rows,
        result.malformed,
        result.not_counted,
        agents,
        str(issuance_path),
        issuance_rows,
        issuance_malformed,
        tenants,
    )


def _epoch(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _valid_issuance(row: object) -> datetime | None:
    """The issue time of a well-formed issuance row, or None when the row is malformed."""
    if not isinstance(row, dict) or set(row) != ISSUANCE_FIELDS:
        return None
    if not all(_text(row[name]) for name in ISSUANCE_STRINGS):
        return None
    issued = _epoch(row["issued_at"])
    if issued is None or _epoch(row["expires_at"]) is None:
        return None
    return issued


def _read_issuance(path: Path) -> tuple[list[TenantIssuance], int, int]:
    if not path.exists():
        raise InventoryError(f"issuance file {path} does not exist")
    tenants: dict[str, TenantIssuance] = {}
    rows = malformed = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (ValueError, RecursionError):
                malformed += 1
                continue
            issued = _valid_issuance(row)
            if issued is None:
                malformed += 1
                continue
            rows += 1
            entry = tenants.setdefault(row["tenant_id"], TenantIssuance(row["tenant_id"]))
            entry.issuances += 1
            entry.tools.add(row["tool"])
            entry.task_ids.add(row["task_id"])
            entry.first_issued = issued if entry.first_issued is None else min(entry.first_issued, issued)
            entry.last_issued = issued if entry.last_issued is None else max(entry.last_issued, issued)
    return sorted(tenants.values(), key=lambda item: item.tenant_id), rows, malformed


def _stamp(value: datetime | None) -> str:
    return value.isoformat() if value else "-"


def _joined(values: set[str]) -> str:
    return ", ".join(sorted(values)) if values else "-"


def render_inventory(inventory: Inventory) -> str:
    lines = [
        f"audit: {inventory.audit_path}",
        f"limit: {LIMIT_TEXT}",
        f"rows read: {inventory.rows}",
        f"malformed lines: {inventory.malformed}",
        f"lifecycle rows not counted as decisions (terminal, fault): {inventory.not_counted}",
        f"agents ({len(inventory.agents)}):",
    ]
    for agent in inventory.agents:
        counts = " ".join(f"{name}={count}" for name, count in sorted(agent.decisions.items()))
        lines += [
            f"  actor={agent.actor} tenant={agent.tenant_id or '-'}",
            f"    first seen: {_stamp(agent.first_seen)}",
            f"    last seen: {_stamp(agent.last_seen)}",
            f"    tools: {_joined(agent.tools)}",
            f"    grant_hash: {_joined(agent.grant_hashes)}",
            f"    decisions: {counts}",
            f"    decisions with no grant_hash: {agent.without_grant_hash}",
        ]
    if inventory.issuance_path is None:
        return "\n".join(lines)
    lines += [
        f"issuance: {inventory.issuance_path}",
        f"issuance rows read: {inventory.issuance_rows}",
        f"issuance malformed lines: {inventory.issuance_malformed}",
        f"tenants with issuances ({len(inventory.tenants)}):",
    ]
    for tenant in inventory.tenants:
        lines += [
            f"  tenant={tenant.tenant_id} issuances={tenant.issuances}",
            f"    first issued: {_stamp(tenant.first_issued)}",
            f"    last issued: {_stamp(tenant.last_issued)}",
            f"    tools: {_joined(tenant.tools)}",
            f"    tasks: {_joined(tenant.task_ids)}",
        ]
    return "\n".join(lines)


def is_incomplete(inventory: Inventory) -> bool:
    return inventory.malformed > 0 or inventory.issuance_malformed > 0
