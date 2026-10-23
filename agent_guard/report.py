from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .claude_code import SELFTEST_AGENT_ID

TOP_RULES = 5
TOP_SESSIONS = 10
FLAGGED_DECISIONS = ("deny", "require_human")
FLAGGED_EXCERPT_CHARS = 160


@dataclass(frozen=True)
class Summary:
    path: str
    exists: bool
    events: int
    selftest_events: int
    faults: int
    unreadable_lines: int
    decisions: Counter
    outcomes: Counter
    would_deny: int
    would_ask: int
    top_rules: list[tuple[str, int]]
    first: str | None
    last: str | None
    sessions: Counter


def read_audit(path: Path) -> tuple[list[dict], int]:
    if not path.exists():
        return [], 0
    records: list[dict] = []
    unreadable = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if _is_valid_row(record):
            records.append(record)
        else:
            unreadable += 1
    return records, unreadable


def _is_valid_row(record: object) -> bool:
    if not isinstance(record, dict) or not isinstance(record.get("ts"), str):
        return False
    try:
        stamp = datetime.fromisoformat(record["ts"])
    except ValueError:
        return False
    return stamp.tzinfo is not None


def _printable(value: object) -> str:
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in str(value))


def summarize(path: Path, records: list[dict], unreadable: int) -> Summary:
    decisions: Counter = Counter()
    outcomes: Counter = Counter()
    rules: Counter = Counter()
    sessions: Counter = Counter()
    timestamps: list[str] = []
    faults = selftest = would_deny = would_ask = events = 0
    for record in records:
        if record.get("agent_id") == SELFTEST_AGENT_ID:
            selftest += 1
            continue
        timestamps.append(record["ts"])
        if record.get("event") == "fault":
            faults += 1
            continue
        events += 1
        decision = record.get("decision")
        outcome = record.get("outcome")
        decisions[decision] += 1
        outcomes[outcome] += 1
        sessions[record.get("agent_id")] += 1
        if decision != "allow" and record.get("rule_id"):
            rules[record["rule_id"]] += 1
        if outcome == "observed":
            would_deny += decision == "deny"
            would_ask += decision == "require_human"
    return Summary(
        path=str(path),
        exists=path.exists(),
        events=events,
        selftest_events=selftest,
        faults=faults,
        unreadable_lines=unreadable,
        decisions=decisions,
        outcomes=outcomes,
        would_deny=would_deny,
        would_ask=would_ask,
        top_rules=rules.most_common(TOP_RULES),
        first=min(timestamps) if timestamps else None,
        last=max(timestamps) if timestamps else None,
        sessions=sessions,
    )


def is_firing(summary: Summary) -> bool:
    return summary.events + summary.faults > 0


def _status(summary: Summary) -> str:
    if not is_firing(summary):
        where = f"no audit file at {summary.path}" if not summary.exists else "the audit file has no checked calls"
        return f"NOT FIRING: {where}; the hook is not installed, is disabled, or never ran"
    if summary.events == 0:
        return f"FIRING, FAULTING: {summary.faults} faults and no checked calls; enforce mode blocks every matched call"
    flagged = summary.decisions["deny"] + summary.decisions["require_human"] + summary.faults
    if flagged == 0:
        return f"FIRING, CLEAN: {summary.events} calls checked, none denied, gated or faulted"
    return f"FIRING: {summary.events} calls checked, {flagged} denied, gated or faulted"


def _age(last: str, now: datetime) -> str:
    seconds = int((now - datetime.fromisoformat(last)).total_seconds())
    if seconds < 120:
        return f"{max(seconds, 0)}s ago"
    if seconds < 7200:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def render_report(summary: Summary, now: datetime, warnings: list[str]) -> str:
    lines = [f"audit: {_printable(summary.path)}", _printable(_status(summary))]
    lines += [f"WARNING: {_printable(warning)}" for warning in warnings]
    if summary.first and summary.last:
        lines.append(f"first event: {summary.first}")
        lines.append(f"last event: {summary.last} ({_age(summary.last, now)})")
    if summary.events:
        lines.append(
            f"checked: {summary.events}  allowed: {summary.decisions['allow']}  "
            f"denied: {summary.decisions['deny']}  asked: {summary.decisions['require_human']}"
        )
        lines.append(
            f"enforced: blocked {summary.outcomes['blocked']}, asked {summary.outcomes['ask']}, "
            f"deferred {summary.outcomes['deferred']}"
        )
        lines.append(f"observed (would have): blocked {summary.would_deny}, asked {summary.would_ask}")
        if summary.top_rules:
            lines.append(
                "top rules: " + ", ".join(f"{_printable(rule)} ({count})" for rule, count in summary.top_rules)
            )
        lines.append(f"sessions: {len(summary.sessions)}")
        lines += [f"  {_printable(agent)}: {count}" for agent, count in summary.sessions.most_common(TOP_SESSIONS)]
    lines.append(f"faults: {summary.faults}")
    if summary.selftest_events:
        lines.append(f"self-test events (excluded): {summary.selftest_events}")
    if summary.unreadable_lines:
        lines.append(f"unreadable audit lines: {summary.unreadable_lines}")
    lines.append("observe data does not predict enforce behaviour: a denied agent may rephrase")
    return "\n".join(lines)


def flagged_rows(records: list[dict]) -> list[dict]:
    rows = [
        record
        for record in records
        if record.get("event") == "decision"
        and record.get("agent_id") != SELFTEST_AGENT_ID
        and record.get("decision") in FLAGGED_DECISIONS
    ]
    return sorted(rows, key=lambda record: datetime.fromisoformat(record["ts"]))


def _flagged_line(record: dict) -> str:
    fields = [
        record["ts"],
        record["agent_id"],
        record["decision"],
        record["outcome"],
        f"cmd_len={record['args']['cmd_len']}",
        record["args"]["cmd"][:FLAGGED_EXCERPT_CHARS],
    ]
    return "  " + "  ".join(_printable(field) for field in fields)


def render_flagged(rows: list[dict]) -> str:
    if not rows:
        return "flagged calls: none"
    groups: dict[str, list[dict]] = {}
    for record in rows:
        groups.setdefault(record.get("rule_id") or "policy default", []).append(record)
    lines = [f"flagged calls: {len(rows)}"]
    for rule, members in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        lines.append(f"{_printable(rule)} ({len(members)})")
        lines += [_flagged_line(record) for record in members]
    return "\n".join(lines)
