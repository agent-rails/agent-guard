from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .claude_code import SELFTEST_AGENT_ID, _digest
from .decision import Decision
from .policy import Policy, load_policy
from .report import FLAGGED_EXCERPT_CHARS, _printable, read_audit

DECISION_VALUES = frozenset(decision.value for decision in Decision)


class ReplayError(Exception):
    pass


@dataclass(frozen=True)
class Outcome:
    decision: str
    rule_id: str | None


@dataclass(frozen=True)
class Change:
    record: dict
    before: Outcome
    after: Outcome


@dataclass(frozen=True)
class ReplayResult:
    replayed: int
    selftest: int
    faults: int
    unreadable: int
    skipped: int
    stored_differs: int
    changes: list[Change]


def load_replay_policy(path: Path) -> Policy:
    try:
        policy = load_policy(path)
    except Exception as err:
        raise ReplayError(f"policy {path} failed to load: {type(err).__name__}: {err}") from err
    if any(rule.judge for rule in policy.rules):
        raise ReplayError(f"policy {path} has a judge rule; static replay cannot run the judge")
    return policy


def read_replay_audit(path: Path) -> tuple[list[dict], int]:
    if not path.exists():
        raise ReplayError(f"no audit file at {path}")
    try:
        return read_audit(path)
    except (OSError, UnicodeDecodeError) as err:
        raise ReplayError(f"audit file {path} is unreadable: {type(err).__name__}: {err}") from err


def _stored_command(record: dict, logged_baseline: bool) -> str | None:
    args = record.get("args")
    if not isinstance(args, dict) or not isinstance(args.get("cmd"), str):
        return None
    if not isinstance(args.get("cmd_sha256"), str) or not _is_utf8(args["cmd"]):
        return None
    if logged_baseline and record.get("decision") not in DECISION_VALUES:
        return None
    return args["cmd"]


def _is_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _evaluate(policy: Policy, command: str) -> Outcome:
    verdict = policy.evaluate("shell", {"cmd": command})
    return Outcome(verdict.decision.value, verdict.rule_id)


def _logged(record: dict) -> Outcome:
    rule_id = record.get("rule_id")
    return Outcome(record["decision"], rule_id if isinstance(rule_id, str) else None)


def replay_rows(records: list[dict], unreadable: int, candidate: Policy, baseline: Policy | None) -> ReplayResult:
    selftest = faults = skipped = stored_differs = replayed = 0
    changes: list[Change] = []
    for record in records:
        if record.get("agent_id") == SELFTEST_AGENT_ID:
            selftest += 1
            continue
        if record.get("event") == "fault":
            faults += 1
            continue
        command = _stored_command(record, baseline is None) if record.get("event") == "decision" else None
        if command is None:
            skipped += 1
            continue
        replayed += 1
        stored_differs += _digest(command) != record["args"]["cmd_sha256"]
        before = _logged(record) if baseline is None else _evaluate(baseline, command)
        after = _evaluate(candidate, command)
        if before.decision != after.decision:
            changes.append(Change(record, before, after))
    if replayed == 0:
        raise ReplayError("no decision rows to replay")
    return ReplayResult(replayed, selftest, faults, unreadable, skipped, stored_differs, changes)


def _rule(outcome: Outcome) -> str:
    return outcome.rule_id or "policy default"


def _change_line(change: Change) -> str:
    fields = [
        change.record["ts"],
        change.record.get("agent_id"),
        f"{_rule(change.before)} -> {_rule(change.after)}",
        change.record["args"]["cmd"][:FLAGGED_EXCERPT_CHARS],
    ]
    return "  " + "  ".join(_printable(field) for field in fields)


def _change_groups(changes: list[Change]) -> list[str]:
    groups: dict[str, list[Change]] = {}
    for change in changes:
        groups.setdefault(f"{change.before.decision} -> {change.after.decision}", []).append(change)
    lines: list[str] = []
    for name, members in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        lines.append(f"{name} ({len(members)})")
        ordered = sorted(members, key=lambda change: datetime.fromisoformat(change.record["ts"]))
        lines += [_change_line(change) for change in ordered]
    return lines


def render_replay(audit: Path, candidate: Path, baseline: Path | None, result: ReplayResult) -> str:
    baseline_label = str(baseline) if baseline else "logged decisions (mixes every policy live during the log)"
    lines = [
        f"audit: {_printable(audit)}",
        f"candidate: {_printable(candidate)}",
        f"baseline: {_printable(baseline_label)}",
        f"replayed: {result.replayed}  self-test excluded: {result.selftest}  faults excluded: {result.faults}  "
        f"unreadable: {result.unreadable}  skipped: {result.skipped}",
        f"stored text differs from the original command (redacted or truncated): {result.stored_differs}",
        f"changed: {len(result.changes)}",
    ]
    lines += _change_groups(result.changes)
    lines.append("result: OK")
    return "\n".join(lines)
