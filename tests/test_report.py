from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_guard import report
from agent_guard.claude_code import SELFTEST_SESSION, HookOptions, run_hook
from agent_guard.cli import main

POLICY = {
    "default": "allow",
    "rules": [
        {
            "id": "block-rm-rf",
            "decision": "deny",
            "tools": ["shell"],
            "arg_patterns": [r"\brm\s+-rf\b"],
            "reason": "recursive force delete blocked",
        },
        {
            "id": "gate-force-push",
            "decision": "require_human",
            "tools": ["shell"],
            "arg_patterns": [r"git\s+push\b.*--force"],
            "reason": "force-push rewrites shared history",
        },
    ],
}


@pytest.fixture
def policy(tmp_path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY))
    return path


@pytest.fixture
def audit(tmp_path) -> Path:
    return tmp_path / "state" / "audit.jsonl"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)
    return home


def hook(policy: Path, audit: Path, command, mode="enforce", session="sess-a", tool_use_id="toolu_1") -> int:
    payload = {
        "session_id": session,
        "hook_event_name": "PreToolUse",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": tool_use_id,
    }
    raw = json.dumps(payload).encode()
    return run_hook(io.BytesIO(raw), HookOptions(str(policy), str(audit), mode)).exit_code


def summary_of(audit: Path) -> report.Summary:
    records, unreadable = report.read_audit(audit)
    return report.summarize(audit, records, unreadable)


def render(audit: Path, now: datetime | None = None, warnings=()) -> list[str]:
    moment = now or datetime.now(timezone.utc)
    return report.render_report(summary_of(audit), moment, list(warnings)).splitlines()


def test_missing_audit_file_is_not_firing_and_the_cli_exits_one(audit, capsys):
    assert main(["report", "--audit", str(audit)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[1] == f"NOT FIRING: no audit file at {audit}; the hook is not installed, is disabled, or never ran"


def test_self_test_rows_alone_do_not_count_as_firing(policy, audit):
    hook(policy, audit, "echo hi", session=SELFTEST_SESSION, tool_use_id="selftest-benign")
    hook(policy, audit, "rm -rf /tmp/x", session=SELFTEST_SESSION, tool_use_id="selftest-canary")
    hook(policy, audit, None, session=SELFTEST_SESSION, tool_use_id="selftest-fault")
    summary = summary_of(audit)
    assert not report.is_firing(summary)
    lines = render(audit)
    assert lines[1].startswith("NOT FIRING: the audit file has no checked calls")
    assert "self-test events (excluded): 3" in lines
    assert "faults: 0" in lines


def test_a_hook_that_faults_on_every_call_is_firing_and_faulting_not_silent(tmp_path, audit, capsys):
    assert hook(tmp_path / "deleted-policy.json", audit, "echo hi") == 2
    assert hook(tmp_path / "deleted-policy.json", audit, "ls", tool_use_id="toolu_2") == 2
    lines = render(audit)
    assert lines[1] == "FIRING, FAULTING: 2 faults and no checked calls; enforce mode blocks every matched call"
    assert lines[2].startswith("first event: ")
    assert "faults: 2" in lines
    assert main(["report", "--audit", str(audit)]) == 0
    capsys.readouterr()


def test_clean_traffic_is_firing_clean_with_per_session_counts(policy, audit):
    hook(policy, audit, "echo one", session="sess-a")
    hook(policy, audit, "echo two", session="sess-a", tool_use_id="toolu_2")
    hook(policy, audit, "echo three", session="sess-b", tool_use_id="toolu_3")
    lines = render(audit)
    assert lines[1] == "FIRING, CLEAN: 3 calls checked, none denied, gated or faulted"
    assert "sessions: 2" in lines
    assert "  claude-code:sess-a: 2" in lines
    assert "  claude-code:sess-b: 1" in lines


def test_enforced_and_observed_outcomes_are_counted_separately(policy, audit):
    hook(policy, audit, "rm -rf /tmp/x")
    hook(policy, audit, "git push --force", tool_use_id="toolu_2")
    hook(policy, audit, "echo hi", tool_use_id="toolu_3")
    hook(policy, audit, "rm -rf /tmp/y", mode="observe", tool_use_id="toolu_4")
    hook(policy, audit, "git push origin --force", mode="observe", tool_use_id="toolu_5")
    lines = render(audit)
    assert lines[1] == "FIRING: 5 calls checked, 4 denied, gated or faulted"
    assert "checked: 5  allowed: 1  denied: 2  asked: 2" in lines
    assert "enforced: blocked 1, asked 1, deferred 1" in lines
    assert "observed (would have): blocked 1, asked 1" in lines
    assert "top rules: block-rm-rf (2), gate-force-push (2)" in lines


def test_last_event_age_is_measured_in_utc(policy, audit):
    hook(policy, audit, "echo hi")
    last = summary_of(audit).last
    later = datetime.fromisoformat(last) + timedelta(hours=3)
    assert f"last event: {last} (3h ago)" in render(audit, now=later)


def test_unreadable_lines_are_counted_not_fatal(policy, audit):
    hook(policy, audit, "echo hi")
    with audit.open("a", encoding="utf-8") as handle:
        handle.write("{torn line\n[]\n")
    assert "unreadable audit lines: 2" in render(audit)


def test_rows_with_a_bad_schema_are_counted_unreadable_not_fatal(policy, audit, capsys):
    hook(policy, audit, "echo hi")
    bad_rows = [
        {"agent_id": "claude-code:x", "decision": "allow"},
        {"ts": 5, "agent_id": "claude-code:x", "decision": "allow"},
        {"ts": "yesterday", "agent_id": "claude-code:x", "decision": "allow"},
        {"ts": "2026-10-15T10:00:00", "agent_id": "claude-code:x", "decision": "allow"},
        ["not", "a", "dict"],
    ]
    with audit.open("a", encoding="utf-8") as handle:
        for row in bad_rows:
            handle.write(json.dumps(row) + "\n")
    lines = render(audit)
    assert lines[1] == "FIRING, CLEAN: 1 calls checked, none denied, gated or faulted"
    assert "unreadable audit lines: 5" in lines
    assert main(["report", "--audit", str(audit)]) == 0
    capsys.readouterr()


def test_control_characters_in_audit_text_are_escaped_when_printed(audit):
    audit.parent.mkdir(parents=True)
    hostile = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": "claude-code:\x1b[31mEVIL\x07",
        "decision": "deny",
        "rule_id": "rule\x1b]0;title\x07",
        "outcome": "blocked",
    }
    audit.write_text(json.dumps(hostile) + "\n")
    text = report.render_report(summary_of(audit), datetime.now(timezone.utc), ["warn\x1b[2J"])
    assert "\x1b" not in text
    assert "\x07" not in text
    assert "claude-code:\\x1b[31mEVIL\\x07" in text
    assert "rule\\x1b]0;title\\x07 (1)" in text
    assert "WARNING: warn\\x1b[2J" in text


def test_cli_report_warns_when_hooks_are_disabled_in_the_project(policy, audit, tmp_path, capsys):
    hook(policy, audit, "echo hi")
    local = tmp_path / "project" / ".claude" / "settings.local.json"
    local.parent.mkdir()
    local.write_text(json.dumps({"disableAllHooks": True}))
    assert main(["report", "--audit", str(audit)]) == 0
    warnings = [line for line in capsys.readouterr().out.splitlines() if line.startswith("WARNING: ")]
    assert len(warnings) == 1
    assert warnings[0].startswith("WARNING: disableAllHooks is true in ")
    assert warnings[0].endswith("/project/.claude/settings.local.json: the hook will not run")


def test_report_always_states_that_observe_data_does_not_predict_enforce(audit):
    assert render(audit)[-1] == "observe data does not predict enforce behaviour: a denied agent may rephrase"


FROZEN_NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN_NOW


def flagged_lines(audit: Path) -> list[str]:
    records, _unreadable = report.read_audit(audit)
    return report.render_flagged(*report.flagged_rows(records)).splitlines()


def flagged_row(ts: str, rule_id: str | None = "r", decision: str = "deny", cmd: str = "c", **overrides) -> dict:
    row = {
        "ts": ts,
        "agent_id": "claude-code:s1",
        "event": "decision",
        "decision": decision,
        "rule_id": rule_id,
        "outcome": "observed",
        "args": {"cmd": cmd, "cmd_len": len(cmd)},
    }
    row.update(overrides)
    return row


def write_rows(audit: Path, rows: list[dict]) -> None:
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text("".join(json.dumps(row) + "\n" for row in rows))


def row_line(record: dict) -> str:
    return (
        f"  {record['ts']}  {record['agent_id']}  {record['decision']}  {record['outcome']}  "
        f"cmd_len={record['args']['cmd_len']}  {record['args']['cmd']}"
    )


def audit_rows(audit: Path) -> list[dict]:
    return report.read_audit(audit)[0]


def test_flagged_lists_would_deny_and_would_ask_grouped_by_rule(policy, audit, tmp_path):
    hook(policy, audit, "rm -rf /tmp/x", mode="observe")
    hook(policy, audit, "echo hi", mode="observe", tool_use_id="toolu_2")
    hook(policy, audit, "git push --force", mode="observe", session="sess-b", tool_use_id="toolu_3")
    hook(policy, audit, "rm -rf /tmp/y", mode="observe", tool_use_id="toolu_4")
    deny_all = tmp_path / "deny-all.json"
    deny_all.write_text(json.dumps({"default": "deny", "rules": []}))
    hook(deny_all, audit, "ls", mode="observe", tool_use_id="toolu_5")
    rm_x, _echo, push, rm_y, ls = audit_rows(audit)
    assert flagged_lines(audit) == [
        "flagged calls: 4",
        "block-rm-rf (2)",
        row_line(rm_x),
        row_line(rm_y),
        "gate-force-push (1)",
        row_line(push),
        "policy default (1)",
        row_line(ls),
    ]


def test_flagged_excludes_selftest_allow_and_fault_rows(policy, audit, tmp_path):
    hook(policy, audit, "rm -rf /tmp/canary", session=SELFTEST_SESSION, tool_use_id="selftest-canary")
    hook(policy, audit, "echo hi", tool_use_id="toolu_2")
    hook(tmp_path / "missing-policy.json", audit, "rm -rf /tmp/x", tool_use_id="toolu_3")
    hook(policy, audit, None, tool_use_id="toolu_4")
    rows = audit_rows(audit)
    assert [row.get("event") for row in rows] == ["decision", "decision", "fault", "fault"]
    assert [row.get("decision") for row in rows[2:]] == ["deny", "deny"]
    assert flagged_lines(audit) == ["flagged calls: none"]


def test_flagged_includes_enforced_blocked_and_ask_outcomes(policy, audit):
    hook(policy, audit, "rm -rf /tmp/x")
    hook(policy, audit, "git push --force", tool_use_id="toolu_2")
    hook(policy, audit, "rm -rf /tmp/y", mode="observe", tool_use_id="toolu_3")
    blocked, asked, observed = audit_rows(audit)
    assert [blocked["outcome"], asked["outcome"], observed["outcome"]] == ["blocked", "ask", "observed"]
    assert flagged_lines(audit) == [
        "flagged calls: 3",
        "block-rm-rf (2)",
        row_line(blocked),
        row_line(observed),
        "gate-force-push (1)",
        row_line(asked),
    ]


def test_flagged_escapes_control_characters_and_truncates_to_160_chars(policy, audit):
    prefix = "rm -rf /tmp/\x1b[31mred\x07/"
    command = prefix + "a" * 300
    hook(policy, audit, command, mode="observe")
    lines = flagged_lines(audit)
    text = "\n".join(lines)
    assert "\x1b" not in text
    assert "\x07" not in text
    excerpt = "rm -rf /tmp/\\x1b[31mred\\x07/" + "a" * (160 - len(prefix))
    assert lines[2].endswith(f"cmd_len={len(command)}  {excerpt}")
    assert not lines[2].endswith("a" * (161 - len(prefix)))


def test_flagged_with_no_rows_prints_none(policy, audit, capsys):
    assert flagged_lines(audit) == ["flagged calls: none"]
    hook(policy, audit, "echo hi")
    assert flagged_lines(audit) == ["flagged calls: none"]
    assert main(["report", "--audit", str(audit), "--flagged"]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "flagged calls: none"


def test_report_without_flagged_flag_is_unchanged(policy, audit, capsys, monkeypatch):
    monkeypatch.setattr("agent_guard.cli.datetime", FrozenDatetime)
    audit.parent.mkdir(parents=True)
    rows = [
        {
            "ts": "2026-10-23T09:00:00+00:00",
            "agent_id": "claude-code:s1",
            "event": "decision",
            "decision": "deny",
            "rule_id": "block-rm-rf",
            "outcome": "observed",
            "args": {"cmd": "rm -rf /tmp/x", "cmd_len": 13},
        },
        {
            "ts": "2026-10-23T10:00:00+00:00",
            "agent_id": "claude-code:s1",
            "event": "decision",
            "decision": "allow",
            "rule_id": None,
            "outcome": "observed",
            "args": {"cmd": "echo hi", "cmd_len": 7},
        },
    ]
    audit.write_text("".join(json.dumps(row) + "\n" for row in rows))
    expected = [
        f"audit: {audit}",
        "FIRING: 2 calls checked, 1 denied, gated or faulted",
        "first event: 2026-10-23T09:00:00+00:00",
        "last event: 2026-10-23T10:00:00+00:00 (2h ago)",
        "checked: 2  allowed: 1  denied: 1  asked: 0",
        "enforced: blocked 0, asked 0, deferred 0",
        "observed (would have): blocked 1, asked 0",
        "top rules: block-rm-rf (1)",
        "sessions: 1",
        "  claude-code:s1: 2",
        "faults: 0",
        "observe data does not predict enforce behaviour: a denied agent may rephrase",
    ]
    assert main(["report", "--audit", str(audit)]) == 0
    plain = capsys.readouterr().out
    assert plain == "\n".join(expected) + "\n"
    assert main(["report", "--audit", str(audit), "--flagged"]) == 0
    assert capsys.readouterr().out == plain + "flagged calls: 1\nblock-rm-rf (1)\n" + (
        "  2026-10-23T09:00:00+00:00  claude-code:s1  deny  observed  cmd_len=13  rm -rf /tmp/x\n"
    )


MALFORMED_OVERRIDES = [
    pytest.param({"args": None}, id="args-null"),
    pytest.param({"args": "x"}, id="args-string"),
    pytest.param({"args": {"cmd_len": 1}}, id="cmd-missing"),
    pytest.param({"args": {"cmd": "c"}}, id="cmd-len-missing"),
    pytest.param({"args": {"cmd": 5, "cmd_len": 1}}, id="cmd-int"),
    pytest.param({"args": {"cmd": None, "cmd_len": 1}}, id="cmd-null"),
    pytest.param({"args": {"cmd": ["x"], "cmd_len": 1}}, id="cmd-list"),
    pytest.param({"args": {"cmd": "c", "cmd_len": "1"}}, id="cmd-len-string"),
    pytest.param({"agent_id": None}, id="agent-id-null"),
    pytest.param({"outcome": 3}, id="outcome-int"),
    pytest.param({"rule_id": 5}, id="rule-id-int"),
    pytest.param({"rule_id": ""}, id="rule-id-empty"),
]


@pytest.mark.parametrize("overrides", MALFORMED_OVERRIDES)
def test_flagged_skips_and_counts_rows_with_missing_or_malformed_fields(audit, capsys, overrides):
    good = flagged_row("2026-10-23T09:00:00+00:00", rule_id="good", cmd="rm -rf /tmp/x")
    bad = flagged_row("2026-10-23T09:01:00+00:00", **overrides)
    if "agent_id" not in overrides:
        bad["agent_id"] = "claude-code:s2"
    write_rows(audit, [good, bad])
    assert main(["report", "--audit", str(audit), "--flagged"]) == 0
    assert capsys.readouterr().out.splitlines()[-4:] == [
        "flagged calls: 1",
        "good (1)",
        row_line(good),
        "flagged rows skipped (missing or malformed fields): 1",
    ]


def test_flagged_with_only_malformed_rows_prints_none_and_the_skip_count(audit):
    write_rows(
        audit,
        [flagged_row("2026-10-23T09:00:00+00:00", args=None), flagged_row("2026-10-23T09:01:00+00:00", args=None)],
    )
    assert flagged_lines(audit) == [
        "flagged calls: none",
        "flagged rows skipped (missing or malformed fields): 2",
    ]


def test_flagged_orders_rows_by_instant_and_groups_by_size_then_name(audit):
    later_offset = flagged_row("2026-10-23T10:00:00+00:00", rule_id="z-rule", cmd="later")
    earlier_offset = flagged_row("2026-10-23T09:30:00+01:00", rule_id="z-rule", cmd="earlier")
    small = flagged_row("2026-10-23T08:00:00+00:00", rule_id="a-rule", cmd="small")
    tie_b = flagged_row("2026-10-23T08:10:00+00:00", rule_id="b-tie", cmd="tie-b")
    tie_a = flagged_row("2026-10-23T08:20:00+00:00", rule_id="a-tie", cmd="tie-a")
    write_rows(audit, [later_offset, tie_b, small, earlier_offset, tie_a])
    assert flagged_lines(audit) == [
        "flagged calls: 5",
        "z-rule (2)",
        row_line(earlier_offset),
        row_line(later_offset),
        "a-rule (1)",
        row_line(small),
        "a-tie (1)",
        row_line(tie_a),
        "b-tie (1)",
        row_line(tie_b),
    ]
