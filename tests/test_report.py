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
