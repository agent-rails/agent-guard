from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from agent_guard import AuditRecord, JsonlAuditSink
from agent_guard.cli import main
from agent_guard.detect import (
    DEPTH_SKIPPED,
    FIRST_RESOURCE_USE,
    FIRST_TOOL_USE,
    OUTSIDE_USUAL_HOURS,
    RATE_ABOVE_BASELINE,
    DetectConfig,
    DetectError,
    detect_file,
    parse_usual_hours,
)

EVALUATE_FROM = datetime(2026, 11, 2, 0, 0, tzinfo=timezone.utc)


def _write(path, ts, **overrides):
    base = {
        "ts": ts,
        "agent_id": "agent-1",
        "tool": "deploy",
        "args": {},
        "decision": "allow",
        "reason": "ok",
        "rule_id": None,
        "executed": True,
        "event": "release",
        "tenant_id": "t1",
        "actor": "bot",
    }
    JsonlAuditSink(path).write(AuditRecord(**{**base, **overrides}))


def _kinds(result):
    return [alert.kind for alert in result.alerts]


@pytest.fixture
def audit(tmp_path):
    path = tmp_path / "audit.jsonl"
    for hour in range(0, 24):
        _write(path, f"2026-11-01T{hour:02d}:00:00+00:00", args={"resource": "svc/api"})
    return path


def test_no_alerts_when_evaluation_matches_baseline(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert result.alerts == []
    assert result.baseline_rows == 24
    assert result.evaluated_rows == 1


def test_first_use_of_tool_flagged_once(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", tool="delete_prod")
    _write(audit, "2026-11-02T04:00:00+00:00", tool="delete_prod")
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert _kinds(result) == [FIRST_TOOL_USE]
    assert "delete_prod" in result.alerts[0].detail
    assert result.alerts[0].persona == "bot"
    assert result.alerts[0].tenant_id == "t1"


def test_first_use_of_resource_flagged(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", args={"resource": "svc/payments"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert _kinds(result) == [FIRST_RESOURCE_USE]


def test_tool_known_in_other_tenant_is_still_first_use(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", tenant_id="t2", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert sorted(_kinds(result)) == [FIRST_RESOURCE_USE, FIRST_TOOL_USE]


def test_rate_above_baseline_flagged(audit):
    for minute in range(10):
        _write(audit, f"2026-11-02T05:{minute:02d}:00+00:00", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM, rate_multiplier=3.0, min_rate_events=5))
    assert _kinds(result) == [RATE_ABOVE_BASELINE]
    assert result.alerts[0].count == 10
    assert result.alerts[0].ts == "2026-11-02T05:00:00+00:00"


def test_rate_within_multiplier_not_flagged(audit):
    for minute in range(2):
        _write(audit, f"2026-11-02T05:{minute:02d}:00+00:00", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM, min_rate_events=1))
    assert result.alerts == []


def test_rate_multiplier_is_configurable(audit):
    for minute in range(3):
        _write(audit, f"2026-11-02T05:{minute:02d}:00+00:00", args={"resource": "svc/api"})
    strict = DetectConfig(evaluate_from=EVALUATE_FROM, rate_multiplier=2.0, min_rate_events=1)
    loose = DetectConfig(evaluate_from=EVALUATE_FROM, rate_multiplier=5.0, min_rate_events=1)
    assert _kinds(detect_file(audit, strict)) == [RATE_ABOVE_BASELINE]
    assert detect_file(audit, loose).alerts == []


def test_rate_needs_minimum_events(audit):
    for minute in range(4):
        _write(audit, f"2026-11-02T05:{minute:02d}:00+00:00", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM, min_rate_events=5))
    assert result.alerts == []


def test_off_hours_flagged_per_hour_bucket(audit):
    _write(audit, "2026-11-02T03:10:00+00:00", args={"resource": "svc/api"})
    _write(audit, "2026-11-02T03:20:00+00:00", args={"resource": "svc/api"})
    _write(audit, "2026-11-02T10:00:00+00:00", args={"resource": "svc/api"})
    config = DetectConfig(evaluate_from=EVALUATE_FROM, usual_hours=parse_usual_hours("8-18"))
    result = detect_file(audit, config)
    assert _kinds(result) == [OUTSIDE_USUAL_HOURS]
    assert result.alerts[0].count == 2


def test_off_hours_off_by_default(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", args={"resource": "svc/api"})
    assert detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM)).alerts == []


def test_offsets_are_converted_to_utc(audit):
    _write(audit, "2026-11-02T10:00:00+07:00", args={"resource": "svc/api"})
    config = DetectConfig(evaluate_from=EVALUATE_FROM, usual_hours=parse_usual_hours("8-18"))
    result = detect_file(audit, config)
    assert _kinds(result) == [OUTSIDE_USUAL_HOURS]
    assert result.alerts[0].ts == "2026-11-02T03:00:00+00:00"


def test_purpose_defines_persona_over_actor(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, "2026-11-01T01:00:00+00:00", actor="bot-1", purpose="deployer", tool="deploy")
    _write(path, "2026-11-02T01:00:00+00:00", actor="bot-2", purpose="deployer", tool="deploy")
    _write(path, "2026-11-02T02:00:00+00:00", actor="bot-2", purpose="reader", tool="deploy")
    result = detect_file(path, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert [(alert.persona, alert.kind) for alert in result.alerts] == [("reader", FIRST_TOOL_USE)]


def test_persona_falls_back_to_agent_id(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, "2026-11-01T01:00:00+00:00", actor=None, tenant_id=None)
    _write(path, "2026-11-02T01:00:00+00:00", actor=None, tenant_id=None, tool="other")
    result = detect_file(path, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert [(a.persona, a.tenant_id) for a in result.alerts] == [("agent-1", None)]


def test_windows_respect_bounds(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", tool="late", args={"resource": "svc/api"})
    _write(audit, "2026-11-03T03:00:00+00:00", tool="later", args={"resource": "svc/api"})
    config = DetectConfig(evaluate_from=EVALUATE_FROM, evaluate_until=datetime(2026, 11, 3, tzinfo=timezone.utc))
    result = detect_file(audit, config)
    assert [a.detail for a in result.alerts] == ["tool 'late'"]


def test_terminal_and_fault_rows_are_not_evaluated(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", tool="other", event="terminal", outcome="returned")
    assert detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM)).alerts == []


def test_malformed_lines_counted(audit):
    with audit.open("a") as handle:
        handle.write("not json\n")
        handle.write(json.dumps({"ts": "2026-11-02T01:00:00+00:00", "tool": "x"}) + "\n")
        handle.write(json.dumps({"ts": "2026-11-02T01:00:00+00:00", "agent_id": "a", "tool": "x", "purpose": 5}) + "\n")
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert result.malformed == 3


def test_delegation_depth_check_is_reported_skipped(audit):
    assert DEPTH_SKIPPED in detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM)).skipped


def test_missing_audit_raises(tmp_path):
    with pytest.raises(DetectError):
        detect_file(tmp_path / "missing.jsonl", DetectConfig(evaluate_from=EVALUATE_FROM))


@pytest.mark.parametrize("text", ["8", "a-b", "8-8", "25-3", "8-18-20"])
def test_bad_usual_hours_refused(text):
    with pytest.raises(DetectError):
        parse_usual_hours(text)


def test_usual_hours_wrap_midnight():
    assert parse_usual_hours("22-2") == frozenset({22, 23, 0, 1})


def test_naive_timestamp_refused():
    with pytest.raises(DetectError):
        DetectConfig(evaluate_from=datetime(2026, 11, 2))


def test_cli_alerts_exit_3(audit, capsys):
    _write(audit, "2026-11-02T03:00:00+00:00", tool="delete_prod", args={"resource": "svc/api"})
    code = main(["detect", "--audit", str(audit), "--evaluate-from", "2026-11-02T00:00:00+00:00"])
    out = capsys.readouterr().out
    assert code == 3
    assert "[first_tool_use] persona=bot tenant=t1" in out
    assert DEPTH_SKIPPED in out


def test_cli_clean_exit_0(audit, capsys):
    _write(audit, "2026-11-02T03:00:00+00:00", args={"resource": "svc/api"})
    assert main(["detect", "--audit", str(audit), "--evaluate-from", "2026-11-02T00:00:00+00:00"]) == 0
    assert "alerts (0):" in capsys.readouterr().out


def test_cli_malformed_only_exit_4(audit, capsys):
    with audit.open("a") as handle:
        handle.write("nope\n")
    assert main(["detect", "--audit", str(audit), "--evaluate-from", "2026-11-02T00:00:00+00:00"]) == 4
    assert "malformed lines: 1" in capsys.readouterr().out


def test_cli_rejects_naive_timestamp(audit, capsys):
    assert main(["detect", "--audit", str(audit), "--evaluate-from", "2026-11-02T00:00:00"]) == 1
    assert "UTC offset" in capsys.readouterr().err


def test_cli_usual_hours_option(audit, capsys):
    _write(audit, "2026-11-02T03:00:00+00:00", args={"resource": "svc/api"})
    args = ["detect", "--audit", str(audit), "--evaluate-from", "2026-11-02T00:00:00+00:00", "--usual-hours", "8-18"]
    assert main(args) == 3
    assert "outside_usual_hours" in capsys.readouterr().out


def test_guard_does_not_import_detect():
    code = "import sys, agent_guard.guard; sys.exit(1 if 'agent_guard.detect' in sys.modules else 0)"
    assert subprocess.run([sys.executable, "-I", "-c", code], check=False).returncode == 0


def test_alerts_carry_task_roots_from_evidence(audit):
    for minute in range(6):
        _write(
            audit, f"2026-11-02T05:{minute:02d}:00+00:00", task_root=f"root-{minute % 2}", args={"resource": "svc/api"}
        )
    _write(audit, "2026-11-02T07:00:00+00:00", task_root="root-9", tool="delete_prod", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    by_kind = {alert.kind: alert for alert in result.alerts}
    assert by_kind[RATE_ABOVE_BASELINE].task_roots == ("root-0", "root-1")
    assert by_kind[FIRST_TOOL_USE].task_roots == ("root-9",)


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_unconvertible_timestamp_is_malformed_and_alerts_survive(audit, stamp):
    with audit.open("a") as handle:
        handle.write(json.dumps({"ts": stamp, "agent_id": "x", "tool": "t"}) + "\n")
    _write(audit, "2026-11-02T03:00:00+00:00", tool="delete_prod", args={"resource": "svc/api"})
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert result.malformed == 1
    assert _kinds(result) == [FIRST_TOOL_USE]


def test_unknown_event_is_malformed(audit):
    _write(audit, "2026-11-02T03:00:00+00:00", event="relabelled")
    result = detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
    assert result.malformed == 1
    assert result.evaluated_rows == 0


def test_detect_streams_the_log(audit, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("whole-file read")

    monkeypatch.setattr("pathlib.Path.read_text", refuse)
    detect_file(audit, DetectConfig(evaluate_from=EVALUATE_FROM))
