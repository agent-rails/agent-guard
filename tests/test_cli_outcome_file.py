from __future__ import annotations

import json

import pytest

from agent_guard import cli
from agent_guard.cli import main


def run_with_outcome(tmp_path, *argv: str, trust: bool = True):
    outcome_path = tmp_path / "out" / "outcome.json"
    base = ["run", "--outcome-file", str(outcome_path)]
    if trust:
        base.append("--dev-trust-runtime")
    code = main([*base, "--", *argv])
    outcome = json.loads(outcome_path.read_text()) if outcome_path.exists() else None
    return code, outcome, outcome_path


def test_clean_command_reports_completed_with_status_zero(tmp_path):
    code, outcome, _ = run_with_outcome(tmp_path, "echo hi")
    assert code == 0
    assert outcome == {"outcome": "completed", "exit_code": 0, "reason": None}


@pytest.mark.parametrize("status", [2, 3])
def test_command_exiting_with_a_guard_code_is_distinguishable_from_a_verdict(tmp_path, status):
    code, outcome, _ = run_with_outcome(tmp_path, f"exit {status}")
    assert code == status
    assert outcome == {"outcome": "completed", "exit_code": status, "reason": None}


def test_policy_block_reports_blocked_with_no_command_status(tmp_path):
    code, outcome, _ = run_with_outcome(tmp_path, "rm -rf /tmp/x")
    assert code == 3
    assert outcome["outcome"] == "blocked"
    assert outcome["exit_code"] is None
    assert "recursive force delete blocked" in outcome["reason"]


def test_untrusted_runtime_reports_refused_with_no_command_status(tmp_path):
    code, outcome, _ = run_with_outcome(tmp_path, "echo hi", trust=False)
    assert code == 2
    assert outcome["outcome"] == "refused"
    assert outcome["exit_code"] is None


def test_empty_command_reports_usage_error(tmp_path):
    outcome_path = tmp_path / "outcome.json"
    assert main(["run", "--outcome-file", str(outcome_path), "--dev-trust-runtime", "--"]) == 1
    assert json.loads(outcome_path.read_text())["outcome"] == "usage_error"


def test_signal_death_reports_the_shell_convention_status(tmp_path):
    code, outcome, _ = run_with_outcome(tmp_path, "kill -9 $$")
    assert code == 137
    assert outcome == {"outcome": "completed", "exit_code": 137, "reason": None}


def test_stale_outcome_from_a_previous_run_is_replaced(tmp_path):
    outcome_path = tmp_path / "outcome.json"
    outcome_path.write_text(json.dumps({"outcome": "completed", "exit_code": 0, "reason": None}))
    assert main(["run", "--outcome-file", str(outcome_path), "--", "echo hi"]) == 2
    assert json.loads(outcome_path.read_text())["outcome"] == "refused"


def test_internal_failure_leaves_no_outcome_file_so_a_stale_verdict_cannot_be_read(tmp_path, monkeypatch):
    outcome_path = tmp_path / "outcome.json"
    outcome_path.write_text(json.dumps({"outcome": "completed", "exit_code": 0, "reason": None}))

    def explode(path):
        raise RuntimeError("policy loader bug")

    monkeypatch.setattr(cli, "load_policy", explode)
    with pytest.raises(RuntimeError, match="policy loader bug"):
        main(["run", "--outcome-file", str(outcome_path), "--dev-trust-runtime", "--policy", "x.yaml", "--", "echo hi"])
    assert not outcome_path.exists()


def test_outcome_write_leaves_no_staging_file(tmp_path):
    _, _, outcome_path = run_with_outcome(tmp_path, "echo hi")
    assert [p.name for p in outcome_path.parent.iterdir()] == ["outcome.json"]


def test_without_the_flag_no_file_is_written_and_exit_codes_are_unchanged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["run", "--dev-trust-runtime", "--", "exit 3"]) == 3
    assert list(tmp_path.iterdir()) == []
