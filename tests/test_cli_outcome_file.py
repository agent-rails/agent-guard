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


def seed_stale_verdict(path):
    path.write_text(json.dumps({"outcome": "completed", "exit_code": 0, "reason": None}))


def test_argument_parse_error_does_not_leave_a_stale_verdict(tmp_path):
    outcome_path = tmp_path / "outcome.json"
    seed_stale_verdict(outcome_path)
    with pytest.raises(SystemExit) as exited:
        main(["run", "--outcome-file", str(outcome_path), "--ttl", "notanint", "--", "true"])
    assert exited.value.code == 2
    assert not outcome_path.exists()


def test_equals_form_is_cleared_before_parsing_too(tmp_path):
    outcome_path = tmp_path / "outcome.json"
    seed_stale_verdict(outcome_path)
    with pytest.raises(SystemExit):
        main(["run", f"--outcome-file={outcome_path}", "--ttl", "notanint", "--", "true"])
    assert not outcome_path.exists()


def test_flag_text_after_the_separator_belongs_to_the_command_and_is_not_cleared(tmp_path):
    untouched = tmp_path / "keep.json"
    seed_stale_verdict(untouched)
    assert main(["run", "--dev-trust-runtime", "--", "echo", "--outcome-file", str(untouched)]) == 0
    assert untouched.exists()


def test_abbreviated_flag_is_not_accepted_so_the_clearing_scan_cannot_be_bypassed(tmp_path):
    with pytest.raises(SystemExit):
        main(["run", "--outcome", str(tmp_path / "o.json"), "--dev-trust-runtime", "--", "true"])


def test_publish_failure_keeps_the_commands_exit_status_and_cleans_up(tmp_path, capsys):
    locked = tmp_path / "locked"
    locked.mkdir()
    outcome_path = locked / "outcome.json"
    try:
        code = main(
            ["run", "--dev-trust-runtime", "--outcome-file", str(outcome_path), "--", f"chmod 555 {locked}; exit 5"]
        )
    finally:
        locked.chmod(0o755)
    assert code == 5
    assert "failed to publish outcome file" in capsys.readouterr().err
    assert list(locked.iterdir()) == []


def test_path_turned_into_a_directory_by_the_command_is_reported_without_leftovers(tmp_path, capsys):
    outcome_path = tmp_path / "outcome.json"
    code = main(
        ["run", "--dev-trust-runtime", "--outcome-file", str(outcome_path), "--", f"mkdir {outcome_path}; exit 5"]
    )
    assert code == 5
    assert "failed to publish outcome file" in capsys.readouterr().err
    assert [p.name for p in tmp_path.iterdir()] == ["outcome.json"]


def test_command_cannot_redirect_the_write_through_a_predictable_staging_name(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("original")
    outcome_path = tmp_path / "outcome.json"
    plant = f"ln -s {victim} {outcome_path}.$PPID.tmp"
    assert main(["run", "--dev-trust-runtime", "--outcome-file", str(outcome_path), "--", plant]) == 0
    assert victim.read_text() == "original"
    assert json.loads(outcome_path.read_text())["outcome"] == "completed"


def test_outcome_file_may_not_be_the_audit_file(tmp_path, capsys):
    shared = tmp_path / "same.json"
    code = main(["run", "--dev-trust-runtime", "--outcome-file", str(shared), "--audit", str(shared), "--", "echo hi"])
    assert code == 1
    assert "must be different files" in capsys.readouterr().err
    assert not shared.exists()


def test_unusable_outcome_path_fails_before_the_command_runs(tmp_path, capsys):
    marker = tmp_path / "ran"
    directory = tmp_path / "outcome.json"
    directory.mkdir()
    code = main(["run", "--dev-trust-runtime", "--outcome-file", str(directory), "--", f"touch {marker}"])
    assert code == 1
    assert "cannot use --outcome-file" in capsys.readouterr().err
    assert not marker.exists()
