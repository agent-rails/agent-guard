from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

from agent_guard import Decision, Policy
from agent_guard import claude_code_install as installer
from agent_guard.claude_code import SELFTEST_AGENT_ID
from agent_guard.claude_code_install import InstallError
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
        }
    ],
}
NEW_CLAUDE = (2, 1, 295)
OLD_CLAUDE = (2, 1, 284)
FOREIGN_HOOK = {
    "matcher": "Write",
    "hooks": [{"type": "command", "command": "/usr/local/bin/scan-write.sh", "timeout": 5}],
}


@pytest.fixture(autouse=True)
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.chdir(project)
    monkeypatch.setattr(installer, "detect_claude_version", lambda: None)
    return home


@pytest.fixture
def policy(tmp_path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY))
    return path


@pytest.fixture
def audit(tmp_path) -> Path:
    return tmp_path / "state" / "audit.jsonl"


@pytest.fixture
def settings_path(fake_home) -> Path:
    return fake_home / ".claude" / "settings.json"


def do_install(settings_path, hook_python, policy, audit, mode="enforce", scope="user", version=None, visible=()):
    return installer.install(settings_path, hook_python, policy, audit, mode, scope, version, list(visible))


def read(path) -> dict:
    return json.loads(Path(path).read_text())


def our_hooks(settings: dict) -> list[dict]:
    return [
        hook
        for group in settings.get("hooks", {}).get("PreToolUse", [])
        for hook in group["hooks"]
        if installer.is_ours(hook.get("command"))
    ]


def test_build_command_golden_enforce_and_observe():
    enforce = installer.build_command("/opt/venv/bin/python", "/etc/a b/policy.json", "/var/audit.jsonl", "enforce")
    assert enforce == (
        "/opt/venv/bin/python -I -m agent_guard.cli hook claude-code --policy '/etc/a b/policy.json' "
        "--audit /var/audit.jsonl --mode enforce || { [ $? -eq 2 ] || echo 'agent-guard hook failed, command "
        "blocked. Recovery from a terminal: guard install claude-code --check.' >&2; exit 2; }"
    )
    observe = installer.build_command("/opt/venv/bin/python", "/p.json", "/a.jsonl", "observe")
    assert (
        observe == "/opt/venv/bin/python -I -m agent_guard.cli hook claude-code "
        "--policy /p.json --audit /a.jsonl --mode observe"
    )


def test_build_command_rejects_unknown_mode():
    with pytest.raises(InstallError):
        installer.build_command("/p", "/a", "/b", "audit-only")


def test_fresh_install_writes_one_anchored_bash_entry_and_verifies(settings_path, hook_python, policy, audit):
    report = do_install(settings_path, hook_python, policy, audit)
    assert report.ok
    assert report.lines[-1] == "command verified; firing inside Claude Code not verified"
    settings = read(settings_path)
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "^Bash$"
    (hook,) = our_hooks(settings)
    assert hook["type"] == "command"
    assert hook["timeout"] == 10
    assert "onFailure" not in hook
    assert hook["command"].startswith(f"{hook_python} -I -m agent_guard.cli hook claude-code --policy ")
    assert hook["command"].endswith("exit 2; }")
    assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("version", "mode", "expected"),
    [
        (NEW_CLAUDE, "enforce", True),
        ((2, 2, 0), "enforce", True),
        (OLD_CLAUDE, "enforce", False),
        (None, "enforce", False),
        (NEW_CLAUDE, "observe", False),
    ],
)
def test_on_failure_block_only_for_enforce_on_supported_versions(
    settings_path, hook_python, policy, audit, version, mode, expected
):
    do_install(settings_path, hook_python, policy, audit, mode=mode, version=version)
    (hook,) = our_hooks(read(settings_path))
    assert (hook.get("onFailure") == "block") is expected


def test_old_version_report_names_the_timeout_residual(settings_path, hook_python, policy, audit):
    report = do_install(settings_path, hook_python, policy, audit, version=OLD_CLAUDE)
    assert any("hook timeout still lets the command run" in line for line in report.lines)


def test_foreign_settings_and_hooks_are_preserved(settings_path, hook_python, policy, audit):
    settings_path.parent.mkdir(parents=True)
    existing = {
        "permissions": {"allow": ["Bash(ls:*)"]},
        "hooks": {"PreToolUse": [FOREIGN_HOOK], "PostToolUse": [{"matcher": "", "hooks": []}]},
        "model": "opus",
    }
    settings_path.write_text(json.dumps(existing))
    do_install(settings_path, hook_python, policy, audit)
    settings = read(settings_path)
    assert settings["permissions"] == existing["permissions"]
    assert settings["model"] == "opus"
    assert settings["hooks"]["PostToolUse"] == existing["hooks"]["PostToolUse"]
    assert settings["hooks"]["PreToolUse"][0] == FOREIGN_HOOK
    assert len(settings["hooks"]["PreToolUse"]) == 2


def test_reinstall_is_idempotent_and_leaves_one_entry(settings_path, hook_python, policy, audit):
    do_install(settings_path, hook_python, policy, audit)
    first = settings_path.read_bytes()
    do_install(settings_path, hook_python, policy, audit)
    assert settings_path.read_bytes() == first
    assert len(our_hooks(read(settings_path))) == 1


def test_reinstall_with_a_new_mode_replaces_the_entry(settings_path, hook_python, policy, audit):
    do_install(settings_path, hook_python, policy, audit, mode="enforce")
    do_install(settings_path, hook_python, policy, audit, mode="observe")
    (hook,) = our_hooks(read(settings_path))
    assert hook["command"].endswith("--mode observe")


def test_entries_from_another_interpreter_are_replaced_not_duplicated():
    settings = {"hooks": {"PreToolUse": [FOREIGN_HOOK]}}
    old = installer.hook_entry(
        installer.build_command("/old/venv/bin/python", "/p.json", "/a.jsonl", "enforce"), "enforce", None
    )
    new = installer.hook_entry(
        installer.build_command("/new/venv/bin/python", "/p.json", "/a.jsonl", "enforce"), "enforce", None
    )
    replaced = installer.apply_hook(installer.apply_hook(settings, old), new)
    (hook,) = our_hooks(replaced)
    assert hook["command"].startswith("/new/venv/bin/python")
    assert replaced["hooks"]["PreToolUse"][0] == FOREIGN_HOOK


def test_foreign_hook_sharing_our_group_survives_removal():
    shared = {"matcher": "^Bash$", "hooks": [{"type": "command", "command": "other.sh"}]}
    ours = installer.hook_entry(installer.build_command("/py", "/p.json", "/a.jsonl", "enforce"), "enforce", None)
    shared["hooks"].append(ours)
    updated, removed = installer.remove_ours({"hooks": {"PreToolUse": [shared]}})
    assert removed == 1
    assert updated["hooks"]["PreToolUse"] == [
        {"matcher": "^Bash$", "hooks": [{"type": "command", "command": "other.sh"}]}
    ]


def test_symlinked_settings_are_written_through_to_the_target(settings_path, hook_python, policy, audit, tmp_path):
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    real = dotfiles / "settings.json"
    real.write_text(json.dumps({"model": "opus"}))
    settings_path.parent.mkdir(parents=True)
    settings_path.symlink_to(real)
    do_install(settings_path, hook_python, policy, audit)
    assert settings_path.is_symlink()
    assert settings_path.resolve() == real.resolve()
    assert read(real)["model"] == "opus"
    assert len(our_hooks(read(real))) == 1


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        "",
        "[]",
        '"string"',
        json.dumps({"hooks": []}),
        json.dumps({"hooks": {"PreToolUse": {}}}),
        json.dumps({"hooks": {"PreToolUse": ["x"]}}),
        json.dumps({"hooks": {"PreToolUse": [{"hooks": "x"}]}}),
        json.dumps({"hooks": {"PreToolUse": [{"hooks": ["x"]}]}}),
    ],
)
def test_invalid_or_unexpected_settings_are_refused_untouched(settings_path, hook_python, policy, audit, text):
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(text)
    with pytest.raises(InstallError, match="refus"):
        do_install(settings_path, hook_python, policy, audit)
    assert settings_path.read_text() == text
    assert [p.name for p in settings_path.parent.iterdir()] == ["settings.json"]


def test_backup_is_utc_stamped_and_byte_identical(settings_path, hook_python, policy, audit):
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"model":   "opus"}\n')
    report = do_install(settings_path, hook_python, policy, audit)
    (backup,) = [p for p in settings_path.parent.iterdir() if ".agent-guard-backup-" in p.name]
    assert re.fullmatch(r"settings\.json\.agent-guard-backup-\d{8}T\d{12}Z", backup.name)
    assert backup.read_text() == '{"model":   "opus"}\n'
    assert any(str(backup) in line for line in report.lines)


def test_existing_file_mode_is_preserved(settings_path, hook_python, policy, audit):
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text("{}")
    settings_path.chmod(0o640)
    do_install(settings_path, hook_python, policy, audit)
    assert stat.S_IMODE(settings_path.stat().st_mode) == 0o640


def test_modification_between_read_and_replace_aborts_and_keeps_the_other_writers_data(
    settings_path, hook_python, policy, audit, monkeypatch
):
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"model": "opus"}')
    real_copy = installer.shutil.copy2

    def copy_then_tamper(source, destination):
        result = real_copy(source, destination)
        Path(source).write_text('{"model": "sonnet"}')
        return result

    monkeypatch.setattr(installer.shutil, "copy2", copy_then_tamper)
    with pytest.raises(InstallError, match="changed"):
        do_install(settings_path, hook_python, policy, audit)
    assert settings_path.read_text() == '{"model": "sonnet"}'
    assert not [p for p in settings_path.parent.iterdir() if p.name.endswith(".tmp")]


def test_failed_self_test_rolls_back_an_existing_file_byte_for_byte(settings_path, hook_python, tmp_path, audit):
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"model": "opus"}\n')
    blocks_echo = tmp_path / "blocks-echo.json"
    blocks_echo.write_text(
        json.dumps(
            {
                "default": "allow",
                "rules": [{"id": "no-echo", "decision": "deny", "tools": ["shell"], "arg_patterns": ["echo"]}],
            }
        )
    )
    with pytest.raises(InstallError, match="self-test failed, settings rolled back.*benign"):
        do_install(settings_path, hook_python, blocks_echo, audit)
    assert settings_path.read_text() == '{"model": "opus"}\n'


def test_failed_self_test_removes_a_file_the_install_created(settings_path, hook_python, tmp_path, audit):
    blocks_all = tmp_path / "blocks-all.json"
    blocks_all.write_text(json.dumps({"default": "deny"}))
    with pytest.raises(InstallError, match="rolled back"):
        do_install(settings_path, hook_python, blocks_all, audit)
    assert not settings_path.exists()


def test_a_broken_interpreter_fails_the_self_test_and_rolls_back(settings_path, tmp_path, policy, audit):
    fake_python = tmp_path / "fake-python"
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o755)
    with pytest.raises(InstallError, match="rolled back"):
        do_install(settings_path, str(fake_python), policy, audit)
    assert not settings_path.exists()


def test_policy_that_denies_no_bash_command_warns(settings_path, hook_python, tmp_path, audit):
    permissive = tmp_path / "permissive.json"
    permissive.write_text(json.dumps({"default": "allow", "rules": []}))
    report = do_install(settings_path, hook_python, permissive, audit)
    assert report.ok
    assert any(line.startswith("WARNING: policy does not deny the canary") for line in report.lines)


def test_policy_that_denies_the_canary_does_not_warn(settings_path, hook_python, policy, audit):
    report = do_install(settings_path, hook_python, policy, audit)
    assert not any("canary" in line for line in report.lines)


def test_observe_install_proves_the_would_be_deny_in_the_audit_and_says_not_enforcing(
    settings_path, hook_python, policy, audit
):
    report = do_install(settings_path, hook_python, policy, audit, mode="observe")
    assert "NOT ENFORCING: observe mode audits only and never blocks" in report.lines
    assert not any("canary" in line for line in report.lines)
    (hook,) = our_hooks(read(settings_path))
    assert "||" not in hook["command"]
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    canary = [row for row in rows if row["call_id"] == "cc:selftest-canary"]
    assert [(row["decision"], row["outcome"]) for row in canary] == [("deny", "observed")]


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_every_self_test_audit_row_is_attributed_to_the_self_test_session(
    settings_path, hook_python, policy, audit, mode
):
    do_install(settings_path, hook_python, policy, audit, mode=mode)
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    assert {row["agent_id"] for row in rows} == {SELFTEST_AGENT_ID}
    assert sorted(row["call_id"] for row in rows) == [
        "cc:selftest-benign",
        "cc:selftest-canary",
        "cc:selftest-fault",
    ]
    assert [row["event"] for row in rows if row["call_id"] == "cc:selftest-fault"] == ["fault"]


def test_unloadable_policy_or_relative_paths_are_refused_before_any_write(
    settings_path, hook_python, tmp_path, policy, audit
):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(InstallError, match="does not load"):
        do_install(settings_path, hook_python, bad, audit)
    with pytest.raises(InstallError, match="absolute"):
        do_install(settings_path, hook_python, Path("policy.json"), audit)
    with pytest.raises(InstallError, match="interpreter"):
        do_install(settings_path, "python3", policy, audit)
    assert not settings_path.exists()


def test_project_scope_warns_and_disabled_hooks_are_reported(settings_path, hook_python, policy, audit, tmp_path):
    local = tmp_path / "project" / ".claude" / "settings.local.json"
    local.parent.mkdir(parents=True)
    local.write_text(json.dumps({"disableAllHooks": True}))
    project_settings = tmp_path / "project" / ".claude" / "settings.json"
    report = do_install(project_settings, hook_python, policy, audit, scope="project", visible=[local])
    assert any(line.startswith("WARNING: project scope") for line in report.lines)
    assert any(f"disableAllHooks is true in {local}" in line for line in report.lines)


def test_uninstall_removes_only_our_entry(settings_path, hook_python, policy, audit):
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": [FOREIGN_HOOK]}}))
    do_install(settings_path, hook_python, policy, audit)
    report = installer.uninstall(settings_path)
    assert report.ok
    assert read(settings_path) == {"model": "opus", "hooks": {"PreToolUse": [FOREIGN_HOOK]}}


def test_uninstall_without_an_entry_changes_nothing(settings_path):
    assert "nothing to remove" in installer.uninstall(settings_path).lines[0]
    assert not settings_path.exists()
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"a":1}')
    installer.uninstall(settings_path)
    assert settings_path.read_text() == '{"a":1}'
    assert [p.name for p in settings_path.parent.iterdir()] == ["settings.json"]


def installed(settings_path, hook_python, policy, audit, **kwargs):
    do_install(settings_path, hook_python, policy, audit, **kwargs)
    return read(settings_path)


def test_check_passes_on_a_healthy_install(settings_path, hook_python, policy, audit):
    installed(settings_path, hook_python, policy, audit)
    report = installer.check(settings_path, hook_python, None, [])
    assert report.ok
    assert report.lines[-1] == "command verified; firing inside Claude Code not verified"
    assert not any("--uninstall" in line for line in report.lines)


def test_install_output_names_the_uninstall_step_for_the_operator(settings_path, hook_python, policy, audit):
    report = do_install(settings_path, hook_python, policy, audit)
    assert installer.UNINSTALL_NOTICE in report.lines


def test_starter_policy_gates_the_control_plane_with_its_own_paths(tmp_path):
    policy_path = tmp_path / "a b" / "policy.json"
    audit_path = tmp_path / "state" / "audit.jsonl"
    starter = installer.starter_policy(policy_path, audit_path)
    loaded = Policy.from_dict(starter)
    for command in (f"rm {policy_path}", f": > {audit_path}", "guard install claude-code --uninstall"):
        assert loaded.evaluate("shell", {"cmd": command}).decision is Decision.REQUIRE_HUMAN, command
    assert loaded.evaluate("shell", {"cmd": f"cat {tmp_path / 'other.json'}"}).decision is Decision.ALLOW


def test_check_flags_missing_entry_duplicates_and_stale_matcher(settings_path, hook_python, policy, audit):
    assert not installer.check(settings_path, hook_python, None, []).ok
    settings = installed(settings_path, hook_python, policy, audit)
    duplicated = json.loads(json.dumps(settings))
    duplicated["hooks"]["PreToolUse"].append(duplicated["hooks"]["PreToolUse"][0])
    settings_path.write_text(json.dumps(duplicated))
    assert "2 agent-guard hook entries" in installer.check(settings_path, hook_python, None, []).lines[0]
    stale = json.loads(json.dumps(settings))
    stale["hooks"]["PreToolUse"][0]["matcher"] = "^(Bash|Write)$"
    settings_path.write_text(json.dumps(stale))
    report = installer.check(settings_path, hook_python, None, [])
    assert not report.ok
    assert "stale matcher" in report.lines[0]


def test_check_flags_a_deleted_policy_and_a_missing_interpreter(settings_path, hook_python, policy, audit):
    installed(settings_path, hook_python, policy, audit)
    policy.unlink()
    report = installer.check(settings_path, hook_python, None, [])
    assert not report.ok
    assert "does not load" in report.lines[0]
    assert report.lines[-1] == installer.UNINSTALL_NOTICE
    policy.write_text(json.dumps(POLICY))
    text = settings_path.read_text().replace(hook_python, "/nonexistent/python")
    settings_path.write_text(text)
    report = installer.check(settings_path, hook_python, None, [])
    assert not report.ok
    assert "hook interpreter /nonexistent/python is not the interpreter running this guard" in report.lines[0]


def test_check_warns_when_on_failure_is_supported_but_absent(settings_path, hook_python, policy, audit):
    installed(settings_path, hook_python, policy, audit, version=OLD_CLAUDE)
    report = installer.check(settings_path, hook_python, NEW_CLAUDE, [])
    assert report.ok
    assert any("supports onFailure" in line for line in report.lines)


def write_project_hook(tmp_path, command: str) -> Path:
    project_settings = tmp_path / "project" / ".claude" / "settings.json"
    project_settings.parent.mkdir(parents=True, exist_ok=True)
    group = {"matcher": "^Bash$", "hooks": [{"type": "command", "command": command, "timeout": 10}]}
    project_settings.write_text(json.dumps({"hooks": {"PreToolUse": [group]}}))
    return project_settings


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_check_refuses_a_tampered_project_command_and_never_runs_it(
    monkeypatch, hook_python, policy, audit, tmp_path, capsys, mode
):
    monkeypatch.setattr(sys, "executable", hook_python)
    marker = tmp_path / "MARKER"
    command = installer.build_command(hook_python, str(policy), str(audit), mode) + f"; touch {marker}"
    write_project_hook(tmp_path, command)
    assert main(["install", "claude-code", "--check", "--scope", "project"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("PROBLEM: installed command ")
    assert "refusing to run it" in out
    assert not marker.exists()
    assert not audit.exists()


def test_check_refuses_an_interpreter_other_than_the_running_one(monkeypatch, policy, audit, tmp_path, capsys):
    marker = tmp_path / "MARKER"
    impostor = tmp_path / "project" / "impostor"
    impostor.write_text(f"#!/bin/sh\ntouch {marker}\nexit 2\n")
    impostor.chmod(0o755)
    write_project_hook(tmp_path, installer.build_command(str(impostor), str(policy), str(audit), "enforce"))
    assert main(["install", "claude-code", "--check", "--scope", "project"]) == 1
    assert f"PROBLEM: hook interpreter {impostor} is not the interpreter running this guard" in capsys.readouterr().out
    assert not marker.exists()


def test_cli_install_check_uninstall_round_trip_with_the_default_starter_policy(
    monkeypatch, hook_python, capsys, fake_home, tmp_path
):
    monkeypatch.setattr(sys, "executable", hook_python)
    assert main(["install", "claude-code", "--mode", "enforce"]) == 0
    out = capsys.readouterr().out
    assert "command verified; firing inside Claude Code not verified" in out
    starter = tmp_path / "xdg-config" / "agent-guard" / "claude-code-policy.json"
    audit_path = tmp_path / "xdg-state" / "agent-guard" / "claude-code.jsonl"
    assert json.loads(starter.read_text()) == installer.starter_policy(starter, audit_path)
    assert (tmp_path / "xdg-state" / "agent-guard").is_dir()
    settings_path = fake_home / ".claude" / "settings.json"
    assert len(our_hooks(read(settings_path))) == 1
    assert main(["install", "claude-code", "--check"]) == 0
    assert main(["install", "claude-code", "--uninstall"]) == 0
    assert our_hooks(read(settings_path)) == []
    capsys.readouterr()


def test_cli_scope_selects_the_settings_file(monkeypatch, hook_python, policy, audit, tmp_path, capsys):
    monkeypatch.setattr(sys, "executable", hook_python)
    argv = ["install", "claude-code", "--mode", "observe", "--policy", str(policy), "--audit", str(audit)]
    assert main([*argv, "--scope", "local"]) == 0
    assert (tmp_path / "project" / ".claude" / "settings.local.json").is_file()
    assert not (tmp_path / "project" / ".claude" / "settings.json").exists()
    assert main([*argv, "--scope", "project"]) == 0
    assert (tmp_path / "project" / ".claude" / "settings.json").is_file()
    assert not (tmp_path / "home" / ".claude").exists()
    capsys.readouterr()


def test_cli_refuses_missing_mode_conflicting_flags_and_missing_policy(monkeypatch, hook_python, capsys, tmp_path):
    monkeypatch.setattr(sys, "executable", hook_python)
    assert main(["install", "claude-code"]) == 1
    assert "--mode" in capsys.readouterr().err
    assert main(["install", "claude-code", "--check", "--uninstall"]) == 1
    assert "mutually exclusive" in capsys.readouterr().err
    assert main(["install", "claude-code", "--mode", "enforce", "--policy", str(tmp_path / "nope.json")]) == 1
    assert "does not exist" in capsys.readouterr().err
    assert not (tmp_path / "xdg-config").exists()


def test_install_tests_never_touch_the_real_home(fake_home, tmp_path):
    assert Path.home() == fake_home
    assert str(fake_home).startswith(str(tmp_path))
    assert os.environ["HOME"] == str(fake_home)
