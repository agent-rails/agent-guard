from __future__ import annotations

import json
import os
import random
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agent_guard import claude_code
from agent_guard.claude_code_install import RECOVERY_NOTICE, build_command, starter_policy

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
MINIMAL_ENV = {"PATH": "/usr/bin:/bin"}


def event(command: str, tool_use_id: str = "toolu_subprocess", **overrides) -> bytes:
    payload = {
        "session_id": "11111111-2222-3333-4444-555555555555",
        "hook_event_name": "PreToolUse",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "d"},
        "tool_use_id": tool_use_id,
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


@pytest.fixture
def policy(tmp_path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY))
    return path


@pytest.fixture
def audit(tmp_path) -> Path:
    return tmp_path / "state" / "audit.jsonl"


@pytest.fixture
def enforce(hook_python, policy, audit) -> str:
    return build_command(hook_python, str(policy), str(audit), "enforce")


@pytest.fixture
def observe(hook_python, policy, audit) -> str:
    return build_command(hook_python, str(policy), str(audit), "observe")


def run_installed(command: str, payload: bytes, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sh", "-c", command],
        input=payload,
        capture_output=True,
        env=MINIMAL_ENV if env is None else env,
        timeout=60,
    )


def standin(tmp_path: Path, name: str, body: str, executable: bool = True) -> str:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755 if executable else 0o644)
    return str(path)


def test_installed_command_matrix_under_a_minimal_path(enforce):
    allow = run_installed(enforce, event("echo hi"))
    assert (allow.returncode, allow.stdout, allow.stderr) == (0, b"", b"")
    deny = run_installed(enforce, event("rm -rf /tmp/x"))
    assert (deny.returncode, deny.stdout) == (2, b"")
    assert deny.stderr.decode().startswith(claude_code.DENY_MARKER)
    ask = run_installed(enforce, event("git push --force"))
    assert ask.returncode == 0
    assert json.loads(ask.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    bypass = run_installed(enforce, event("git push --force", permission_mode="bypassPermissions"))
    assert (bypass.returncode, bypass.stdout) == (2, b"")


def test_observe_command_never_blocks_but_audits_the_would_be_deny(observe, audit):
    result = run_installed(observe, event("rm -rf /tmp/x"))
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")
    row = json.loads(audit.read_text())
    assert (row["decision"], row["outcome"]) == ("deny", "observed")


@pytest.mark.parametrize(("mode", "expected"), [("observe", 0), ("enforce", 2)])
def test_version_skewed_command_never_blocks_in_observe_but_blocks_in_enforce(
    hook_python, policy, audit, mode, expected
):
    skewed = build_command(hook_python, str(policy), str(audit), mode).replace(
        "hook claude-code", "hook claude-codex", 1
    )
    result = run_installed(skewed, event("echo hi"))
    assert result.returncode == expected
    assert result.stdout == b""


@pytest.mark.parametrize("body", ["exit 1", "exit 2", "exit 127", "kill -9 $$"])
def test_observe_wrapper_turns_every_crash_into_a_pass(tmp_path, policy, audit, body):
    command = build_command(standin(tmp_path, "crash", body), str(policy), str(audit), "observe")
    result = run_installed(command, event("rm -rf /tmp/x"))
    assert (result.returncode, result.stdout) == (0, b"")


def test_observe_command_does_not_block_on_a_missing_policy(hook_python, tmp_path, audit):
    command = build_command(hook_python, str(tmp_path / "gone.json"), str(audit), "observe")
    result = run_installed(command, event("echo hi"))
    assert result.returncode == 0
    assert b"observe mode: fault, not blocking" in result.stderr


@pytest.mark.parametrize(
    ("name", "body", "executable"),
    [
        ("exit1", "exit 1", True),
        ("exit3", "exit 3", True),
        ("exit127", "exit 127", True),
        ("kill9", "kill -9 $$", True),
        ("not-executable", "exit 0", False),
        ("exit1-with-traceback-text", "echo traceback >&2; exit 1", True),
    ],
)
def test_wrapper_turns_every_crash_before_python_runs_into_a_block(tmp_path, policy, audit, name, body, executable):
    interpreter = standin(tmp_path, name, body, executable)
    command = build_command(interpreter, str(policy), str(audit), "enforce")
    wrapped = run_installed(command, event("echo hi"))
    assert wrapped.returncode == 2
    assert RECOVERY_NOTICE in wrapped.stderr.decode()
    unwrapped = run_installed(command.split(" || ")[0], event("echo hi"))
    assert unwrapped.returncode != 2


def test_missing_interpreter_is_blocked_by_the_wrapper(tmp_path, policy, audit):
    command = build_command(str(tmp_path / "no-such-python"), str(policy), str(audit), "enforce")
    result = run_installed(command, event("echo hi"))
    assert result.returncode == 2
    assert RECOVERY_NOTICE in result.stderr.decode()
    assert run_installed(command.split(" || ")[0], event("echo hi")).returncode == 127


def test_sigkill_of_the_real_hook_process_is_blocked(enforce):
    process = subprocess.Popen(
        ["sh", "-c", enforce], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=MINIMAL_ENV
    )
    deadline = time.monotonic() + 10
    child = None
    while child is None and time.monotonic() < deadline:
        found = subprocess.run(["pgrep", "-P", str(process.pid)], capture_output=True, text=True).stdout.split()
        child = int(found[0]) if found else None
        time.sleep(0.02)
    assert child is not None
    os.kill(child, signal.SIGKILL)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 2
    assert stdout == b""
    assert RECOVERY_NOTICE in stderr.decode()


def test_deny_output_carries_no_recovery_hint_for_the_agent(enforce):
    deny = run_installed(enforce, event("rm -rf /tmp/x"))
    assert "Recovery" not in deny.stderr.decode()
    assert "uninstall" not in deny.stderr.decode()


def test_fault_prints_the_recovery_hint_exactly_once(hook_python, tmp_path, audit):
    command = build_command(hook_python, str(tmp_path / "gone.json"), str(audit), "enforce")
    result = run_installed(command, event("echo hi"))
    assert result.returncode == 2
    assert result.stderr.decode().count("guard install claude-code --check") == 1
    assert "--uninstall" not in result.stderr.decode()


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_persisted_command_never_names_the_uninstall_switch(hook_python, policy, audit, mode):
    assert "--uninstall" not in build_command(hook_python, str(policy), str(audit), mode)


def test_isolated_mode_ignores_a_hostile_pythonpath(enforce, tmp_path):
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "sitecustomize.py").write_text("import os\nos._exit(0)\n")
    env = {**MINIMAL_ENV, "PYTHONPATH": str(evil)}
    assert run_installed(enforce, event("rm -rf /tmp/x"), env=env).returncode == 2
    without_isolation = enforce.replace(" -I ", " ", 1)
    assert run_installed(without_isolation, event("rm -rf /tmp/x"), env=env).returncode == 0


@pytest.mark.parametrize("payload", [b"", b"not json", b"[]", b"\xff\xfe\xfd"])
def test_malformed_stdin_blocks_through_the_installed_command(enforce, payload):
    assert run_installed(enforce, payload).returncode == 2


def test_oversize_stdin_blocks_through_the_installed_command(enforce):
    result = run_installed(enforce, b" " * (claude_code.MAX_STDIN_BYTES + 1))
    assert result.returncode == 2
    assert b"exceeds" in result.stderr


def test_installed_command_fuzz_exits_only_zero_or_two(enforce):
    rng = random.Random(20261016)
    seeds = [event("echo hi"), event("rm -rf /x"), event("git push --force"), b"{}"]
    payloads = []
    for _ in range(48):
        raw = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            roll = rng.random()
            if roll < 0.5 and raw:
                raw[rng.randrange(len(raw))] = rng.randrange(256)
            elif roll < 0.75 and raw:
                del raw[rng.randrange(len(raw)) :]
            else:
                raw.insert(rng.randrange(len(raw) + 1), rng.randrange(256))
        payloads.append(bytes(raw))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda raw: run_installed(enforce, raw), payloads))
    for raw, result in zip(payloads, results, strict=True):
        assert result.returncode in (0, 2), raw
        if result.returncode == 0:
            assert json.loads(raw)["hook_event_name"] == "PreToolUse"


def self_protection_commands(policy_path: Path, audit_path: Path) -> list[str]:
    return [
        "guard install claude-code --uninstall",
        "/opt/venv/bin/python -I -m agent_guard.cli install claude-code --uninstall",
        "jq '.disableAllHooks = true' s.json > t.json",
        "sed -i.bak '/PreToolUse/d' ~/.claude/settings.json",
        f"rm {policy_path}",
        f"truncate -s 0 {audit_path}",
    ]


@pytest.fixture
def starter_enforce(hook_python, tmp_path, audit) -> tuple[str, Path]:
    starter = tmp_path / "starter-policy.json"
    starter.write_text(json.dumps(starter_policy(starter, audit)))
    return build_command(hook_python, str(starter), str(audit), "enforce"), starter


def test_starter_policy_asks_before_touching_the_hook_control_plane(starter_enforce, audit):
    command, starter = starter_enforce
    for bash in self_protection_commands(starter, audit):
        result = run_installed(command, event(bash))
        assert result.returncode == 0, bash
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", bash
        bypass = run_installed(command, event(bash, permission_mode="bypassPermissions"))
        assert (bypass.returncode, bypass.stdout) == (2, b""), bash


def test_starter_policy_still_allows_ordinary_commands(starter_enforce):
    command, _starter = starter_enforce
    for bash in ("ls -la", "git status", "cat README.md", "echo agent-guard-selftest"):
        result = run_installed(command, event(bash))
        assert (result.returncode, result.stdout) == (0, b""), bash


def test_parallel_hooks_keep_every_audit_line_intact(enforce, audit):
    commands = [f"echo parallel-{index}" for index in range(32)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(
            pool.map(lambda pair: run_installed(enforce, event(pair[1], f"toolu_p{pair[0]}")), enumerate(commands))
        )
    assert [result.returncode for result in results] == [0] * 32
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sorted(row["call_id"] for row in rows) == sorted(f"cc:toolu_p{index}" for index in range(32))
