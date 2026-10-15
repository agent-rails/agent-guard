from __future__ import annotations

import copy
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .claude_code import DENY_MARKER, MODES, RECOVERY_HINT, SELFTEST_SESSION
from .policy import load_policy

MATCHER = "^Bash$"
HOOK_TIMEOUT_SECONDS = 10
ON_FAILURE_MIN_VERSION = (2, 1, 295)
ENTRY_ARGS = ("-I", "-m", "agent_guard.cli", "hook", "claude-code")
SCOPES = ("user", "local", "project")
SELFTEST_PATH = "/usr/bin:/bin"
SELFTEST_TIMEOUT_SECONDS = 30
CANARY_COMMAND = "rm -rf /tmp/agent-guard-selftest-canary"
VERIFIED_NOTICE = "command verified; firing inside Claude Code not verified"
RECOVERY_NOTICE = f"agent-guard hook failed, command blocked. {RECOVERY_HINT}"


class InstallError(Exception):
    pass


@dataclass(frozen=True)
class Report:
    ok: bool
    lines: list[str] = field(default_factory=list)

    def render(self) -> str:
        return "\n".join(self.lines)


@dataclass(frozen=True)
class SelfTestResult:
    problems: list[str]
    warnings: list[str]


def default_policy_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "agent-guard" / "claude-code-policy.json"


def default_audit_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "agent-guard" / "claude-code.jsonl"


def settings_path_for(scope: str, home: Path, cwd: Path) -> Path:
    if scope == "user":
        return home / ".claude" / "settings.json"
    if scope == "local":
        return cwd / ".claude" / "settings.local.json"
    if scope == "project":
        return cwd / ".claude" / "settings.json"
    raise InstallError(f"unknown scope {scope!r}; expected one of {SCOPES}")


def build_command(python: str, policy: str, audit: str, mode: str) -> str:
    if mode not in MODES:
        raise InstallError(f"unknown mode {mode!r}; expected one of {MODES}")
    head = shlex.join([python, *ENTRY_ARGS, "--policy", policy, "--audit", audit, "--mode", mode])
    if mode == "observe":
        return head
    return f"{head} || {{ [ $? -eq 2 ] || echo {shlex.quote(RECOVERY_NOTICE)} >&2; exit 2; }}"


def _tokens(command: Any) -> list[str]:
    if not isinstance(command, str):
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return []


def is_ours(command: Any) -> bool:
    tokens = _tokens(command)
    return len(tokens) > len(ENTRY_ARGS) and tokens[1 : 1 + len(ENTRY_ARGS)] == list(ENTRY_ARGS)


def parse_command(command: str) -> dict[str, str]:
    tokens = _tokens(command)
    flags_at = len(ENTRY_ARGS) + 1
    shaped = (
        len(tokens) >= flags_at + 6
        and tokens[1:flags_at] == list(ENTRY_ARGS)
        and tokens[flags_at : flags_at + 6 : 2] == ["--policy", "--audit", "--mode"]
        and tokens[flags_at + 5] in MODES
    )
    if not shaped:
        raise InstallError("installed command does not have the shape guard install writes; refusing to run it")
    parsed = {
        "python": tokens[0],
        "policy": tokens[flags_at + 1],
        "audit": tokens[flags_at + 3],
        "mode": tokens[flags_at + 5],
    }
    if build_command(parsed["python"], parsed["policy"], parsed["audit"], parsed["mode"]) != command:
        raise InstallError("installed command differs from what guard install writes; refusing to run it")
    return parsed


def _validate_settings(settings: Any, path: Path) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise InstallError(f"{path}: top level must be a JSON object; refusing to modify")
    hooks = settings.get("hooks")
    if hooks is None:
        return settings
    if not isinstance(hooks, dict):
        raise InstallError(f"{path}: 'hooks' must be an object; refusing to modify")
    groups = hooks.get("PreToolUse")
    if groups is None:
        return settings
    if not isinstance(groups, list):
        raise InstallError(f"{path}: 'hooks.PreToolUse' must be a list; refusing to modify")
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks", []), list):
            raise InstallError(f"{path}: every PreToolUse entry must be an object with a 'hooks' list; refusing")
        if not all(isinstance(hook, dict) for hook in group.get("hooks", [])):
            raise InstallError(f"{path}: every hook must be an object; refusing to modify")
    return settings


def load_settings(path: Path) -> tuple[dict[str, Any], bytes | None]:
    target = path.resolve()
    if not target.exists():
        return {}, None
    original = target.read_bytes()
    try:
        parsed = json.loads(original.decode("utf-8"))
    except ValueError as err:
        raise InstallError(f"{target}: not valid JSON ({err}); refusing to modify") from err
    return _validate_settings(parsed, target), original


def remove_ours(settings: dict[str, Any]) -> tuple[dict[str, Any], int]:
    updated = copy.deepcopy(settings)
    groups = updated.get("hooks", {}).get("PreToolUse")
    if groups is None:
        return updated, 0
    removed = 0
    kept = []
    for group in groups:
        hooks = group.get("hooks", [])
        remaining = [hook for hook in hooks if not is_ours(hook.get("command"))]
        removed += len(hooks) - len(remaining)
        if remaining or len(remaining) == len(hooks):
            kept.append({**group, "hooks": remaining} if "hooks" in group else group)
    updated["hooks"]["PreToolUse"] = kept
    return updated, removed


def hook_entry(command: str, mode: str, claude_version: tuple[int, int, int] | None) -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "command", "command": command, "timeout": HOOK_TIMEOUT_SECONDS}
    if mode == "enforce" and claude_version is not None and claude_version >= ON_FAILURE_MIN_VERSION:
        entry["onFailure"] = "block"
    return entry


def apply_hook(settings: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    updated, _removed = remove_ours(settings)
    groups = updated.setdefault("hooks", {}).setdefault("PreToolUse", [])
    groups.append({"matcher": MATCHER, "hooks": [entry]})
    return updated


def _render(settings: dict[str, Any]) -> bytes:
    return (json.dumps(settings, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _current_bytes(target: Path) -> bytes | None:
    return target.read_bytes() if target.exists() else None


def write_settings_atomic(path: Path, data: bytes, original: bytes | None) -> Path | None:
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if _current_bytes(target) != original:
        raise InstallError(f"{target} changed since it was read; aborting without writing, re-run")
    backup = None
    mode = 0o600
    if original is not None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = target.with_name(f"{target.name}.agent-guard-backup-{stamp}")
        shutil.copy2(target, backup)
        mode = stat.S_IMODE(target.stat().st_mode)
    descriptor, staging = tempfile.mkstemp(dir=target.parent, prefix=f"{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, mode)
        if _current_bytes(target) != original:
            raise InstallError(f"{target} changed while staging; aborting without writing, re-run")
        os.replace(staging, target)
    except BaseException:
        Path(staging).unlink(missing_ok=True)
        raise
    return backup


def detect_claude_version() -> tuple[int, int, int] | None:
    try:
        completed = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", completed.stdout.strip())
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def _version_text(version: tuple[int, int, int] | None) -> str:
    return "not detected" if version is None else ".".join(str(part) for part in version)


def _selftest_event(name: str, command: str | None) -> bytes:
    return json.dumps(
        {
            "session_id": SELFTEST_SESSION,
            "hook_event_name": "PreToolUse",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": f"selftest-{name}",
        }
    ).encode()


def _run_installed(command: str, payload: bytes) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": SELFTEST_PATH}
    return subprocess.run(
        ["sh", "-c", command], input=payload, capture_output=True, timeout=SELFTEST_TIMEOUT_SECONDS, env=env
    )


def _audit_decision_for(audit_path: str, call_id: str) -> str | None:
    path = Path(audit_path)
    if not path.exists():
        return None
    found = None
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("call_id") == call_id:
            found = row.get("decision")
    return found


def _check_fault(command: str, mode: str) -> list[str]:
    expected = 2 if mode == "enforce" else 0
    completed = _run_installed(command, _selftest_event("fault", None))
    if completed.returncode != expected:
        return [f"fault probe exited {completed.returncode}, expected {expected}: {completed.stderr.decode()!r}"]
    return []


def _check_benign(command: str) -> list[str]:
    completed = _run_installed(command, _selftest_event("benign", "echo agent-guard-selftest"))
    if completed.returncode != 0 or completed.stdout:
        return [f"benign command exited {completed.returncode} with stdout {completed.stdout!r}, expected 0 and empty"]
    return []


def _check_canary(command: str, mode: str, audit_path: str) -> tuple[list[str], list[str]]:
    completed = _run_installed(command, _selftest_event("canary", CANARY_COMMAND))
    not_denied = f"policy does not deny the canary Bash command {CANARY_COMMAND!r}; the deny path is unproven"
    if mode == "observe":
        if completed.returncode != 0:
            return [f"observe-mode canary exited {completed.returncode}, expected 0"], []
        if _audit_decision_for(audit_path, "cc:selftest-canary") != "deny":
            return [], [not_denied]
        return [], []
    if completed.returncode == 2 and DENY_MARKER in completed.stderr.decode():
        return [], []
    if completed.returncode == 2:
        return [f"canary was blocked by a fault, not a policy deny: {completed.stderr.decode()!r}"], []
    return [], [not_denied]


def run_self_test(command: str, mode: str, audit_path: str) -> SelfTestResult:
    try:
        problems = _check_fault(command, mode) + _check_benign(command)
        canary_problems, canary_warnings = _check_canary(command, mode, audit_path)
    except subprocess.TimeoutExpired as err:
        return SelfTestResult([f"self-test timed out after {err.timeout}s"], [])
    return SelfTestResult(problems + canary_problems, canary_warnings)


def disabled_hooks_warnings(paths: list[Path]) -> list[str]:
    warnings = []
    for path in paths:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            warnings.append(f"cannot read {path}: {err}")
            continue
        if isinstance(data, dict) and data.get("disableAllHooks") is True:
            warnings.append(f"disableAllHooks is true in {path}: the hook will not run")
    return warnings


def _validate_inputs(python: str, policy: Path, audit: Path) -> None:
    if not os.path.isabs(python) or not os.access(python, os.X_OK):
        raise InstallError(f"interpreter {python!r} must be an absolute path to an executable")
    if not policy.is_absolute() or not audit.is_absolute():
        raise InstallError("policy and audit paths must be absolute")
    try:
        load_policy(policy)
    except Exception as err:
        raise InstallError(f"policy {policy} does not load: {type(err).__name__}: {err}") from err
    audit.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not os.access(audit.parent, os.W_OK):
        raise InstallError(f"audit directory {audit.parent} is not writable")


def _rollback(settings_path: Path, written: bytes, original: bytes | None) -> None:
    if original is None:
        target = settings_path.resolve()
        if _current_bytes(target) != written:
            raise InstallError(f"{target} changed during the self-test; not rolling back, inspect it")
        target.unlink()
        return
    write_settings_atomic(settings_path, original, written)


def install(
    settings_path: Path,
    python: str,
    policy: Path,
    audit: Path,
    mode: str,
    scope: str,
    claude_version: tuple[int, int, int] | None,
    visible_settings: list[Path],
) -> Report:
    settings, original = load_settings(settings_path)
    _validate_inputs(python, policy, audit)
    command = build_command(python, str(policy), str(audit), mode)
    entry = hook_entry(command, mode, claude_version)
    written = _render(apply_hook(settings, entry))
    backup = write_settings_atomic(settings_path, written, original)
    result = run_self_test(command, mode, str(audit))
    if result.problems:
        _rollback(settings_path, written, original)
        problems = "; ".join(result.problems)
        raise InstallError(f"self-test failed, settings rolled back: {problems}")
    lines = [f"installed {mode} hook for Claude Code ({scope} scope) in {settings_path.resolve()}"]
    if mode == "observe":
        lines.append("NOT ENFORCING: observe mode audits only and never blocks")
    if scope == "project":
        lines.append(
            "WARNING: project scope commits a machine-specific absolute path and lets the repo control the hook"
        )
    if backup is not None:
        lines.append(f"backup: {backup}")
    if mode == "enforce" and "onFailure" not in entry:
        lines.append(
            f"note: Claude Code {_version_text(claude_version)} is below {'.'.join(map(str, ON_FAILURE_MIN_VERSION))}"
            " or undetected, so a hook timeout still lets the command run; the hook budget is "
            f"{HOOK_TIMEOUT_SECONDS}s"
        )
    lines += [f"WARNING: {warning}" for warning in result.warnings]
    lines += [f"WARNING: {warning}" for warning in disabled_hooks_warnings(visible_settings)]
    lines.append(f"policy: {policy}")
    lines.append(f"audit: {audit}")
    lines.append(VERIFIED_NOTICE)
    return Report(True, lines)


def uninstall(settings_path: Path) -> Report:
    settings, original = load_settings(settings_path)
    updated, removed = remove_ours(settings)
    if removed == 0:
        return Report(True, [f"nothing to remove: no agent-guard hook in {settings_path.resolve()}"])
    backup = write_settings_atomic(settings_path, _render(updated), original)
    return Report(
        True, [f"removed {removed} agent-guard hook entr{'y' if removed == 1 else 'ies'}", f"backup: {backup}"]
    )


def _our_hooks(settings: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    found = []
    for group in settings.get("hooks", {}).get("PreToolUse", []):
        for hook in group.get("hooks", []):
            if is_ours(hook.get("command")):
                found.append((group, hook))
    return found


def _check_entry(
    group: dict[str, Any], hook: dict[str, Any], python: str, version: tuple[int, int, int] | None
) -> Report:
    try:
        parsed = parse_command(hook["command"])
    except InstallError as err:
        return Report(False, [f"PROBLEM: {err}; re-run guard install claude-code"])
    if parsed["python"] != python:
        return Report(
            False,
            [
                f"PROBLEM: hook interpreter {parsed['python']} is not the interpreter running this guard ({python}); "
                "run --check with the hook's own guard, or re-run guard install claude-code from the environment "
                "the hook should use"
            ],
        )
    command = build_command(parsed["python"], parsed["policy"], parsed["audit"], parsed["mode"])
    problems: list[str] = []
    warnings: list[str] = []
    if group.get("matcher") != MATCHER:
        problems.append(
            f"stale matcher {group.get('matcher')!r}, expected {MATCHER!r}: re-run guard install claude-code"
        )
    try:
        load_policy(parsed["policy"])
    except Exception as err:
        problems.append(f"policy {parsed['policy']} does not load: {type(err).__name__}: {err}")
    if parsed["mode"] == "enforce" and version is not None and version >= ON_FAILURE_MIN_VERSION:
        if hook.get("onFailure") != "block":
            warnings.append(
                "Claude Code supports onFailure but the hook does not set it: re-run guard install claude-code"
            )
    if problems:
        return Report(False, [f"PROBLEM: {problem}" for problem in problems] + [f"WARNING: {w}" for w in warnings])
    result = run_self_test(command, parsed["mode"], parsed["audit"])
    lines = [f"mode: {parsed['mode']}", f"policy: {parsed['policy']}", f"audit: {parsed['audit']}"]
    lines += [f"PROBLEM: {problem}" for problem in result.problems]
    lines += [f"WARNING: {warning}" for warning in warnings + result.warnings]
    if not result.problems:
        lines.append(VERIFIED_NOTICE)
    return Report(not result.problems, lines)


def check(
    settings_path: Path, python: str, claude_version: tuple[int, int, int] | None, visible_settings: list[Path]
) -> Report:
    settings, _original = load_settings(settings_path)
    ours = _our_hooks(settings)
    if not ours:
        return Report(False, [f"PROBLEM: no agent-guard hook in {settings_path.resolve()}"])
    if len(ours) > 1:
        return Report(False, [f"PROBLEM: {len(ours)} agent-guard hook entries; re-run guard install claude-code"])
    group, hook = ours[0]
    report = _check_entry(group, hook, python, claude_version)
    warnings = [f"WARNING: {warning}" for warning in disabled_hooks_warnings(visible_settings)]
    return Report(report.ok, [*report.lines, *warnings])
