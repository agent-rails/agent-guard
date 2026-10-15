from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO

import re2

from .audit import AuditRecord, build_record
from .decision import Decision, Verdict
from .guard import Guard
from .policy import load_policy

MODES = ("enforce", "observe")
MAX_STDIN_BYTES = 32 * 1024 * 1024
MAX_CMD_AUDIT_BYTES = 2048
MAX_DESCRIPTION_AUDIT_BYTES = 256
SELFTEST_SESSION = "agent-guard-selftest"
SELFTEST_AGENT_ID = f"claude-code:{SELFTEST_SESSION}"
DENY_MARKER = "agent-guard blocked"
RECOVERY_HINT = "Recovery from a terminal: guard install claude-code --check."

_SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")

_REDACTIONS: tuple[tuple[Any, str], ...] = (
    (re2.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1***@"),
    (re2.compile(r"(?i)(authorization:\s*\S+\s+)\S+"), r"\1***"),
    (re2.compile(r"(?i)\b(bearer\s+)\S+"), r"\1***"),
    (re2.compile(r"(?i)\b([A-Za-z0-9_]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth)[A-Za-z0-9_]*=)\S+"), r"\1***"),
    (re2.compile(r"\b(sk-|ghp_|github_pat_|AKIA|xox[abp]-)[A-Za-z0-9_\-]+"), r"\1***"),
)


@dataclass(frozen=True)
class HookOptions:
    policy_path: str
    audit_path: str
    mode: str


@dataclass(frozen=True)
class HookResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class HookEvent:
    session_id: str
    subagent_id: str | None
    tool_use_id: str
    tool_name: str
    tool_input: dict[str, Any]
    permission_mode: str | None

    @property
    def agent_id(self) -> str:
        suffix = f":{self.subagent_id}" if self.subagent_id else ""
        return f"claude-code:{self.session_id}{suffix}"


@dataclass(frozen=True)
class MappedCall:
    tool: str
    args: dict[str, Any]
    audit_meta: dict[str, Any]


class _PrivateJsonlSink:
    def __init__(self, path: str) -> None:
        self._path = Path(path)

    def write(self, record: AuditRecord) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        line = (json.dumps(asdict(record)) + "\n").encode("utf-8")
        descriptor = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            written = os.write(descriptor, line)
        finally:
            os.close(descriptor)
        if written != len(line):
            raise OSError(f"short audit write to {self._path}: {written} of {len(line)} bytes")


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"event field '{field}' must match [A-Za-z0-9_-]{{1,128}}")
    return value


def parse_event(raw: bytes) -> HookEvent:
    if len(raw) > MAX_STDIN_BYTES:
        raise ValueError(f"hook input exceeds {MAX_STDIN_BYTES} bytes")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    if payload.get("hook_event_name") != "PreToolUse":
        raise ValueError(f"hook_event_name must be 'PreToolUse', got {payload.get('hook_event_name')!r}")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a non-empty string")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    subagent = payload.get("agent_id")
    permission_mode = payload.get("permission_mode")
    return HookEvent(
        session_id=_safe_id(payload.get("session_id"), "session_id"),
        subagent_id=None if subagent is None else _safe_id(subagent, "agent_id"),
        tool_use_id=_safe_id(payload.get("tool_use_id"), "tool_use_id"),
        tool_name=tool_name,
        tool_input=tool_input,
        permission_mode=permission_mode if isinstance(permission_mode, str) else None,
    )


def map_tool_call(event: HookEvent) -> MappedCall:
    if event.tool_name != "Bash":
        return MappedCall(event.tool_name, event.tool_input, {})
    command = event.tool_input.get("command")
    if not isinstance(command, str):
        raise ValueError("Bash tool_input.command must be a string")
    meta = {
        key: event.tool_input[key] for key in ("description", "timeout", "run_in_background") if key in event.tool_input
    }
    return MappedCall("shell", {"cmd": command}, meta)


def _mask(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _truncate(text: str, limit: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact_for_audit(call: MappedCall) -> dict[str, Any]:
    if call.tool != "shell":
        canonical = json.dumps(call.args, sort_keys=True)
        return {"keys": sorted(call.args), "args_sha256": _digest(canonical), "args_len": len(canonical)}
    command = call.args["cmd"]
    audited: dict[str, Any] = {
        "cmd": _truncate(_mask(command), MAX_CMD_AUDIT_BYTES),
        "cmd_sha256": _digest(command),
        "cmd_len": len(command),
    }
    meta: dict[str, Any] = {}
    description = call.audit_meta.get("description")
    if isinstance(description, str):
        meta["description"] = _truncate(_mask(description), MAX_DESCRIPTION_AUDIT_BYTES)
    for key in ("timeout", "run_in_background"):
        if key in call.audit_meta:
            meta[key] = call.audit_meta[key]
    if meta:
        audited["meta"] = meta
    return audited


def _deny_message(verdict: Verdict) -> str:
    rule = verdict.rule_id or "policy default"
    return (
        f"{DENY_MARKER} this Bash command: {verdict.reason} (rule: {rule}). "
        "Do not retry or rephrase it. Stop and ask the user how to proceed."
    )


def _ask_stdout(verdict: Verdict) -> str:
    reason = f"agent-guard: {verdict.reason} (rule: {verdict.rule_id or 'policy default'})"
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason,
            }
        }
    )


def render_result(verdict: Verdict, event: HookEvent, mode: str) -> HookResult:
    if mode == "observe" or verdict.decision is Decision.ALLOW:
        return HookResult(0, "", "")
    if verdict.decision is Decision.DENY:
        return HookResult(2, "", _deny_message(verdict))
    if event.permission_mode == "bypassPermissions":
        return HookResult(2, "", _deny_message(verdict))
    return HookResult(0, _ask_stdout(verdict), "")


def _outcome(result: HookResult, mode: str) -> str:
    if mode == "observe":
        return "observed"
    if result.exit_code == 2:
        return "blocked"
    if result.stdout:
        return "ask"
    return "deferred"


def _evaluate(event: HookEvent, options: HookOptions) -> HookResult:
    policy = load_policy(options.policy_path)
    guard = Guard(policy, audit=_PrivateJsonlSink(options.audit_path), agent_id=event.agent_id)
    call = map_tool_call(event)
    _allowed, verdict = guard.decide(call.tool, call.args)
    result = render_result(verdict, event, options.mode)
    guard.record(
        call.tool,
        redact_for_audit(call),
        verdict,
        executed=False,
        event="decision",
        call_id=f"cc:{event.tool_use_id}",
        outcome=_outcome(result, options.mode),
    )
    return result


def _fault_message(err: BaseException) -> str:
    return f"{type(err).__name__}: {str(err)[:500]}"


def _record_fault(options: HookOptions, event: HookEvent | None, err: BaseException) -> None:
    verdict = Verdict(Decision.DENY, f"hook fault: {_fault_message(err)}", rule_id="hook-fault")
    agent_id = "claude-code" if event is None else event.agent_id
    call_id = None if event is None else f"cc:{event.tool_use_id}"
    record = build_record(agent_id, "hook", {}, verdict, False, event="fault", call_id=call_id, outcome="fault")
    _PrivateJsonlSink(options.audit_path).write(record)


def _fault_result(options: HookOptions, event: HookEvent | None, err: BaseException) -> HookResult:
    with suppress(Exception):
        _record_fault(options, event, err)
    if options.mode == "observe":
        return HookResult(0, "", f"agent-guard observe mode: fault, not blocking: {_fault_message(err)}")
    return HookResult(
        2, "", f"agent-guard fault, command blocked: {_fault_message(err)}. Stop and tell the user. {RECOVERY_HINT}"
    )


def run_hook(stream: BinaryIO, options: HookOptions) -> HookResult:
    event = None
    try:
        event = parse_event(stream.read(MAX_STDIN_BYTES + 1))
        return _evaluate(event, options)
    except BaseException as err:
        return _fault_result(options, event, err)
