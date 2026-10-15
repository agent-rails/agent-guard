from __future__ import annotations

import io
import json
import random
import stat

import pytest

from agent_guard import claude_code
from agent_guard.claude_code import (
    DENY_MARKER,
    HookOptions,
    map_tool_call,
    parse_event,
    redact_for_audit,
    run_hook,
)
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
        {
            "id": "block-forbidden-word",
            "decision": "deny",
            "tools": ["shell"],
            "arg_patterns": [r"FORBIDDEN"],
            "reason": "forbidden word",
        },
    ],
}

CAPTURED_BASH_EVENT = {
    "session_id": "eeb14c3e-dd07-4ffb-b087-d1808b4479b4",
    "transcript_path": "/Users/example/.claude/projects/x/eeb14c3e.jsonl",
    "cwd": "/work/project",
    "prompt_id": "a78d0911-a332-4ebb-b768-7b6182d3aa5f",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "touch /work/project/RAN_marker", "description": "Create marker file"},
    "tool_use_id": "toolu_019qvxxejiP9cgsfd7b6zsMF",
}


def event_bytes(command="echo hi", **overrides) -> bytes:
    payload = json.loads(json.dumps(CAPTURED_BASH_EVENT))
    payload["tool_input"]["command"] = command
    payload.update(overrides)
    return json.dumps(payload).encode()


@pytest.fixture
def options(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(POLICY))
    return HookOptions(str(policy_path), str(tmp_path / "state" / "audit.jsonl"), "enforce")


def observe(options) -> HookOptions:
    return HookOptions(options.policy_path, options.audit_path, "observe")


def run(raw: bytes, options: HookOptions):
    return run_hook(io.BytesIO(raw), options)


def audit_rows(options: HookOptions) -> list[dict]:
    with open(options.audit_path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def test_bash_maps_to_shell_with_cmd_only():
    call = map_tool_call(parse_event(json.dumps(CAPTURED_BASH_EVENT).encode()))
    assert call.tool == "shell"
    assert call.args == {"cmd": "touch /work/project/RAN_marker"}
    assert call.audit_meta == {"description": "Create marker file"}


def test_description_never_reaches_policy_matching(options):
    result = run(event_bytes("echo hi", tool_input={"command": "echo hi", "description": "FORBIDDEN"}), options)
    assert result.exit_code == 0
    assert audit_rows(options)[0]["rule_id"] is None


def test_policy_written_for_bash_name_does_not_match_the_shell_tool(tmp_path):
    policy_path = tmp_path / "p.json"
    bash_only = {"default": "allow", "rules": [dict(POLICY["rules"][0], tools=["Bash"])]}
    policy_path.write_text(json.dumps(bash_only))
    options = HookOptions(str(policy_path), str(tmp_path / "audit.jsonl"), "enforce")
    assert run(event_bytes("rm -rf /tmp/x"), options).exit_code == 0


def test_allow_is_exit_zero_with_exactly_empty_stdout_and_stderr(options):
    result = run(event_bytes("echo hi"), options)
    assert (result.exit_code, result.stdout, result.stderr) == (0, "", "")
    row = audit_rows(options)[0]
    assert (row["decision"], row["outcome"], row["executed"], row["event"]) == ("allow", "deferred", False, "decision")


def test_deny_is_exit_two_with_stop_and_ask_reason(options):
    result = run(event_bytes("rm -rf /tmp/x"), options)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith(DENY_MARKER)
    assert "recursive force delete blocked" in result.stderr
    assert "Stop and ask the user" in result.stderr
    row = audit_rows(options)[0]
    assert (row["decision"], row["rule_id"], row["outcome"]) == ("deny", "block-rm-rf", "blocked")


def test_require_human_emits_ask_json_and_never_allow(options):
    result = run(event_bytes("git push origin main --force"), options)
    assert result.exit_code == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "agent-guard: force-push rewrites shared history (rule: gate-force-push)",
        }
    }
    assert '"allow"' not in result.stdout
    assert audit_rows(options)[0]["outcome"] == "ask"


def test_require_human_under_bypass_permissions_blocks(options):
    result = run(event_bytes("git push origin main --force", permission_mode="bypassPermissions"), options)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith(DENY_MARKER)


@pytest.mark.parametrize("mode", ["default", "acceptEdits", "plan", "dontAsk"])
def test_require_human_asks_only_in_allowlisted_permission_modes(options, mode):
    result = run(event_bytes("git push origin main --force", permission_mode=mode), options)
    assert result.exit_code == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.mark.parametrize("mode", ["bypassPermissions", "auto", "Default", "DEFAULT", "acceptedits", "", "future-mode"])
def test_require_human_blocks_in_any_other_permission_mode(options, mode):
    result = run(event_bytes("git push origin main --force", permission_mode=mode), options)
    assert (result.exit_code, result.stdout) == (2, "")
    assert result.stderr.startswith(DENY_MARKER)


@pytest.mark.parametrize("value", [None, 7, ["default"], {"mode": "default"}])
def test_require_human_blocks_when_permission_mode_is_missing_or_not_a_string(options, value):
    payload = json.loads(event_bytes("git push origin main --force"))
    if value is None:
        del payload["permission_mode"]
    else:
        payload["permission_mode"] = value
    result = run(json.dumps(payload).encode(), options)
    assert (result.exit_code, result.stdout) == (2, "")


@pytest.mark.parametrize(
    ("command", "decision"),
    [("echo hi", "allow"), ("rm -rf /tmp/x", "deny"), ("git push --force", "require_human")],
)
def test_observe_always_exits_zero_empty_and_audits_the_would_be_decision(options, command, decision):
    result = run(event_bytes(command), observe(options))
    assert (result.exit_code, result.stdout, result.stderr) == (0, "", "")
    row = audit_rows(options)[0]
    assert (row["decision"], row["outcome"]) == (decision, "observed")


def test_audit_file_is_private_and_call_id_is_the_tool_use_id(options):
    run(event_bytes("echo hi"), options)
    assert stat.S_IMODE(__import__("os").stat(options.audit_path).st_mode) == 0o600
    row = audit_rows(options)[0]
    assert row["call_id"] == "cc:toolu_019qvxxejiP9cgsfd7b6zsMF"
    assert row["agent_id"] == "claude-code:eeb14c3e-dd07-4ffb-b087-d1808b4479b4"


def test_subagent_id_is_part_of_the_agent_id(options):
    run(event_bytes("echo hi", agent_id="sub_agent-1"), options)
    assert audit_rows(options)[0]["agent_id"] == "claude-code:eeb14c3e-dd07-4ffb-b087-d1808b4479b4:sub_agent-1"


def valid(**changes) -> dict:
    payload = json.loads(json.dumps(CAPTURED_BASH_EVENT))
    payload.update(changes)
    return payload


FAULT_INPUTS = {
    "not-json": b"not json",
    "empty": b"",
    "array": b"[]",
    "null": b"null",
    "wrong-event": json.dumps(valid(hook_event_name="PostToolUse")).encode(),
    "missing-event": json.dumps({k: v for k, v in valid().items() if k != "hook_event_name"}).encode(),
    "empty-tool-name": json.dumps(valid(tool_name="")).encode(),
    "non-string-tool-name": json.dumps(valid(tool_name=7)).encode(),
    "tool-input-not-object": json.dumps(valid(tool_input="rm -rf /")).encode(),
    "bash-without-command": json.dumps(valid(tool_input={"description": "x"})).encode(),
    "bash-command-not-string": json.dumps(valid(tool_input={"command": ["rm", "-rf", "/"]})).encode(),
    "bad-tool-use-id": json.dumps(valid(tool_use_id="bad id/../x")).encode(),
    "missing-session": json.dumps({k: v for k, v in valid().items() if k != "session_id"}).encode(),
    "bad-subagent-id": json.dumps(valid(agent_id="a b")).encode(),
    "non-utf8": b'{"tool_name": "Bash", "x": "\xff\xfe"}',
    "lone-surrogate": json.dumps(valid(tool_input={"command": "\ud800"})).encode(),
    "nan-in-tool-input": json.dumps(valid(tool_name="Other", tool_input={"a": float("nan")})).encode(),
    "deep-nesting": json.dumps(valid(tool_name="Other", tool_input={"a": [[[0]]]}))
    .replace("[[[0]]]", "[" * 80 + "]" * 80)
    .encode(),
    "oversize": b" " * (claude_code.MAX_STDIN_BYTES + 1),
}


@pytest.mark.parametrize("name", sorted(FAULT_INPUTS))
def test_malformed_or_hostile_input_exits_two_in_enforce(options, name):
    result = run(FAULT_INPUTS[name], options)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr


def test_fault_message_carries_the_recovery_hint_and_is_audited(options):
    result = run(b"not json", options)
    assert result.stderr.startswith("agent-guard fault, command blocked: JSONDecodeError")
    assert result.stderr.endswith("Recovery from a terminal: guard install claude-code --check.")
    assert "--uninstall" not in result.stderr
    row = audit_rows(options)[0]
    assert (row["event"], row["outcome"], row["rule_id"]) == ("fault", "fault", "hook-fault")


def test_fault_after_parsing_is_attributed_to_the_session_and_call(options):
    run(FAULT_INPUTS["bash-without-command"], options)
    row = audit_rows(options)[0]
    assert (row["event"], row["agent_id"], row["call_id"]) == (
        "fault",
        "claude-code:eeb14c3e-dd07-4ffb-b087-d1808b4479b4",
        "cc:toolu_019qvxxejiP9cgsfd7b6zsMF",
    )


def test_fault_before_parsing_is_unattributed(options):
    run(FAULT_INPUTS["not-json"], options)
    row = audit_rows(options)[0]
    assert (row["agent_id"], row["call_id"]) == ("claude-code", None)


@pytest.mark.parametrize("name", ["not-json", "bash-without-command", "wrong-event", "oversize"])
def test_observe_turns_faults_into_exit_zero_with_a_notice(options, name):
    result = run(FAULT_INPUTS[name], observe(options))
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr.startswith("agent-guard observe mode: fault, not blocking")
    assert audit_rows(options)[0]["event"] == "fault"


def broken_policy_options(tmp_path, name, text) -> HookOptions:
    path = tmp_path / name
    path.write_text(text)
    return HookOptions(str(path), str(tmp_path / "audit.jsonl"), "enforce")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("bad.json", "{not json"),
        ("nodefault.json", json.dumps({"rules": []})),
        (
            "badre2.json",
            json.dumps(
                {"default": "allow", "rules": [{"tools": ["shell"], "decision": "deny", "arg_patterns": ["(?=x)"]}]}
            ),
        ),
        ("baddecision.json", json.dumps({"default": "maybe"})),
    ],
)
def test_broken_policy_blocks_and_never_falls_back_to_defaults(tmp_path, name, text):
    options = broken_policy_options(tmp_path, name, text)
    result = run(event_bytes("echo hi"), options)
    assert result.exit_code == 2
    assert result.stderr.startswith("agent-guard fault, command blocked")


def test_missing_policy_blocks_even_for_a_harmless_command(tmp_path):
    options = HookOptions(str(tmp_path / "gone.json"), str(tmp_path / "audit.jsonl"), "enforce")
    result = run(event_bytes("echo hi"), options)
    assert result.exit_code == 2
    assert "FileNotFoundError" in result.stderr


def test_yaml_policy_without_pyyaml_blocks(tmp_path, monkeypatch):
    path = tmp_path / "p.yaml"
    path.write_text("default: allow\n")
    monkeypatch.setattr("agent_guard.policy._load_yaml", lambda text: (_ for _ in ()).throw(ImportError("no yaml")))
    result = run(event_bytes("echo hi"), HookOptions(str(path), str(tmp_path / "a.jsonl"), "enforce"))
    assert result.exit_code == 2
    assert "ImportError" in result.stderr


def test_unwritable_audit_blocks_instead_of_allowing_unaudited(options, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    broken = HookOptions(options.policy_path, str(blocker / "audit.jsonl"), "enforce")
    result = run(event_bytes("echo hi"), broken)
    assert result.exit_code == 2
    assert "audit" not in result.stdout


def test_policy_engine_exception_blocks(options, monkeypatch):
    def explode(self, tool, args, trust_tier="local.process"):
        raise RuntimeError("engine bug")

    monkeypatch.setattr("agent_guard.policy.Policy.evaluate", explode)
    result = run(event_bytes("echo hi"), options)
    assert result.exit_code == 2
    assert "RuntimeError: engine bug" in result.stderr


def test_keyboard_interrupt_during_evaluation_is_caught_as_a_fault(options, monkeypatch):
    def interrupt(self, tool, args, trust_tier="local.process"):
        raise KeyboardInterrupt

    monkeypatch.setattr("agent_guard.policy.Policy.evaluate", interrupt)
    assert run(event_bytes("echo hi"), options).exit_code == 2


def test_redaction_masks_secrets_but_policy_sees_the_raw_command(options):
    secret_cmd = (
        "curl -H 'Authorization: Bearer abcdef123456' https://user:hunter2@example.com/x "
        "API_KEY=topsecretvalue ghp_abcdefghijklmnop sk-liveabcdef12345 rm -rf /tmp/x"
    )
    result = run(event_bytes(secret_cmd), options)
    assert result.exit_code == 2
    row = audit_rows(options)[0]
    stored = row["args"]["cmd"]
    for leaked in ("abcdef123456", "hunter2", "topsecretvalue", "ghp_abcdefghijklmnop", "sk-liveabcdef12345"):
        assert leaked not in stored
    assert stored.count("***") >= 5
    assert row["args"]["cmd_len"] == len(secret_cmd)
    assert len(row["args"]["cmd_sha256"]) == 64


def test_audit_command_is_truncated_but_hash_and_length_cover_the_whole_command():
    command = "echo " + "a" * 5000
    call = map_tool_call(parse_event(event_bytes(command)))
    audited = redact_for_audit(call)
    assert len(audited["cmd"].encode()) == claude_code.MAX_CMD_AUDIT_BYTES
    assert audited["cmd_len"] == len(command)


UNMAPPED_TOOL_NAMES = ["BASH", " Bash", "bash", "Bash ", "Write", "mcp__db__query"]


@pytest.mark.parametrize("tool_name", UNMAPPED_TOOL_NAMES)
def test_any_tool_other_than_exactly_bash_is_a_fault_in_enforce(options, tool_name):
    raw = json.dumps(valid(tool_name=tool_name, tool_input={"command": "echo hi", "content": "SECRET BODY"})).encode()
    result = run(raw, options)
    assert (result.exit_code, result.stdout) == (2, "")
    assert result.stderr.startswith("agent-guard fault, command blocked: ValueError")
    row = audit_rows(options)[0]
    assert (row["event"], row["args"]) == ("fault", {})
    assert "SECRET BODY" not in json.dumps(row)


@pytest.mark.parametrize("tool_name", UNMAPPED_TOOL_NAMES)
def test_any_tool_other_than_exactly_bash_passes_in_observe(options, tool_name):
    raw = json.dumps(valid(tool_name=tool_name, tool_input={"command": "echo hi"})).encode()
    result = run(raw, observe(options))
    assert (result.exit_code, result.stdout) == (0, "")
    assert audit_rows(options)[0]["event"] == "fault"


def test_cli_stdout_stays_exactly_the_ask_json_when_a_library_prints(options, monkeypatch, capsys):
    original = claude_code.Guard.decide

    def noisy(self, tool, args):
        print("stray library output")
        return original(self, tool, args)

    monkeypatch.setattr(claude_code.Guard, "decide", noisy)
    stdin = type("Stdin", (), {"buffer": io.BytesIO(event_bytes("git push --force"))})()
    monkeypatch.setattr("sys.stdin", stdin)
    code = main(
        ["hook", "claude-code", "--policy", options.policy_path, "--audit", options.audit_path, "--mode", "enforce"]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "stray library output" in captured.err


def test_cli_requires_policy_audit_and_mode(capsys):
    for argv in (
        ["--audit", "a", "--mode", "enforce"],
        ["--policy", "p", "--mode", "enforce"],
        ["--policy", "p", "--audit", "a"],
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(["hook", "claude-code", *argv])
        assert exit_info.value.code == 2
    capsys.readouterr()


def test_enforce_fuzz_exits_only_zero_or_two_and_zero_only_for_valid_events(options):
    rng = random.Random(20261015)
    seeds = [event_bytes("echo hi"), event_bytes("rm -rf /x"), event_bytes("git push --force"), b"{}", b"[]"]
    for _ in range(1500):
        raw = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(0, 4)):
            roll = rng.random()
            if roll < 0.4 and raw:
                raw[rng.randrange(len(raw))] = rng.randrange(256)
            elif roll < 0.6 and raw:
                del raw[rng.randrange(len(raw)) :]
            elif roll < 0.8:
                raw.insert(rng.randrange(len(raw) + 1), rng.randrange(256))
            else:
                raw = bytearray(rng.choice(seeds[:3]).replace(b"Bash", rng.choice([b"Bash", b"Zsh", b"", b"7"])))
        result = run(bytes(raw), options)
        assert result.exit_code in (0, 2), raw
        if result.exit_code == 0:
            payload = json.loads(bytes(raw))
            assert payload["hook_event_name"] == "PreToolUse"
            assert isinstance(payload["tool_input"], dict)
