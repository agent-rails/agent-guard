from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from agent_guard.claude_code import SELFTEST_SESSION, HookOptions, run_hook
from agent_guard.claude_code_install import RM_PREFIX, starter_policy
from agent_guard.cli import main

OLD_RM_PREFIX = r"(?i)\brm\b[^;&|\n]*\s"
LIVE_RM_PREFIX = r"(?i)(?:^|[^-\w])rm\b[^;&|\n]*\s"
DOCKER_RM = "docker run --rm img pwsh -NoProfile"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)
    return home


@pytest.fixture
def audit(tmp_path) -> Path:
    return tmp_path / "state" / "audit.jsonl"


def write_policy(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data))
    return path


def hook_policy(tmp_path: Path, name: str, prefix: str = RM_PREFIX) -> Path:
    data = starter_policy(tmp_path / name, tmp_path / "state" / "audit.jsonl")
    for rule in data["rules"]:
        rule["arg_patterns"] = [pattern.replace(RM_PREFIX, prefix) for pattern in rule["arg_patterns"]]
    return write_policy(tmp_path / name, data)


@pytest.fixture
def merged(tmp_path) -> Path:
    return hook_policy(tmp_path, "merged.json")


@pytest.fixture
def old(tmp_path) -> Path:
    return hook_policy(tmp_path, "old.json", OLD_RM_PREFIX)


def hook(policy: Path, audit: Path, command, mode="observe", session="sess-a", tool_use_id="toolu_1") -> int:
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


def hook_all(policy: Path, audit: Path, commands: list[str], mode="observe") -> None:
    for index, command in enumerate(commands):
        hook(policy, audit, command, mode=mode, tool_use_id=f"toolu_{index}")


def decision_row(ts: str, cmd: str, decision: str = "allow", rule_id: str | None = None, **overrides) -> dict:
    row = {
        "ts": ts,
        "agent_id": "claude-code:s1",
        "event": "decision",
        "decision": decision,
        "rule_id": rule_id,
        "outcome": "observed",
        "args": {"cmd": cmd, "cmd_sha256": hashlib.sha256(cmd.encode()).hexdigest(), "cmd_len": len(cmd)},
    }
    row.update(overrides)
    return row


def write_rows(audit: Path, rows: list[dict]) -> None:
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text("".join(json.dumps(row) + "\n" for row in rows))


def replay(capsys, *argv: str) -> tuple[int, list[str], str]:
    code = main(["replay", *argv])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


def counts_line(replayed=0, selftest=0, faults=0, unreadable=0, skipped=0) -> str:
    return (
        f"replayed: {replayed}  self-test excluded: {selftest}  faults excluded: {faults}  "
        f"unreadable: {unreadable}  skipped: {skipped}"
    )


MIXED_COMMANDS = [
    "echo hi",
    "rm -rf /tmp/x",
    "git push --force origin main",
    DOCKER_RM,
    "guard install claude-code --uninstall",
    "ls -la\nrm -fr /tmp/y",
]


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_rows_written_under_a_policy_replayed_against_it_show_no_change(merged, audit, capsys, mode):
    hook_all(merged, audit, MIXED_COMMANDS, mode=mode)
    logged = [json.loads(line)["decision"] for line in audit.read_text().splitlines()]
    assert set(logged) == {"allow", "deny", "require_human"}
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--against-policy", str(merged))
    assert code == 0
    assert counts_line(replayed=len(MIXED_COMMANDS)) in out
    assert "changed: 0" in out
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert code == 0
    assert "changed: 0" in out
    assert out[-1] == "result: OK"


def test_docker_rm_flag_flips_deny_to_allow_moving_to_the_merged_prefix(old, merged, audit, capsys):
    hook_all(old, audit, ["echo hi", DOCKER_RM, "rm -rf /tmp/x"])
    row = json.loads(audit.read_text().splitlines()[1])
    assert row["decision"] == "deny"
    expected = [
        f"audit: {audit}",
        f"candidate: {merged}",
        "baseline: logged decisions (mixes every policy live during the log)",
        counts_line(replayed=3),
        "stored text differs from the original command (redacted or truncated): 0",
        "changed: 1",
        "deny -> allow (1)",
        f"  {row['ts']}  claude-code:sess-a  block-rm-rf -> policy default  {DOCKER_RM}",
        "result: OK",
    ]
    assert replay(capsys, "--policy", str(merged), "--audit", str(audit)) == (0, expected, "")
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--against-policy", str(old))
    assert code == 0
    assert out[2] == f"baseline: {old}"
    assert out[5:] == expected[5:]


def test_selftest_fault_and_unreadable_rows_are_excluded_and_counted(merged, tmp_path, audit, capsys):
    hook(merged, audit, "echo hi")
    hook(merged, audit, "rm -rf /tmp/canary", session=SELFTEST_SESSION, tool_use_id="selftest-canary")
    hook(tmp_path / "missing.json", audit, "echo hi", tool_use_id="toolu_2")
    hook(merged, audit, None, tool_use_id="toolu_3")
    with audit.open("a", encoding="utf-8") as handle:
        handle.write('{torn line\n[]\n{"ts": "2026-10-23T09:00:00"}\n\n')
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert code == 0
    assert out[3] == counts_line(replayed=1, selftest=1, faults=2, unreadable=3)


SKIPPED_OVERRIDES = [
    pytest.param({"args": None}, id="args-null"),
    pytest.param({"args": {"cmd_sha256": "0" * 64, "cmd_len": 1}}, id="cmd-missing"),
    pytest.param({"args": {"cmd": 5, "cmd_sha256": "0" * 64, "cmd_len": 1}}, id="cmd-int"),
    pytest.param({"args": {"cmd": "rm -rf /x", "cmd_len": 9}}, id="cmd-sha256-missing"),
    pytest.param({"args": {"cmd": "rm -rf /x", "cmd_sha256": None, "cmd_len": 9}}, id="cmd-sha256-null"),
    pytest.param({"event": "release"}, id="event-not-decision"),
    pytest.param({"event": None}, id="event-missing"),
]


@pytest.mark.parametrize("overrides", SKIPPED_OVERRIDES)
def test_rows_with_missing_or_malformed_fields_are_skipped_and_counted(merged, audit, capsys, overrides):
    write_rows(
        audit,
        [
            decision_row("2026-10-23T09:00:00+00:00", "echo ok"),
            decision_row("2026-10-23T09:01:00+00:00", "rm -rf /x", **overrides),
        ],
    )
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--against-policy", str(merged))
    assert code == 0
    assert out[3] == counts_line(replayed=1, skipped=1)


@pytest.mark.parametrize("decision", [None, "block", 3])
def test_an_invalid_logged_decision_is_skipped_only_when_it_is_the_baseline(merged, audit, capsys, decision):
    write_rows(
        audit,
        [
            decision_row("2026-10-23T09:00:00+00:00", "echo ok"),
            decision_row("2026-10-23T09:01:00+00:00", "rm -rf /x", decision=decision),
        ],
    )
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert (code, out[3]) == (0, counts_line(replayed=1, skipped=1))
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--against-policy", str(merged))
    assert (code, out[3]) == (0, counts_line(replayed=2))


def test_redacted_and_truncated_rows_are_counted_as_differing_from_the_original(merged, audit, capsys):
    hook_all(merged, audit, ["echo hi", "curl -H x token=abc123 https://x", "echo " + "a" * 2100])
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    assert rows[1]["args"]["cmd"] == "curl -H x token=*** https://x"
    assert len(rows[2]["args"]["cmd"].encode()) == 2048
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert code == 0
    assert out[4] == "stored text differs from the original command (redacted or truncated): 2"


def test_a_match_past_the_stored_2048_bytes_is_invisible_to_replay(merged, audit, capsys):
    hook(merged, audit, "echo " + "a" * 2100 + "; rm -rf /tmp/x")
    assert json.loads(audit.read_text())["decision"] == "deny"
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--against-policy", str(merged))
    assert (code, out[4:6]) == (
        0,
        ["stored text differs from the original command (redacted or truncated): 1", "changed: 0"],
    )
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert out[6] == "deny -> allow (1)"


def test_control_and_unicode_characters_in_printed_fields_are_escaped(merged, audit, capsys):
    command = "rm -rf /tmp/\x1b[31mred\x07/‮evilé"
    rows = [
        decision_row("2026-10-23T09:00:00+00:00", command, agent_id="claude-code:\x1b]0;t\x07", rule_id="x"),
    ]
    write_rows(audit, rows)
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    text = "\n".join(out)
    assert code == 0
    assert "\x1b" not in text and "\x07" not in text and "‮" not in text
    assert out[-2] == (
        "  2026-10-23T09:00:00+00:00  claude-code:\\x1b]0;t\\x07  x -> block-rm-rf  "
        "rm -rf /tmp/\\x1b[31mred\\x07/\\u202eevilé"
    )


def test_changes_are_grouped_by_size_then_name_and_ordered_by_instant(merged, audit, capsys):
    rows = [
        decision_row("2026-10-23T10:00:00+00:00", "rm -rf /later"),
        decision_row("2026-10-23T09:30:00+01:00", "rm -rf /earlier"),
        decision_row("2026-10-23T08:00:00+00:00", "git push --force", decision="deny", rule_id="d"),
        decision_row("2026-10-23T08:01:00+00:00", "echo fine", decision="require_human", rule_id="h"),
        decision_row("2026-10-23T08:02:00+00:00", "echo same"),
    ]
    write_rows(audit, rows)
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert code == 0
    assert out[5:] == [
        "changed: 4",
        "allow -> deny (2)",
        "  2026-10-23T09:30:00+01:00  claude-code:s1  policy default -> block-rm-rf  rm -rf /earlier",
        "  2026-10-23T10:00:00+00:00  claude-code:s1  policy default -> block-rm-rf  rm -rf /later",
        "deny -> require_human (1)",
        "  2026-10-23T08:00:00+00:00  claude-code:s1  d -> gate-force-push  git push --force",
        "require_human -> allow (1)",
        "  2026-10-23T08:01:00+00:00  claude-code:s1  h -> policy default  echo fine",
        "result: OK",
    ]


def test_every_changed_row_is_listed_with_a_160_character_excerpt(merged, audit, capsys):
    rows = [
        decision_row(f"2026-10-23T09:{minute:02d}:00+00:00", f"rm -rf /{minute}" + "a" * 300) for minute in range(30)
    ]
    write_rows(audit, rows)
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert code == 0
    listed = [line for line in out if line.startswith("  ")]
    assert len(listed) == 30
    assert listed[0].endswith("  " + ("rm -rf /0" + "a" * 300)[:160])


def test_missing_audit_file_exits_one_without_a_report(merged, audit, capsys):
    assert replay(capsys, "--policy", str(merged), "--audit", str(audit)) == (
        1,
        [],
        f"replay failed: no audit file at {audit}\n",
    )


def test_default_audit_path_is_the_hook_state_path(merged, isolated_home, capsys, monkeypatch):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    code, out, err = replay(capsys, "--policy", str(merged))
    assert (code, out) == (1, [])
    assert err == f"replay failed: no audit file at {isolated_home}/.local/state/agent-guard/claude-code.jsonl\n"


def test_dangling_symlink_audit_path_exits_one(merged, audit, tmp_path, capsys):
    audit.parent.mkdir()
    audit.symlink_to(tmp_path / "gone.jsonl")
    assert replay(capsys, "--policy", str(merged), "--audit", str(audit))[0] == 1


def test_symlinked_audit_path_is_read_through_and_its_target_is_not_modified(merged, audit, tmp_path, capsys):
    target = tmp_path / "copy.jsonl"
    hook(merged, target, "echo hi")
    before = target.read_bytes()
    audit.parent.mkdir()
    audit.symlink_to(target)
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert (code, out[0], out[3]) == (0, f"audit: {audit}", counts_line(replayed=1))
    assert target.read_bytes() == before


@pytest.mark.parametrize("content", [b"\xff\xfe not utf-8\n", None], ids=["not-utf8", "directory"])
def test_unreadable_audit_path_exits_one(merged, audit, capsys, content):
    if content is None:
        audit.mkdir(parents=True)
    else:
        audit.parent.mkdir()
        audit.write_bytes(content)
    code, out, err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert (code, out) == (1, [])
    assert err.startswith(f"replay failed: audit file {audit} is unreadable: ")


def test_audit_with_no_replayable_rows_exits_one(merged, tmp_path, audit, capsys):
    hook(merged, audit, "echo hi", session=SELFTEST_SESSION, tool_use_id="selftest-benign")
    hook(tmp_path / "missing.json", audit, "echo hi", tool_use_id="toolu_2")
    with audit.open("a", encoding="utf-8") as handle:
        handle.write("{torn\n")
    assert replay(capsys, "--policy", str(merged), "--audit", str(audit)) == (
        1,
        [],
        "replay failed: no decision rows to replay\n",
    )


def test_empty_audit_file_exits_one(merged, audit, capsys):
    audit.parent.mkdir()
    audit.write_text("")
    assert replay(capsys, "--policy", str(merged), "--audit", str(audit))[0] == 1


JUDGE_POLICY = {
    "default": "allow",
    "rules": [{"id": "ask-judge", "decision": "require_human", "tools": ["shell"], "judge": True}],
}


@pytest.mark.parametrize("flag", ["--policy", "--against-policy"])
def test_a_judge_rule_in_either_policy_exits_one(merged, tmp_path, audit, capsys, flag):
    hook(merged, audit, "echo hi")
    judge = write_policy(tmp_path / "judge.json", JUDGE_POLICY)
    argv = {"--policy": str(merged), "--against-policy": str(merged), "--audit": str(audit), flag: str(judge)}
    code, out, err = replay(capsys, *[part for pair in argv.items() for part in pair])
    assert (code, out) == (1, [])
    assert err == f"replay failed: policy {judge} has a judge rule; static replay cannot run the judge\n"


BAD_POLICIES = [
    pytest.param("{not json", id="not-json"),
    pytest.param(json.dumps({"rules": []}), id="no-default"),
    pytest.param(json.dumps({"default": "maybe"}), id="bad-default"),
    pytest.param(json.dumps({"default": "allow", "rules": [{"id": "r", "tools": ["shell"]}]}), id="rule-no-decision"),
    pytest.param(json.dumps(["not", "an", "object"]), id="not-an-object"),
    pytest.param(
        json.dumps({"default": "allow", "rules": [{"decision": "deny", "tools": ["s"], "arg_patterns": ["(?=x)"]}]}),
        id="not-re2",
    ),
    pytest.param(None, id="missing-file"),
]


@pytest.mark.parametrize("text", BAD_POLICIES)
@pytest.mark.parametrize("flag", ["--policy", "--against-policy"])
def test_a_policy_that_fails_to_load_exits_one(merged, tmp_path, audit, capsys, text, flag):
    hook(merged, audit, "echo hi")
    bad = tmp_path / "bad.json"
    if text is not None:
        bad.write_text(text)
    argv = {"--policy": str(merged), "--against-policy": str(merged), "--audit": str(audit), flag: str(bad)}
    code, out, err = replay(capsys, *[part for pair in argv.items() for part in pair])
    assert (code, out) == (1, [])
    assert err.startswith(f"replay failed: policy {bad} failed to load: ")


def test_policy_is_required(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["replay"])
    assert raised.value.code == 2
    assert "--policy" in capsys.readouterr().err


def test_replay_does_not_modify_the_audit_or_policies_or_create_files(old, merged, audit, tmp_path, capsys):
    hook_all(old, audit, ["echo hi", DOCKER_RM])
    past = 1_600_000_000
    for path in (audit, old, merged):
        os.utime(path, (past, past))
    snapshot = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (audit, old, merged)}
    tree = sorted(tmp_path.rglob("*"))
    code, _out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--against-policy", str(old))
    assert code == 0
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (audit, old, merged)} == snapshot
    assert sorted(tmp_path.rglob("*")) == tree


def test_a_stored_command_with_a_lone_surrogate_is_skipped_not_fatal(merged, audit, capsys):
    good = json.dumps(decision_row("2026-10-23T09:00:00+00:00", "echo ok"))
    bad = good.replace("echo ok", "rm -rf \\ud800").replace("09:00", "09:01")
    audit.parent.mkdir()
    audit.write_text(good + "\n" + bad + "\n")
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(audit))
    assert (code, out[3]) == (0, counts_line(replayed=1, skipped=1))


@pytest.fixture
def live(tmp_path) -> Path:
    return hook_policy(tmp_path, "live.json", LIVE_RM_PREFIX)


@pytest.fixture
def logged(merged, audit) -> Path:
    hook_all(merged, audit, ["echo hi", "rm -rf /tmp/x"])
    return audit


def must_block_file(tmp_path: Path, content) -> Path:
    path = tmp_path / "must-block.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


EVASIONS = ["${x:-rm} -rf x", "v=--rm eval '${v#--} -rf x'", "--rm -rf x"]


def test_a_must_block_command_allowed_by_the_candidate_is_a_breach_exit_three(live, logged, tmp_path, capsys):
    battery = must_block_file(tmp_path, ["rm -rf ~", *EVASIONS])
    code, out, err = replay(capsys, "--policy", str(live), "--audit", str(logged), "--must-block", str(battery))
    assert (code, err) == (3, "")
    assert out[-5:] == [
        f"must-block: {battery} (4)",
        "  BREACH  allow  ${x:-rm} -rf x",
        "  BREACH  allow  v=--rm eval '${v#--} -rf x'",
        "  BREACH  allow  --rm -rf x",
        "result: BREACH (3)",
    ]


def test_the_merged_prefix_blocks_the_battery_exit_zero(merged, logged, tmp_path, capsys):
    battery = must_block_file(tmp_path, ["rm -rf ~", *EVASIONS])
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(logged), "--must-block", str(battery))
    assert code == 0
    assert out[-2:] == [f"must-block: {battery} (4)", "result: OK"]


def test_require_human_is_not_a_breach(merged, logged, tmp_path, capsys):
    battery = must_block_file(tmp_path, ["git push --force origin main", "guard install claude-code --uninstall"])
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(logged), "--must-block", str(battery))
    assert (code, out[-1]) == (0, "result: OK")


def test_a_multiline_entry_is_evaluated_as_one_command(merged, logged, tmp_path, capsys):
    battery = must_block_file(tmp_path, ["echo one\nrm -rf /", "echo one\necho two\x1b[2J"])
    code, out, _err = replay(capsys, "--policy", str(merged), "--audit", str(logged), "--must-block", str(battery))
    assert code == 3
    assert out[-3:] == [
        f"must-block: {battery} (2)",
        "  BREACH  allow  echo one\\necho two\\x1b[2J",
        "result: BREACH (1)",
    ]


def test_must_block_is_checked_against_the_candidate_not_the_baseline(live, merged, logged, tmp_path, capsys):
    battery = must_block_file(tmp_path, EVASIONS)
    argv = ["--audit", str(logged), "--must-block", str(battery)]
    assert replay(capsys, "--policy", str(merged), "--against-policy", str(live), *argv)[0] == 0
    assert replay(capsys, "--policy", str(live), "--against-policy", str(merged), *argv)[0] == 3


BAD_MUST_BLOCK = [
    pytest.param({"cmd": "rm -rf /"}, id="object"),
    pytest.param("rm -rf /", id="bare-string"),
    pytest.param([], id="empty-list"),
    pytest.param(["rm -rf /", 5], id="non-string-entry"),
    pytest.param(["rm -rf /", ""], id="empty-entry"),
    pytest.param(["rm -rf /", "  \n"], id="blank-entry"),
    pytest.param('["rm -rf \\ud800"]', id="lone-surrogate"),
]


@pytest.mark.parametrize("content", BAD_MUST_BLOCK)
def test_a_must_block_file_that_is_not_a_non_empty_list_of_commands_exits_one(
    merged, logged, tmp_path, capsys, content
):
    battery = must_block_file(tmp_path, content)
    code, out, err = replay(capsys, "--policy", str(merged), "--audit", str(logged), "--must-block", str(battery))
    assert (code, out) == (1, [])
    assert err.startswith(f"replay failed: must-block file {battery} ")


@pytest.mark.parametrize(
    "content", [None, "{not json", "[" * 100000, b"\xff\xfe"], ids=["missing", "not-json", "deep", "bytes"]
)
def test_an_unreadable_must_block_file_exits_one(merged, logged, tmp_path, capsys, content):
    battery = tmp_path / "must-block.json"
    if isinstance(content, bytes):
        battery.write_bytes(content)
    elif content is not None:
        battery.write_text(content)
    code, out, err = replay(capsys, "--policy", str(merged), "--audit", str(logged), "--must-block", str(battery))
    assert (code, out) == (1, [])
    assert err.startswith(f"replay failed: must-block file {battery} is unreadable: ")


def test_a_bad_must_block_file_fails_before_a_missing_audit_is_reported(merged, audit, tmp_path, capsys):
    battery = must_block_file(tmp_path, [])
    code, _out, err = replay(capsys, "--policy", str(merged), "--audit", str(audit), "--must-block", str(battery))
    assert code == 1
    assert "must-block" in err
