from __future__ import annotations

import datetime

import pytest

from agent_guard import (
    ApprovalGrant,
    BlockedError,
    Guard,
    MemoryAuditSink,
    MultiAuditSink,
    Policy,
    guarded,
    unresolved_releases,
)


def make_policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "id": "block-danger",
                    "decision": "deny",
                    "tools": ["act"],
                    "arg_patterns": ["danger"],
                    "reason": "no",
                },
                {"id": "gate-all", "decision": "require_human", "tools": ["gate"], "reason": "review"},
            ],
        }
    )


def make_guard(audit=None, approver=None) -> tuple[Guard, MemoryAuditSink]:
    sink = audit if audit is not None else MemoryAuditSink()
    kwargs = {"approver": approver} if approver else {}
    return Guard(make_policy(), audit=sink, agent_id="agent-test", **kwargs), sink


NON_CANONICAL_ARGS = [
    pytest.param({"when": datetime.datetime(2026, 1, 1)}, id="datetime"),
    pytest.param({"blob": b"bytes"}, id="bytes"),
    pytest.param({"ratio": float("nan")}, id="nan"),
    pytest.param({1: "a", "b": 2}, id="mixed-key-types"),
    pytest.param({"items": {1, 2}}, id="set"),
    pytest.param({"text": "\ud800"}, id="lone-surrogate"),
]


@pytest.mark.parametrize("args", NON_CANONICAL_ARGS)
def test_non_canonical_args_are_blocked_and_audited(args):
    guard, audit = make_guard()
    dispatched = []
    with pytest.raises(BlockedError, match="not canonical JSON"):
        guard.call(lambda tool, call_args: dispatched.append(call_args), "act", args)
    assert dispatched == []
    assert len(audit.records) == 1
    record = audit.records[0]
    assert (record.event, record.outcome, record.executed) == ("decision", "blocked", False)
    assert record.rule_id == "args-not-canonical"
    assert record.args == {}


@pytest.mark.parametrize("args", NON_CANONICAL_ARGS)
def test_decide_fails_closed_on_non_canonical_args(args):
    guard, _ = make_guard()
    allowed, verdict = guard.decide("act", args)
    assert allowed is False
    assert verdict.rule_id == "args-not-canonical"


def test_dispatch_and_audit_see_the_same_canonical_arguments():
    guard, audit = make_guard()
    seen = []
    guard.call(lambda tool, args: seen.append(args), "act", {"pair": (1, 2), "nested": {1: "x"}})
    expected = {"pair": [1, 2], "nested": {"1": "x"}}
    assert seen == [expected]
    assert audit.records[0].args == audit.records[1].args == expected


def test_deepcopy_override_cannot_alias_the_frozen_arguments():
    class Sticky(list):
        def __deepcopy__(self, memo):
            return self

    sticky = Sticky(["ok"])

    class MutatingSink(MemoryAuditSink):
        def write(self, record):
            if record.event == "release":
                sticky.append("evil")
            super().write(record)

    guard, audit = make_guard(MutatingSink())
    seen = []
    guard.call(lambda tool, args: seen.append(args), "act", {"items": sticky})
    assert seen == [{"items": ["ok"]}]
    assert audit.records[0].args == {"items": ["ok"]}


def test_decorator_policy_and_audit_cover_positional_arguments():
    guard, audit = make_guard()

    @guarded(guard, "act")
    def act(payload, flag=False):
        return list(payload)

    assert act(["safe"]) == ["safe"]
    assert audit.records[0].args == {"payload": ["safe"], "flag": False}
    with pytest.raises(BlockedError):
        act(["danger"])
    assert audit.records[-1].rule_id == "block-danger"


def test_decorator_dispatches_the_approved_snapshot_not_the_callers_object():
    original = ["safe"]

    def approver(request):
        original.append("evil")
        return ApprovalGrant(request.call_id, request.call_digest)

    guard, audit = make_guard(approver=approver)

    @guarded(guard, "gate")
    def gate(payload):
        return list(payload)

    assert gate(original) == ["safe"]
    assert audit.records[0].args == {"payload": ["safe"]}
    assert original == ["safe", "evil"]


def test_decorator_binds_var_positional_and_var_keyword():
    guard, audit = make_guard()

    @guarded(guard, "act")
    def act(first, *rest, **options):
        return first, rest, options

    assert act(1, 2, 3, mode="x") == (1, (2, 3), {"mode": "x"})
    assert audit.records[0].args == {"first": 1, "rest": [2, 3], "mode": "x"}


def test_decorator_rejects_keyword_that_shadows_positional_only_parameter():
    guard, audit = make_guard()

    @guarded(guard, "act")
    def act(a, /, **options):
        return a

    with pytest.raises(TypeError, match="collide"):
        act(1, a=2)
    assert audit.records == []


def test_decorator_mutable_out_parameter_is_not_written_through():
    guard, _ = make_guard()
    buffer: list[int] = []

    @guarded(guard, "act")
    def fill(buf):
        buf.append(1)

    fill(buf=buffer)
    assert buffer == []


def test_release_write_failure_closes_the_release_as_not_dispatched():
    local = MemoryAuditSink()

    class DownRemote:
        def write(self, record):
            raise OSError("remote down")

    guard, _ = make_guard(MultiAuditSink(local, DownRemote()))
    dispatched = []
    with pytest.raises(RuntimeError, match="1 of 2 audit sink"):
        guard.call(lambda tool, args: dispatched.append(args), "act", {"q": 1})
    assert dispatched == []
    assert [(r.event, r.outcome, r.executed) for r in local.records] == [
        ("release", "pending", True),
        ("terminal", "not_dispatched", False),
    ]
    assert unresolved_releases(local.records) == []


def test_terminal_audit_failure_keeps_the_dispatch_errors_own_cause():
    root = KeyError("root cause")
    audit_failure = OSError("terminal audit unavailable")

    class Sink:
        def write(self, record):
            if record.event == "terminal":
                raise audit_failure

    guard, _ = make_guard(Sink())

    def dispatch(tool, args):
        raise RuntimeError("tool failed") from root

    with pytest.raises(RuntimeError, match="tool failed") as caught:
        guard.call(dispatch, "act", {"q": 1})
    assert caught.value.__cause__ is audit_failure
    assert audit_failure.__cause__ is root


def test_operator_signal_from_terminal_sink_outranks_an_ordinary_dispatch_error():
    class Sink:
        def write(self, record):
            if record.event == "terminal":
                raise SystemExit(9)

    guard, _ = make_guard(Sink())

    def dispatch(tool, args):
        raise ValueError("tool failed")

    with pytest.raises(SystemExit) as caught:
        guard.call(dispatch, "act", {"q": 1})
    assert caught.value.code == 9


def test_decorator_binds_default_values_so_policy_sees_what_the_tool_runs():
    policy = Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {"id": "no-force", "decision": "deny", "tools": ["push"], "arg_patterns": ["--force"], "reason": "no"}
            ],
        }
    )
    audit = MemoryAuditSink()
    guard = Guard(policy, audit=audit, agent_id="agent-test")
    ran = []

    @guarded(guard, "push")
    def push(branch, mode="--force"):
        ran.append((branch, mode))

    with pytest.raises(BlockedError):
        push("main")
    assert ran == []
    assert audit.records[0].args == {"branch": "main", "mode": "--force"}


def test_decorator_blocks_a_default_that_is_not_json():
    guard, audit = make_guard()

    sentinel = object()

    @guarded(guard, "act")
    def act(value, marker=sentinel):
        return value

    with pytest.raises(BlockedError, match="not canonical JSON"):
        act(1)
    assert audit.records[0].rule_id == "args-not-canonical"


def test_decorator_on_a_method_fails_closed_because_self_is_not_json():
    guard, audit = make_guard()

    class Service:
        @guarded(guard, "act")
        def run(self, value):
            return value

    with pytest.raises(BlockedError, match="not canonical JSON"):
        Service().run(1)
    assert audit.records[0].executed is False


def nested(depth: int) -> dict:
    root: dict = {}
    cursor = root
    for _ in range(depth):
        cursor["k"] = {}
        cursor = cursor["k"]
    return root


def test_deeply_nested_args_are_blocked_and_audited_not_crashed():
    guard, audit = make_guard()
    dispatched = []
    with pytest.raises(BlockedError, match="nest deeper"):
        guard.call(lambda tool, args: dispatched.append(args), "act", {"n": nested(600)})
    assert dispatched == []
    assert [(r.event, r.outcome, r.args) for r in audit.records] == [("decision", "blocked", {})]


def test_nesting_at_the_limit_is_accepted_and_one_past_it_is_not():
    guard, _ = make_guard()
    assert guard.decide("act", {"n": nested(62)})[0] is True
    assert guard.decide("act", {"n": nested(64)})[0] is False


def test_judge_receives_a_detached_copy_and_cannot_change_the_dispatched_arguments():
    from agent_guard import CallableJudge, Decision

    policy = Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "id": "judge-me",
                    "decision": "allow",
                    "tools": ["act"],
                    "judge": True,
                    "judge_ceiling": "allow",
                    "reason": "judged",
                }
            ],
        }
    )

    consulted = []

    def mutating_judge(request):
        consulted.append(request)
        request.args["payload"] = "danger"
        return Decision.ALLOW, "ok"

    audit = MemoryAuditSink()
    guard = Guard(policy, audit=audit, agent_id="agent-test", judge=CallableJudge(mutating_judge))
    seen = []
    guard.call(lambda tool, args: seen.append(args), "act", {"payload": "safe"})
    assert len(consulted) == 1
    assert seen == [{"payload": "safe"}]
    assert audit.records[0].args == {"payload": "safe"}


def test_record_never_stores_arguments_rejected_as_non_canonical():
    guard, audit = make_guard()
    _, verdict = guard.decide("act", {"when": datetime.datetime(2026, 1, 1)})
    guard.record("act", {"when": datetime.datetime(2026, 1, 1)}, verdict, executed=False)
    assert audit.records[0].args == {}


def test_audit_error_that_is_the_dispatch_error_does_not_create_a_cause_cycle():
    shared = OSError("shared")

    class Sink:
        def write(self, record):
            if record.event == "terminal":
                raise shared

    guard, _ = make_guard(Sink())

    def dispatch(tool, args):
        raise shared

    with pytest.raises(OSError) as caught:
        guard.call(dispatch, "act", {"q": 1})
    assert caught.value is shared
    assert shared.__cause__ is None


def test_reused_audit_error_does_not_leak_causes_between_calls():
    reused = OSError("sink down")

    class Sink:
        def write(self, record):
            if record.event == "terminal":
                raise reused

    guard, _ = make_guard(Sink())

    def dispatch(tool, args):
        raise ValueError("tool failed")

    for _ in range(2):
        with pytest.raises(ValueError) as caught:
            guard.call(dispatch, "act", {"q": 1})
        assert caught.value.__cause__ is reused
    assert reused.__cause__ is None or reused.__cause__.__cause__ is None


def test_mcp_proxy_denies_nan_arguments_and_records_empty_args():
    from agent_guard import mcp_handle_line

    guard, audit = make_guard()
    line = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"act","arguments":{"x":NaN}}}'
    forward, reply = mcp_handle_line(line, guard)
    assert forward is None
    assert "not canonical JSON" in reply
    assert audit.records[0].rule_id == "args-not-canonical"
    assert audit.records[0].args == {}


def test_policy_rule_named_like_the_internal_marker_cannot_blank_the_audit_arguments():
    policy = Policy.from_dict(
        {
            "default": "deny",
            "rules": [{"id": "args-not-canonical", "decision": "allow", "tools": ["pay"], "reason": "ok"}],
        }
    )
    audit = MemoryAuditSink()
    guard = Guard(policy, audit=audit, agent_id="agent-test")
    guard.call(lambda tool, args: "paid", "pay", {"to": "attacker", "amount": 1000000})
    assert [record.args for record in audit.records] == [{"to": "attacker", "amount": 1000000}] * 2
    _, verdict = guard.decide("pay", {"to": "attacker"})
    guard.record("pay", {"to": "attacker"}, verdict, executed=True)
    assert audit.records[-1].args == {"to": "attacker"}


def test_decorator_allows_a_keyword_named_like_an_empty_var_positional():
    guard, audit = make_guard()

    @guarded(guard, "act")
    def act(first, *rest, **options):
        return first, rest, options

    assert act(1, rest="safe") == (1, (), {"rest": "safe"})
    assert audit.records[0].args == {"first": 1, "rest": "safe"}


def test_decorator_rejects_a_partial_that_hides_positional_arguments():
    from functools import partial

    guard, _ = make_guard()

    def tool(command, flag=False):
        return command

    with pytest.raises(TypeError, match="functools.partial"):
        guarded(guard, "act")(partial(tool, "rm -rf /"))
    assert guarded(guard, "act")(partial(tool, flag=True))(command="ls") == "ls"


def test_skipped_chaining_still_shows_the_audit_failure_in_the_traceback():
    import traceback

    holder: list[BaseException] = []

    class SinkError(Exception):
        pass

    class Sink:
        def write(self, record):
            if record.event == "terminal":
                raise SinkError("wrapped terminal failure") from holder[0]

    guard, _ = make_guard(Sink())

    def dispatch(tool, args):
        holder.append(ValueError("tool failed"))
        raise holder[0]

    with pytest.raises(ValueError) as caught:
        guard.call(dispatch, "act", {"q": 1})
    assert "wrapped terminal failure" in "".join(traceback.format_exception(caught.value))


def test_mcp_proxy_rejects_a_message_too_deep_to_parse():
    from agent_guard import mcp_handle_line

    guard, audit = make_guard()
    forward, reply = mcp_handle_line("[" * 100_000 + "]" * 100_000, guard)
    assert forward is None
    assert "nests too deeply" in reply


def test_check_cli_rejects_a_payload_too_deep_to_parse(monkeypatch, capsys):
    import io

    from agent_guard.cli import main

    monkeypatch.setattr("sys.stdin", io.StringIO("[" * 100_000 + "]" * 100_000))
    assert main(["check"]) == 1
    assert "malformed JSON payload" in capsys.readouterr().err
