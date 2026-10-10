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
    assert audit.records[0].args == {"payload": ["safe"]}
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
