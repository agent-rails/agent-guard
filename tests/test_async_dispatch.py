from __future__ import annotations

import asyncio
import gc
import warnings
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from agent_guard import AsyncDispatchError, Guard, MemoryAuditSink, Policy, guarded, unresolved_releases


def make_guard() -> tuple[Guard, MemoryAuditSink]:
    audit = MemoryAuditSink()
    policy = Policy.from_dict({"default": "allow", "rules": []})
    return Guard(policy, audit=audit, agent_id="probe"), audit


def test_async_dispatch_is_rejected_and_never_audited_as_returned():
    guard, audit = make_guard()
    side_effects = []

    async def async_dispatch(tool, args):
        side_effects.append(tool)
        raise RuntimeError("tool failed")

    with pytest.raises(AsyncDispatchError, match="coroutine was closed without running"):
        guard.call(async_dispatch, "shell", {"cmd": "echo hi"})
    assert side_effects == []
    assert [(r.event, r.outcome, r.executed) for r in audit.records] == [
        ("release", "pending", True),
        ("terminal", "raised", True),
    ]
    assert "returned an async result" in audit.records[-1].error
    assert unresolved_releases(audit.records) == []


def test_rejected_coroutine_is_closed_so_python_emits_no_never_awaited_warning():
    guard, _ = make_guard()

    async def async_dispatch(tool, args):
        return "unreachable"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(AsyncDispatchError):
            guard.call(async_dispatch, "shell", {})
        gc.collect()
    assert [w for w in caught if issubclass(w.category, RuntimeWarning)] == []


def test_non_coroutine_awaitable_is_recorded_as_unknown_outcome_and_left_alone():
    guard, audit = make_guard()

    class Pending:
        closed = False

        def __await__(self):
            yield

        def close(self):
            Pending.closed = True

    with pytest.raises(AsyncDispatchError, match="side-effect outcome unknown"):
        guard.call(lambda tool, args: Pending(), "shell", {})
    assert Pending.closed is False
    assert audit.records[-1].outcome == "unknown"
    assert audit.records[-1].executed is True


def test_running_task_is_not_cancelled_and_is_recorded_as_unknown():
    guard, audit = make_guard()
    ran = []

    async def scenario():
        async def work():
            ran.append("started")
            await asyncio.sleep(0)
            ran.append("finished")

        with pytest.raises(AsyncDispatchError):
            guard.call(lambda tool, args: asyncio.ensure_future(work()), "shell", {})
        await asyncio.sleep(0.01)

    asyncio.run(scenario())
    assert ran == ["started", "finished"]
    assert audit.records[-1].outcome == "unknown"


def test_decorator_and_wrap_reject_async_tool_functions():
    guard, audit = make_guard()

    @guarded(guard, "act")
    async def act(payload):
        return payload

    with pytest.raises(AsyncDispatchError):
        act(payload=1)

    async def async_dispatch(tool, args):
        return "unreachable"

    with pytest.raises(AsyncDispatchError):
        guard.wrap(async_dispatch)("shell", {})
    assert [r.outcome for r in audit.records if r.event == "terminal"] == ["raised", "raised"]


def test_sync_dispatch_returning_a_plain_value_is_unaffected():
    guard, audit = make_guard()
    assert guard.call(lambda tool, args: "ok", "shell", {}) == "ok"
    assert audit.records[-1].outcome == "returned"


def test_async_generator_is_rejected_and_recorded_as_unknown():
    guard, audit = make_guard()
    started = []

    async def stream(tool, args):
        started.append(tool)
        yield 1

    with pytest.raises(AsyncDispatchError, match="async result"):
        guard.call(stream, "shell", {})
    assert started == []
    assert [(r.event, r.outcome) for r in audit.records] == [("release", "pending"), ("terminal", "unknown")]
    assert unresolved_releases(audit.records) == []


def test_decorated_async_generator_function_is_rejected():
    guard, audit = make_guard()

    @guarded(guard, "act")
    async def act(payload):
        yield payload

    with pytest.raises(AsyncDispatchError):
        act(payload=1)
    assert audit.records[-1].outcome == "unknown"


def test_async_iterator_object_and_async_iterable_are_ordinary_lazy_values():
    guard, audit = make_guard()

    class Stream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    class Iterable:
        def __aiter__(self):
            return Stream()

    for value in (Stream(), Iterable()):
        assert guard.call(lambda tool, args, value=value: value, "shell", {}) is value
        assert audit.records[-1].outcome == "returned"


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(MagicMock, id="MagicMock"),
        pytest.param(AsyncMock, id="AsyncMock"),
        pytest.param(Mock, id="Mock"),
        pytest.param(lambda: MagicMock(spec=dict), id="MagicMock-spec"),
        pytest.param(lambda: {"ok": True}, id="dict"),
        pytest.param(lambda: None, id="none"),
    ],
)
def test_ordinary_return_values_including_test_doubles_are_recorded_as_returned(factory):
    guard, audit = make_guard()
    value = factory()
    assert guard.call(lambda tool, args: value, "shell", {}) is value
    assert audit.records[-1].outcome == "returned"


def test_result_that_cannot_be_classified_is_recorded_as_unknown_not_as_a_dispatch_failure():
    guard, audit = make_guard()
    landed = []

    class Hostile:
        @property
        def __class__(self):
            raise RuntimeError("cannot inspect")

    def dispatch(tool, args):
        landed.append(tool)
        return Hostile()

    with pytest.raises(AsyncDispatchError) as caught:
        guard.call(dispatch, "shell", {})
    assert landed == ["shell"]
    assert audit.records[-1].outcome == "unknown"
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_synchronous_generator_remains_a_returned_lazy_result():
    guard, audit = make_guard()

    def numbers(tool, args):
        yield 1

    result = guard.call(numbers, "shell", {})
    assert list(result) == [1]
    assert audit.records[-1].outcome == "returned"
