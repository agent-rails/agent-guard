from __future__ import annotations

import os
import tempfile
from dataclasses import replace

import pytest

from agent_guard.alert_sink import (
    REPORT_ONLY,
    REVOKE_TASK,
    SUSPEND,
    AlertSink,
    load_writer_key,
    sign_alert,
    verify_alert,
)
from agent_guard.detect import (
    ALERT_KINDS,
    FIRST_TOOL_USE,
    OUTSIDE_USUAL_HOURS,
    RATE_ABOVE_BASELINE,
    Alert,
)
from agentguard_identity.credentials import CredentialInjector, MemoryIssuanceStore

KEY = b"k" * 32
WRITER = "detector-1"
NOW = 1_000_000
MAX_AGE = 300


def _sign(alert, key=KEY, writer=WRITER, issued_at=NOW, alert_id=None):
    return sign_alert(alert, key, writer, issued_at, alert_id)


class _Store:
    def get(self, name):
        raise KeyError(name)


class _Minter:
    def mint(self, *args):
        raise AssertionError("not used")


def _injector(tmp_path) -> CredentialInjector:
    return CredentialInjector(
        store=_Store(),
        minter=_Minter(),
        issuance=MemoryIssuanceStore(),
        secret_names={},
        executor_key_id="executor",
        audience="api",
        max_ttl=30,
        clock=lambda: 0.0,
        state_dir=tmp_path / "broker-state",
        releaser="oncall",
    )


class RecordingRevocations:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def revoke_task(self, task_root, reason, actor):
        self.calls.append((task_root, reason, actor))


def _alert(kind=FIRST_TOOL_USE, task_roots=("root-1",)) -> Alert:
    return Alert(kind, "deployer", "t1", "2026-11-02T03:00:00+00:00", "tool 'x'", 1, task_roots)


def _sink(tmp_path, policy=None, revocations=None, now=NOW) -> AlertSink:
    policy = policy or {
        FIRST_TOOL_USE: SUSPEND,
        "first_resource_use": REPORT_ONLY,
        RATE_ABOVE_BASELINE: REVOKE_TASK,
        OUTSIDE_USUAL_HOURS: SUSPEND,
    }
    return AlertSink(
        KEY,
        WRITER,
        _injector(tmp_path),
        policy,
        revocations or RecordingRevocations(),
        state_dir=tmp_path / "broker-state",
        clock=lambda: float(now),
        max_age=MAX_AGE,
    )


def test_unauthenticated_alert_is_refused(tmp_path):
    sink = _sink(tmp_path)
    outcome = sink.handle(_alert())
    assert (outcome.applied, outcome.reason) == (False, "unauthenticated")
    assert not sink._injector.suspended


def test_bad_mac_is_refused(tmp_path):
    sink = _sink(tmp_path)
    forged = _sign(_alert(), b"x" * 32, WRITER)
    assert sink.handle(forged).reason == "bad_mac"
    garbage = replace(_sign(_alert(), KEY, WRITER), mac="!!!not-base64")
    assert sink.handle(garbage).reason == "bad_mac"
    assert not sink._injector.suspended


def test_tampered_alert_is_refused(tmp_path):
    sink = _sink(tmp_path)
    signed = _sign(_alert())
    tampered = replace(signed, alert=replace(signed.alert, kind=OUTSIDE_USUAL_HOURS))
    assert sink.handle(tampered).reason == "bad_mac"
    assert not sink._injector.suspended


def test_other_writer_id_is_refused_even_with_valid_mac(tmp_path):
    sink = _sink(tmp_path)
    assert sink.handle(_sign(_alert(), KEY, "agent-self")).reason == "bad_mac"
    assert not sink._injector.suspended


def test_valid_alert_suspends_with_writer_as_actor(tmp_path):
    sink = _sink(tmp_path)
    outcome = sink.handle(_sign(_alert(), KEY, WRITER))
    assert (outcome.action, outcome.applied) == (SUSPEND, True)
    assert sink._injector.suspended
    state = (tmp_path / "broker-state" / "suspended.json").read_text()
    assert f'"actor": "{WRITER}"' in state
    assert "first_tool_use persona=deployer" in state


def test_agent_identity_cannot_clear_suspension(tmp_path):
    sink = _sink(tmp_path)
    sink.handle(_sign(_alert(), KEY, WRITER))
    for identity in ("deployer", "agent", WRITER, ""):
        with pytest.raises(PermissionError):
            sink._injector.resume(identity)
    assert sink._injector.suspended
    assert not hasattr(sink, "resume")
    sink._injector.resume("oncall")
    assert not sink._injector.suspended


def test_revoke_task_policy_calls_writer_for_each_task_root(tmp_path):
    revocations = RecordingRevocations()
    sink = _sink(tmp_path, revocations=revocations)
    outcome = sink.handle(_sign(_alert(RATE_ABOVE_BASELINE, ("root-1", "root-2")), KEY, WRITER))
    assert (outcome.action, outcome.applied) == (REVOKE_TASK, True)
    assert [call[0] for call in revocations.calls] == ["root-1", "root-2"]
    assert all(call[2] == WRITER for call in revocations.calls)
    assert not sink._injector.suspended


def test_revoke_task_without_task_root_is_refused(tmp_path):
    revocations = RecordingRevocations()
    sink = _sink(tmp_path, revocations=revocations)
    outcome = sink.handle(_sign(_alert(RATE_ABOVE_BASELINE, ()), KEY, WRITER))
    assert (outcome.applied, outcome.reason) == (False, "no_task_root")
    assert revocations.calls == []


def test_report_only_changes_nothing(tmp_path):
    revocations = RecordingRevocations()
    sink = _sink(tmp_path, revocations=revocations)
    outcome = sink.handle(_sign(_alert("first_resource_use"), KEY, WRITER))
    assert (outcome.applied, outcome.reason) == (False, "report_only")
    assert not sink._injector.suspended
    assert revocations.calls == []


def test_policy_must_cover_every_kind_with_known_actions(tmp_path):
    injector = _injector(tmp_path)
    with pytest.raises(ValueError):
        AlertSink(KEY, WRITER, injector, {FIRST_TOOL_USE: SUSPEND}, state_dir=tmp_path / "s", clock=float, max_age=1)
    with pytest.raises(ValueError):
        AlertSink(
            KEY,
            WRITER,
            injector,
            dict.fromkeys(ALERT_KINDS, "delete_everything"),
            state_dir=tmp_path / "s",
            clock=float,
            max_age=1,
        )
    with pytest.raises(ValueError):
        AlertSink(
            KEY,
            WRITER,
            injector,
            dict.fromkeys(ALERT_KINDS, REVOKE_TASK),
            state_dir=tmp_path / "s",
            clock=float,
            max_age=1,
        )


def test_short_key_refused(tmp_path):
    with pytest.raises(ValueError):
        AlertSink(
            b"short",
            WRITER,
            _injector(tmp_path),
            dict.fromkeys(ALERT_KINDS, SUSPEND),
            state_dir=tmp_path / "s",
            clock=float,
            max_age=1,
        )


def test_verify_alert_round_trip():
    signed = _sign(_alert())
    assert verify_alert(signed, KEY)
    assert not verify_alert(signed, b"y" * 32)


def _key_file(directory, mode=0o600, content=KEY):
    path = directory / "writer.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, mode)
    os.write(fd, content)
    os.close(fd)
    os.chmod(path, mode)
    return path


def test_load_writer_key_reads_private_file(tmp_path):
    assert load_writer_key(_key_file(tmp_path)) == KEY


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_load_writer_key_refuses_loose_permissions(tmp_path, mode):
    with pytest.raises(ValueError, match="0600"):
        load_writer_key(_key_file(tmp_path, mode))


def test_load_writer_key_refuses_symlink(tmp_path):
    target = _key_file(tmp_path)
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        load_writer_key(link)


def test_load_writer_key_refuses_short_key_and_directory(tmp_path):
    with pytest.raises(ValueError, match="at least"):
        load_writer_key(_key_file(tmp_path, content=b"tiny"))
    with pytest.raises(ValueError):
        load_writer_key(tempfile.mkdtemp())


def test_load_writer_key_refuses_missing_file(tmp_path):
    with pytest.raises(ValueError):
        load_writer_key(tmp_path / "absent.key")


def test_replayed_alert_cannot_resuspend_after_release(tmp_path):
    sink = _sink(tmp_path)
    signed = _sign(_alert())
    assert sink.handle(signed).applied
    sink._injector.resume("oncall")
    assert not sink._injector.suspended
    outcome = sink.handle(signed)
    assert (outcome.applied, outcome.reason) == (False, "replayed")
    assert not sink._injector.suspended


def test_replay_is_refused_by_a_new_sink_instance(tmp_path):
    _sink(tmp_path).handle(_sign(_alert(), alert_id="a1"))
    fresh = _sink(tmp_path)
    fresh._injector.resume("oncall")
    assert fresh.handle(_sign(_alert(), alert_id="a1")).reason == "replayed"
    assert not fresh._injector.suspended


def test_distinct_alert_ids_are_each_applied(tmp_path):
    sink = _sink(tmp_path)
    assert sink.handle(_sign(_alert(), alert_id="a1")).applied
    sink._injector.resume("oncall")
    assert sink.handle(_sign(_alert(), alert_id="a2")).applied


def test_stale_alert_is_refused(tmp_path):
    sink = _sink(tmp_path)
    outcome = sink.handle(_sign(_alert(), issued_at=NOW - MAX_AGE - 1))
    assert (outcome.applied, outcome.reason) == (False, "stale")
    assert not sink._injector.suspended


def test_alert_at_max_age_is_accepted(tmp_path):
    assert _sink(tmp_path).handle(_sign(_alert(), issued_at=NOW - MAX_AGE)).applied


def test_future_dated_alert_is_refused(tmp_path):
    outcome = _sink(tmp_path).handle(_sign(_alert(), issued_at=NOW + 3600))
    assert (outcome.applied, outcome.reason) == (False, "stale")


def test_issued_at_and_alert_id_are_authenticated(tmp_path):
    sink = _sink(tmp_path)
    signed = _sign(_alert(), alert_id="a1")
    assert sink.handle(replace(signed, alert_id="a2")).reason == "bad_mac"
    assert sink.handle(replace(signed, issued_at=NOW + 1)).reason == "bad_mac"
    assert not sink._injector.suspended


def test_refused_alerts_do_not_consume_their_id(tmp_path):
    sink = _sink(tmp_path)
    assert sink.handle(replace(_sign(_alert(), alert_id="a1"), mac="AAAA")).reason == "bad_mac"
    assert sink.handle(_sign(_alert(), alert_id="a1")).applied


def test_seen_state_is_pruned_after_max_age(tmp_path):
    first = _sink(tmp_path)
    first.handle(_sign(_alert(), alert_id="old"))
    later = _sink(tmp_path, now=NOW + 10 * MAX_AGE)
    later.handle(_sign(_alert(), issued_at=NOW + 10 * MAX_AGE, alert_id="new"))
    seen = (tmp_path / "broker-state" / "seen-alerts.jsonl").read_text()
    assert "old" not in seen and "new" in seen


def test_corrupt_seen_state_refuses_alerts(tmp_path):
    sink = _sink(tmp_path)
    (tmp_path / "broker-state" / "seen-alerts.jsonl").write_text("not json\n")
    outcome = sink.handle(_sign(_alert()))
    assert (outcome.applied, outcome.reason) == (False, "seen_state_unreadable")
    assert not sink._injector.suspended


def test_symlinked_seen_state_refuses_alerts(tmp_path):
    sink = _sink(tmp_path)
    target = tmp_path / "elsewhere"
    target.write_text("")
    (tmp_path / "broker-state" / "seen-alerts.jsonl").symlink_to(target)
    assert sink.handle(_sign(_alert())).reason == "seen_state_unreadable"


def test_suspend_reason_escapes_control_characters(tmp_path):
    sink = _sink(tmp_path)
    hostile = replace(_alert(), persona="p\x1b[31m\nforged", detail="d\x07")
    sink.handle(_sign(hostile))
    state = (tmp_path / "broker-state" / "suspended.json").read_text()
    assert "\\x1b" in state and "\\x07" in state


def test_load_writer_key_refuses_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "writer.key"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError, match="regular file"):
        load_writer_key(fifo)
