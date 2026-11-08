from __future__ import annotations

import json
from dataclasses import replace

from agent_guard import AuditRecord, JsonlAuditSink, MemoryAuditSink, SigningAuditSink
from agent_guard.audit import _signable_body, record_dict, verify_record

SECRET = b"audit-v2-test-secret"

V2 = {
    "trace_id": "trace-1",
    "task_root": "root-1",
    "grant_hash": "grant-1",
    "tenant_id": "tenant-1",
    "principal": "alice",
    "actor": "agent-a",
    "parent_actor": "agent-root",
    "host": "host-1",
}


def _record(**extra) -> AuditRecord:
    return AuditRecord(
        ts="t",
        agent_id="a",
        tool="x",
        args={"k": 1},
        decision="allow",
        reason="r",
        rule_id=None,
        executed=True,
        event="release",
        call_id="c",
        **extra,
    )


def test_record_without_v2_fields_keeps_exact_signed_bytes():
    expected = (
        b'{"agent_id":"a","args":{"k":1},"call_id":"c","decision":"allow","error":null,'
        b'"event":"release","executed":true,"reason":"r","rule_id":null,"sig":null,"tool":"x","ts":"t"}'
    )
    assert _signable_body(_record()) == expected
    assert _record().schema_version is None


def test_record_without_v2_fields_keeps_exact_wire_form(tmp_path):
    path = tmp_path / "audit.jsonl"
    JsonlAuditSink(path).write(_record())
    assert path.read_text() == (
        '{"ts": "t", "agent_id": "a", "tool": "x", "args": {"k": 1}, "decision": "allow", "reason": "r", '
        '"rule_id": null, "executed": true, "sig": null, "error": null, "event": "release", "call_id": "c", '
        '"call_digest": null, "outcome": null}\n'
    )


def test_any_v2_field_stamps_schema_version_2():
    for name, value in V2.items():
        assert _record(**{name: value}).schema_version == 2


def test_v2_fields_round_trip_through_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    record = _record(**V2)
    JsonlAuditSink(path).write(record)
    row = json.loads(path.read_text())
    assert row["schema_version"] == 2
    assert AuditRecord(**row) == record


def test_v2_fields_omitted_from_wire_when_unset():
    payload = record_dict(_record(trace_id="trace-1"))
    assert payload["trace_id"] == "trace-1"
    assert payload["schema_version"] == 2
    assert "tenant_id" not in payload


def test_signature_covers_every_v2_field_and_schema_version():
    sink = MemoryAuditSink()
    SigningAuditSink(sink, SECRET).write(_record(**V2))
    signed = sink.records[0]
    assert verify_record(signed, SECRET)
    for name in V2:
        assert not verify_record(replace(signed, **{name: "tampered"}), SECRET)
        assert not verify_record(replace(signed, **{name: None}), SECRET)
    assert not verify_record(replace(signed, schema_version=3), SECRET)


def test_v1_signature_still_verifies_and_new_field_invalidates_it():
    sink = MemoryAuditSink()
    SigningAuditSink(sink, SECRET).write(_record())
    signed = sink.records[0]
    assert verify_record(signed, SECRET)
    assert not verify_record(replace(signed, tenant_id="tenant-1"), SECRET)
