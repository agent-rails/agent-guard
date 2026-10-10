from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
from dataclasses import asdict

from agent_guard import AuditRecord, Guard, MemoryAuditSink, Policy, SigningAuditSink, unresolved_releases
from agent_guard.audit import verify_record

SECRET = b"lifecycle-test-secret"


def _policy() -> Policy:
    return Policy.from_dict({"default": "allow", "rules": []})


def test_process_death_after_release_leaves_reconcilable_signed_event(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    code = """
import os, sys
from agent_guard import Guard, JsonlAuditSink, Policy, SigningAuditSink
policy = Policy.from_dict({"default": "allow", "rules": []})
guard = Guard(policy, audit=SigningAuditSink(JsonlAuditSink(sys.argv[1]), b"lifecycle-test-secret"), agent_id="e2e")
guard.call(lambda tool, args: os._exit(23), "shell", {"cmd": "side-effect then abrupt process death"})
"""
    result = subprocess.run([sys.executable, "-c", code, str(audit_path)], check=False)
    assert result.returncode == 23

    rows = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert len(rows) == 1
    record = AuditRecord(**rows[0])
    assert record.event == "release"
    assert record.outcome == "pending"
    assert record.executed is True
    assert verify_record(record, SECRET)
    assert unresolved_releases([record]) == [record]


def test_terminal_record_closes_release_and_binds_identical_call():
    sink = MemoryAuditSink()
    guard = Guard(_policy(), audit=SigningAuditSink(sink, SECRET), agent_id="agent-1")
    assert guard.call(lambda tool, args: "ok", "shell", {"cmd": "echo ok"}) == "ok"
    assert [record.event for record in sink.records] == ["release", "terminal"]
    assert sink.records[0].call_id == sink.records[1].call_id
    assert sink.records[0].call_digest == sink.records[1].call_digest
    assert all(verify_record(record, SECRET) for record in sink.records)
    assert unresolved_releases(sink.records) == []
    mismatched_terminal = AuditRecord(**{**asdict(sink.records[1]), "call_digest": "f" * 64})
    assert unresolved_releases([sink.records[0], mismatched_terminal]) == [sink.records[0]]
    malformed_terminal = AuditRecord(**{**asdict(sink.records[1]), "outcome": "pending"})
    assert unresolved_releases([sink.records[0], malformed_terminal]) == [sink.records[0]]
    changed = AuditRecord(**{**asdict(sink.records[0]), "call_digest": "0" * 64})
    assert not verify_record(changed, SECRET)


def test_dispatch_mutation_does_not_rewrite_audited_approved_arguments():
    sink = MemoryAuditSink()

    def mutating_dispatch(tool, args):
        args["cmd"] = "mutated after release"
        return "ok"

    guard = Guard(_policy(), audit=sink, agent_id="agent-1")
    guard.call(mutating_dispatch, "shell", {"cmd": "echo approved"})
    assert sink.records[0].args == sink.records[1].args == {"cmd": "echo approved"}
    assert sink.records[0].call_digest == sink.records[1].call_digest


def test_legacy_record_signature_shape_remains_unchanged():
    from agent_guard.audit import build_record
    from agent_guard.decision import Decision, Verdict

    record = build_record("agent-1", "shell", {"cmd": "echo ok"}, Verdict(Decision.ALLOW, "default"), False)
    legacy_fields = asdict(record)
    for field in ("event", "call_id", "call_digest", "outcome"):
        legacy_fields.pop(field)
    legacy_body = json.dumps(legacy_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    legacy_sig = base64.urlsafe_b64encode(hmac.new(SECRET, legacy_body, hashlib.sha256).digest()).decode()
    # Simulate loading a pre-lifecycle JSON record which has none of the new fields.
    legacy_fields["sig"] = legacy_sig
    signed = AuditRecord(**legacy_fields)
    assert verify_record(signed, SECRET)


def test_interrupted_approval_is_recorded_before_prompt():
    sink = MemoryAuditSink()
    policy = Policy.from_dict(
        {
            "default": "allow",
            "rules": [{"id": "approve", "decision": "require_human", "tools": ["shell"], "reason": "review"}],
        }
    )

    def interrupt_approval(request):
        raise KeyboardInterrupt

    guard = Guard(policy, audit=sink, agent_id="agent-1", approver=interrupt_approval)
    try:
        guard.call(lambda tool, args: "must not run", "shell", {"cmd": "deploy"})
    except KeyboardInterrupt:
        pass
    else:
        raise AssertionError("approval interruption should propagate")
    assert len(sink.records) == 1
    assert sink.records[0].event == "decision"
    assert sink.records[0].outcome == "approval_requested"
