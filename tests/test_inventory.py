from __future__ import annotations

import json

from agent_guard import AuditRecord, JsonlAuditSink
from agent_guard.cli import main
from agent_guard.inventory import LIMIT_TEXT, build_inventory
from agentguard_identity.credentials import IssuanceRecord, JsonlIssuanceStore


def _write(path, **overrides):
    base = {
        "ts": "2026-11-01T10:00:00+00:00",
        "agent_id": "agent-1",
        "tool": "deploy",
        "args": {},
        "decision": "allow",
        "reason": "ok",
        "rule_id": None,
        "executed": True,
        "event": "release",
    }
    JsonlAuditSink(path).write(AuditRecord(**{**base, **overrides}))


def test_groups_by_actor_and_tenant(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit, actor="alice-agent", tenant_id="t1", grant_hash="g1", ts="2026-11-01T10:00:00+00:00")
    _write(audit, actor="alice-agent", tenant_id="t1", grant_hash="g2", tool="read", ts="2026-11-01T12:00:00+02:00")
    _write(audit, actor="alice-agent", tenant_id="t2", grant_hash="g3")
    _write(audit, agent_id="legacy", ts="2026-11-02T00:00:00+00:00")
    inventory = build_inventory(audit)
    by_key = {(a.actor, a.tenant_id): a for a in inventory.agents}
    assert set(by_key) == {("alice-agent", "t1"), ("alice-agent", "t2"), ("legacy", None)}
    first = by_key[("alice-agent", "t1")]
    assert first.tools == {"deploy", "read"}
    assert first.grant_hashes == {"g1", "g2"}
    assert first.first_seen.isoformat() == "2026-11-01T10:00:00+00:00"
    assert first.last_seen.isoformat() == "2026-11-01T10:00:00+00:00"
    assert first.without_grant_hash == 0
    assert by_key[("legacy", None)].without_grant_hash == 1


def test_actor_falls_back_to_agent_id_and_prefers_actor(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit, agent_id="raw", actor="stamped")
    _write(audit, agent_id="raw2")
    assert {a.actor for a in build_inventory(audit).agents} == {"stamped", "raw2"}


def test_decision_counts_exclude_terminal_rows(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit, decision="allow", event="release")
    _write(audit, decision="allow", event="terminal", outcome="returned")
    _write(audit, decision="deny", event="decision")
    _write(audit, decision="allow", event=None)
    inventory = build_inventory(audit)
    assert dict(inventory.agents[0].decisions) == {"allow": 2, "deny": 1}
    assert inventory.not_counted == 1


def test_malformed_lines_are_counted(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    with audit.open("a") as handle:
        handle.write("not json\n")
        handle.write(json.dumps({"ts": "garbage", "agent_id": "x", "tool": "t"}) + "\n")
        handle.write(json.dumps({"ts": "2026-11-01T10:00:00+00:00", "tool": "t"}) + "\n")
        handle.write(json.dumps([1, 2]) + "\n")
    inventory = build_inventory(audit)
    assert inventory.malformed == 4
    assert inventory.rows == 1
    assert len(inventory.agents) == 1


def test_issuance_grouped_by_tenant_with_malformed_counted(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    issuance = tmp_path / "issuance.jsonl"
    store = JsonlIssuanceStore(issuance)
    for index, tenant in enumerate(["t1", "t1", "t2"]):
        store.append(
            IssuanceRecord(
                issuance_id=f"i{index}",
                op_id=f"op{index}",
                tenant_id=tenant,
                task_id=f"task{index}",
                tool="deploy",
                request_digest="d",
                executor_key_id="k",
                audience="a",
                issued_at=1_000.0 + index,
                expires_at=1_060.0,
            )
        )
    with issuance.open("a") as handle:
        handle.write("{broken\n")
        handle.write(json.dumps({"op_id": "x"}) + "\n")
    inventory = build_inventory(audit, issuance)
    assert inventory.issuance_rows == 3
    assert inventory.issuance_malformed == 2
    tenants = {t.tenant_id: t for t in inventory.tenants}
    assert tenants["t1"].issuances == 2
    assert tenants["t1"].task_ids == {"task0", "task1"}
    assert tenants["t2"].first_issued.isoformat() == "1970-01-01T00:16:42+00:00"


def test_cli_prints_limit_and_counts(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    _write(audit, actor="a1", tenant_id="t1", grant_hash="g1")
    assert main(["inventory", "--audit", str(audit)]) == 0
    out = capsys.readouterr().out
    assert LIMIT_TEXT in out
    assert "actor=a1 tenant=t1" in out
    assert "grant_hash: g1" in out
    assert "decisions: allow=1" in out
    assert "decisions with no grant_hash: 0" in out
    assert "malformed lines: 0" in out


def test_cli_reports_malformed_and_exits_4(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    with audit.open("a") as handle:
        handle.write("nope\n")
    assert main(["inventory", "--audit", str(audit)]) == 4
    assert "malformed lines: 1" in capsys.readouterr().out


def test_cli_missing_audit_is_an_error(tmp_path, capsys):
    assert main(["inventory", "--audit", str(tmp_path / "missing.jsonl")]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_cli_missing_issuance_is_an_error(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    assert main(["inventory", "--audit", str(audit), "--issuance", str(tmp_path / "none.jsonl")]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_inventory_does_not_write(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    before = audit.read_bytes()
    main(["inventory", "--audit", str(audit)])
    assert audit.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit.jsonl"]


OVERFLOW_TS = ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"]


def test_unconvertible_timestamps_are_malformed_not_a_crash(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    with audit.open("a") as handle:
        for stamp in OVERFLOW_TS:
            handle.write(json.dumps({"ts": stamp, "agent_id": "x", "tool": "t"}) + "\n")
    inventory = build_inventory(audit)
    assert inventory.malformed == 2
    assert len(inventory.agents) == 1


def test_unconvertible_issuance_timestamps_are_malformed(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    issuance = tmp_path / "issuance.jsonl"
    good = {
        "issuance_id": "i",
        "op_id": "o",
        "tenant_id": "t",
        "task_id": "k",
        "tool": "deploy",
        "request_digest": "d",
        "executor_key_id": "e",
        "audience": "a",
        "issued_at": 1.0,
        "expires_at": 2.0,
    }
    lines = [
        json.dumps({**good, "issued_at": 10**100}),
        json.dumps({**good, "issued_at": 1e300}),
        '{"issuance_id":"i","op_id":"o","tenant_id":"t","task_id":"k","tool":"d","request_digest":"d",'
        '"executor_key_id":"e","audience":"a","issued_at":NaN,"expires_at":2.0}',
        json.dumps({**good, "expires_at": 10**100}),
        json.dumps(good),
    ]
    issuance.write_text("\n".join(lines) + "\n")
    inventory = build_inventory(audit, issuance)
    assert inventory.issuance_malformed == 4
    assert inventory.issuance_rows == 1


def test_logs_are_streamed_not_read_whole(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    _write(audit)
    issuance = tmp_path / "issuance.jsonl"
    issuance.write_text("")

    def refuse(*_args, **_kwargs):
        raise AssertionError("whole-file read")

    monkeypatch.setattr("pathlib.Path.read_text", refuse)
    build_inventory(audit, issuance)
