from __future__ import annotations

import json
from dataclasses import replace

import pytest

from agent_guard import Decision, MemoryAuditSink, MultiAuditSink, SigningAuditSink, Verdict, WebhookAuditSink
from agent_guard.audit import build_record, verify_record


def a_record():
    verdict = Verdict(decision=Decision.DENY, reason="nope", rule_id="r1")
    return build_record("agent:1", "sql", {"q": "DROP TABLE t"}, verdict, executed=False)


def test_webhook_posts_json_body():
    sent = {}

    def fake_poster(url, body, headers, timeout):
        sent["url"] = url
        sent["payload"] = json.loads(body)
        sent["headers"] = headers

    WebhookAuditSink("https://siem.example/collect", poster=fake_poster).write(a_record())
    assert sent["url"] == "https://siem.example/collect"
    assert sent["payload"]["tool"] == "sql"
    assert sent["payload"]["decision"] == "deny"
    assert sent["headers"]["Content-Type"] == "application/json"


def test_webhook_raises_on_delivery_failure():
    def boom(url, body, headers, timeout):
        raise RuntimeError("connection refused")

    with pytest.raises(RuntimeError):
        WebhookAuditSink("https://x", poster=boom).write(a_record())


def test_multi_fans_out_to_all():
    a, b = MemoryAuditSink(), MemoryAuditSink()
    MultiAuditSink(a, b).write(a_record())
    assert len(a.records) == 1
    assert len(b.records) == 1


def test_multi_attempts_all_then_raises():
    local = MemoryAuditSink()

    def boom(url, body, headers, timeout):
        raise RuntimeError("remote down")

    remote = WebhookAuditSink("https://x", poster=boom)
    with pytest.raises(RuntimeError):
        MultiAuditSink(local, remote).write(a_record())
    assert len(local.records) == 1  # durable local audit survived the remote failure


def test_signing_sink_requires_a_secret():
    with pytest.raises(ValueError):
        SigningAuditSink(MemoryAuditSink(), secret=b"")


def test_signing_sink_attaches_a_verifiable_signature():
    inner = MemoryAuditSink()
    SigningAuditSink(inner, secret=b"k").write(a_record())
    assert verify_record(inner.records[-1], b"k") is True


def test_unsigned_record_fails_verification():
    assert verify_record(a_record(), b"k") is False


def test_tampered_record_fails_verification():
    inner = MemoryAuditSink()
    SigningAuditSink(inner, secret=b"k").write(a_record())
    tampered = replace(inner.records[-1], executed=True)
    assert verify_record(tampered, b"k") is False


def test_wrong_secret_fails_verification():
    inner = MemoryAuditSink()
    SigningAuditSink(inner, secret=b"k").write(a_record())
    assert verify_record(inner.records[-1], b"wrong-secret") is False
