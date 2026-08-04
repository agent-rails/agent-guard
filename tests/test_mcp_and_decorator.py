from __future__ import annotations

import json

import pytest

from agent_guard import (
    BlockedError,
    Decision,
    Guard,
    MemoryAuditSink,
    PolicyModule,
    PolicyRegistry,
    guarded,
    mcp_handle_line,
)


def a_guard(audit=None):
    mod = PolicyModule.from_dict(
        {
            "name": "sql",
            "rules": [
                {
                    "id": "no-drop",
                    "decision": "deny",
                    "tools": ["run_sql"],
                    "arg_patterns": [r"(?i)drop table"],
                    "reason": "no destructive sql",
                }
            ],
        }
    )
    policy = PolicyRegistry(default=Decision.ALLOW).register(mod).compile()
    return Guard(policy, audit=audit or MemoryAuditSink(), agent_id="mcp")


def call_msg(tool, args, msg_id=1):
    return json.dumps(
        {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    )


def test_non_tool_call_passes_through():
    forward, reply = mcp_handle_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), a_guard())
    assert forward is not None and reply is None


def test_non_json_passes_through():
    forward, reply = mcp_handle_line("not json at all", a_guard())
    assert forward == "not json at all" and reply is None


def test_allowed_tool_call_forwards():
    forward, reply = mcp_handle_line(call_msg("run_sql", {"q": "SELECT 1"}), a_guard())
    assert forward is not None and reply is None


def test_blocked_tool_call_replies_with_tool_error_and_does_not_forward():
    audit = MemoryAuditSink()
    forward, reply = mcp_handle_line(call_msg("run_sql", {"q": "DROP TABLE users"}, msg_id=7), a_guard(audit))
    assert forward is None
    payload = json.loads(reply)
    assert payload["id"] == 7
    assert payload["result"]["isError"] is True
    assert "blocked by agent-guard" in payload["result"]["content"][0]["text"]
    assert audit.records[-1].executed is False


def test_blocked_call_is_audited_as_not_executed():
    audit = MemoryAuditSink()
    mcp_handle_line(call_msg("run_sql", {"q": "drop table x"}), a_guard(audit))
    assert audit.records[-1].decision == "deny"


def test_decorator_allows_and_blocks():
    audit = MemoryAuditSink()
    guard = a_guard(audit)

    @guarded(guard, "run_sql")
    def run_sql(q):
        return f"rows for {q}"

    assert run_sql(q="SELECT 1") == "rows for SELECT 1"
    with pytest.raises(BlockedError):
        run_sql(q="DROP TABLE users")
    assert audit.records[-1].executed is False


def test_decorator_uses_function_name_by_default():
    guard = a_guard()

    @guarded(guard)
    def run_sql(q):
        return "ok"

    assert run_sql(q="SELECT 1") == "ok"


def test_batch_framed_tool_call_is_rejected_not_forwarded():
    """A JSON-RPC batch (top-level array) must never reach the wrapped server
    unguarded -- a denied tools/call wrapped in a batch used to bypass Policy
    entirely because handle_line only inspected dict-shaped messages."""
    audit = MemoryAuditSink()
    batch = json.dumps([json.loads(call_msg("run_sql", {"q": "DROP TABLE users"}))])
    forward, reply = mcp_handle_line(batch, a_guard(audit))
    assert forward is None
    payload = json.loads(reply)
    assert payload["error"]["code"] == -32600
    assert not audit.records


def test_malformed_params_blocked_not_crashed():
    msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["not", "a", "dict"]})
    forward, reply = mcp_handle_line(msg, a_guard())
    assert forward is None
    assert "params" in json.loads(reply)["result"]["content"][0]["text"]


def test_malformed_arguments_blocked_not_crashed():
    msg = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_sql", "arguments": "not a dict"}}
    )
    forward, reply = mcp_handle_line(msg, a_guard())
    assert forward is None
    assert "arguments" in json.loads(reply)["result"]["content"][0]["text"]
