from __future__ import annotations

import time

import pytest

from agent_guard import Decision, Policy, Rule


def test_nested_quantifier_pattern_does_not_hang_on_adversarial_content():
    # Regression: this exact pattern (a plausible policy-author mistake, not an
    # exotic one -- someone matching "repeated tokens then a digit") reproduced
    # live against the pre-migration stdlib-re engine: a 31-byte adversarial
    # payload hung the process for 5+ seconds via catastrophic backtracking, with
    # zero protection. RE2 guarantees linear-time matching by construction, so
    # this asserts a generous-but-decisive wall-clock bound on a payload roughly
    # 6,000x larger than the one that hung the old engine -- proving the fix is
    # actually wired in, not just "fast for small input."
    rule = Rule(id="r", decision=Decision.DENY, tools=("write",), arg_patterns=[r"(\w+)+\d"])
    policy = Policy(default=Decision.ALLOW, rules=[rule])
    payload = "a" * 200_000 + "!"

    start = time.time()
    verdict = policy.evaluate("write", {"content": payload})
    elapsed = time.time() - start

    assert elapsed < 2.0, f"took {elapsed}s on a 200,000-byte payload -- catastrophic backtracking is back"
    assert verdict.decision is Decision.ALLOW  # no trailing digit in the payload, correctly no match


def test_valid_pattern_still_matches_via_re2():
    rule = Rule(id="r", decision=Decision.DENY, tools=("write",), arg_patterns=[r"\bdrop\s+table\b"])
    policy = Policy(default=Decision.ALLOW, rules=[rule])
    verdict = policy.evaluate("write", {"content": "please drop table users"})
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "r"


def test_backreference_pattern_rejected_at_rule_construction():
    # RE2's syntax is a strict subset of PCRE -- no backreferences. A policy
    # author who writes one should get a clear error at load time, not a crash
    # or silent no-op at first-match time.
    with pytest.raises(ValueError, match="not valid RE2 syntax"):
        Rule(id="r", decision=Decision.DENY, tools=("write",), arg_patterns=[r"(a)\1"])


def test_lookahead_pattern_rejected_at_rule_construction():
    with pytest.raises(ValueError, match="not valid RE2 syntax"):
        Rule(id="r", decision=Decision.DENY, tools=("write",), arg_patterns=[r"(?<=foo)bar"])


def test_invalid_pattern_rejection_does_not_leak_raw_c_log_output(capfd):
    # re2 logs invalid-pattern parse errors to stderr via abseil by default, even
    # when the caller catches the exception -- our own ValueError message is
    # supposed to be the only thing a caller sees, not a raw C++ log line on top
    # of it (agent-guard's own clean-error contract, same bar as the CLI's
    # unknown-trust-tier fix).
    with pytest.raises(ValueError):
        Rule(id="r", decision=Decision.DENY, tools=("write",), arg_patterns=[r"(a)\1"])
    captured = capfd.readouterr()
    assert "re2.cc" not in captured.err
    assert "InitializeLog" not in captured.err
