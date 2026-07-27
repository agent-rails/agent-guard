from __future__ import annotations

from agent_guard.policy import Policy


def _policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "id": "deny-rm",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"\brm\s+-rf\b"],
                    "reason": "recursive force delete",
                },
                {
                    "id": "gate-push",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"git\s+push\b.*--force"],
                    "reason": "force push",
                },
                {
                    "id": "tool-only",
                    "decision": "deny",
                    "tools": ["dangerous.*"],
                    "reason": "tool-only rule, no arg patterns",
                },
                {
                    "id": "tier-gated",
                    "decision": "allow",
                    "tools": ["deploy"],
                    "arg_patterns": [r"\bprod\b"],
                    "min_trust_tier": "remote.microvm",
                    "reason": "prod deploy needs isolation",
                },
                {
                    "id": "judge-email",
                    "decision": "require_human",
                    "tools": ["email"],
                    "judge": True,
                    "reason": "external email needs judgment",
                },
            ],
        }
    )


CASES = [
    ("shell", {"cmd": "rm -rf /tmp/x"}, "local.process"),
    ("shell", {"cmd": "echo hi"}, "local.process"),
    ("shell", {"cmd": "git push --force origin main"}, "local.process"),
    ("dangerous.exec", {"cmd": "anything"}, "local.process"),
    ("deploy", {"cmd": "deploy prod"}, "local.process"),
    ("deploy", {"cmd": "deploy prod"}, "remote.microvm"),
    ("email", {"to": "x@external.com"}, "local.process"),
    ("unknown", {"cmd": "nothing matches"}, "local.process"),
]


def test_explain_agrees_with_evaluate():
    policy = _policy()
    for tool, args, tier in CASES:
        verdict = policy.evaluate(tool, args, tier)
        detail = policy.explain(tool, args, tier)
        assert detail["verdict"]["decision"] == verdict.decision.value, (tool, args, tier)
        assert detail["verdict"]["rule_id"] == verdict.rule_id, (tool, args, tier)
        assert detail["verdict"]["needs_judge"] == verdict.needs_judge, (tool, args, tier)


def test_explain_output_shape_pinned():
    policy = _policy()

    # tool-only match surfaces empty matched_arg_patterns
    tool_only = policy.explain("dangerous.exec", {"cmd": "x"}, "local.process")
    assert tool_only["matched"] is True
    assert tool_only["rule"]["matched_arg_patterns"] == []

    # arg-pattern match surfaces the hitting pattern
    arg_hit = policy.explain("shell", {"cmd": "rm -rf /tmp/x"}, "local.process")
    assert arg_hit["rule"]["matched_arg_patterns"]

    # tool-miss skip entries omit arg_patterns; arg-miss skip entries include it
    default_path = policy.explain("shell", {"cmd": "harmless"}, "local.process")
    reasons = {s["why_skipped"] for s in default_path["skipped_before"]}
    assert "tool pattern miss" in reasons
    for skip in default_path["skipped_before"]:
        if skip["why_skipped"] == "tool pattern miss":
            assert "arg_patterns" not in skip
        if skip["why_skipped"] == "arg pattern miss":
            assert "arg_patterns" in skip
