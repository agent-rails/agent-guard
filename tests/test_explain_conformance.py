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
            ],
        }
    )


CASES = [
    ("shell", {"cmd": "rm -rf /tmp/x"}),
    ("shell", {"cmd": "echo hi"}),
    ("shell", {"cmd": "git push --force origin main"}),
    ("dangerous.exec", {"cmd": "anything"}),
    ("deploy", {"cmd": "deploy prod"}),
    ("unknown", {"cmd": "nothing matches"}),
]


def test_explain_agrees_with_evaluate():
    policy = _policy()
    for tool, args in CASES:
        verdict = policy.evaluate(tool, args, "local.process")
        detail = policy.explain(tool, args, "local.process")
        assert detail["verdict"]["decision"] == verdict.decision.value, (tool, args)
        assert detail["verdict"]["rule_id"] == verdict.rule_id, (tool, args)
