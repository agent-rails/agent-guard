from __future__ import annotations

import re

from agent_guard import Decision, Policy, Rule
from agent_guard.policy import _render_args


def test_render_args_preserves_word_boundary_across_a_newline():
    # Regression: json.dumps (the old implementation) escapes a real newline
    # as the two characters backslash+n. Since 'n' is a word character, that
    # escape sequence silently merges the word before it with the word after
    # it -- "...load\neval(x)" rendered as "...load\\neval(x)" has no \b
    # boundary between "load" and "eval" anymore, so \beval\b silently fails
    # to match. This is the single most common real position for flagged
    # content (starting a new line), so the bug was a live false-negative,
    # not a theoretical one.
    rendered = _render_args({"content": "do_thing_at_load\neval(payload)"})
    assert re.search(r"\beval\s*\(", rendered) is not None


def test_policy_denies_content_immediately_after_a_newline():
    policy = Policy(
        default=Decision.ALLOW,
        rules=[Rule(id="eval-call", decision=Decision.DENY, tools=("write",), arg_patterns=[r"\beval\s*\("])],
    )
    verdict = policy.evaluate("write", {"content": "some_line_here\neval(payload)"})
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "eval-call"


def test_policy_still_denies_content_with_no_preceding_newline():
    # Same rule, no newline involved -- confirms the fix didn't just move
    # the bug rather than remove it.
    policy = Policy(
        default=Decision.ALLOW,
        rules=[Rule(id="eval-call", decision=Decision.DENY, tools=("write",), arg_patterns=[r"\beval\s*\("])],
    )
    verdict = policy.evaluate("write", {"content": "eval(payload)"})
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "eval-call"
