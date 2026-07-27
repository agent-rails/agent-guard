from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .decision import Decision, Verdict
from .tiers import TRUST_TIERS, meets


@dataclass(frozen=True)
class Rule:
    id: str
    decision: Decision
    tools: tuple[str, ...]
    arg_patterns: tuple[str, ...] = ()
    reason: str = ""
    min_trust_tier: str | None = None
    judge: bool = False
    judge_ceiling: Decision = Decision.REQUIRE_HUMAN

    def matches(self, tool: str, rendered_args: str) -> bool:
        if not any(fnmatch.fnmatch(tool, pattern) for pattern in self.tools):
            return False
        if not self.arg_patterns:
            return True
        return any(re.search(pattern, rendered_args) for pattern in self.arg_patterns)


def verdict_for_rule(rule: Rule, tool: str, trust_tier: str) -> Verdict:
    if rule.min_trust_tier and not meets(trust_tier, rule.min_trust_tier):
        return Verdict(
            decision=Decision.DENY,
            reason=f"tool '{tool}' requires trust tier '{rule.min_trust_tier}'; caller runtime is '{trust_tier}'",
            rule_id=rule.id,
        )
    return Verdict(
        decision=rule.decision,
        reason=rule.reason or f"matched rule '{rule.id}'",
        rule_id=rule.id,
        needs_judge=rule.judge,
        judge_ceiling=rule.judge_ceiling,
    )


@dataclass
class Policy:
    default: Decision
    rules: list[Rule] = field(default_factory=list)

    def evaluate(self, tool: str, args: dict[str, Any], trust_tier: str = TRUST_TIERS[0]) -> Verdict:
        rendered_args = _render_args(args)
        for rule in self.rules:
            if rule.matches(tool, rendered_args):
                return verdict_for_rule(rule, tool, trust_tier)
        return Verdict(decision=self.default, reason="no rule matched; policy default")

    def explain(self, tool: str, args: dict[str, Any], trust_tier: str = TRUST_TIERS[0]) -> dict[str, Any]:
        """First-match explanation for humans and CI.

        Unlike ``evaluate``, this returns *why* a rule won: which tool
        glob matched, which ``arg_patterns`` entry hit (if any), and how
        many prior rules were skipped. Default path is explicit when
        nothing matches.
        """
        rendered_args = _render_args(args)
        skipped: list[dict[str, Any]] = []
        for index, rule in enumerate(self.rules):
            tool_hit = any(fnmatch.fnmatch(tool, pattern) for pattern in rule.tools)
            if not tool_hit:
                skipped.append(
                    {
                        "id": rule.id,
                        "index": index,
                        "why_skipped": "tool pattern miss",
                        "tools": list(rule.tools),
                    }
                )
                continue
            matched_patterns: list[str] = []
            if rule.arg_patterns:
                matched_patterns = [pat for pat in rule.arg_patterns if re.search(pat, rendered_args)]
                if not matched_patterns:
                    skipped.append(
                        {
                            "id": rule.id,
                            "index": index,
                            "why_skipped": "arg pattern miss",
                            "tools": list(rule.tools),
                            "arg_patterns": list(rule.arg_patterns),
                        }
                    )
                    continue
            verdict = verdict_for_rule(rule, tool, trust_tier)
            return {
                "tool": tool,
                "args": args,
                "rendered_args": rendered_args,
                "trust_tier": trust_tier,
                "matched": True,
                "rule": {
                    "id": rule.id,
                    "index": index,
                    "decision": rule.decision.value,
                    "tools": list(rule.tools),
                    "arg_patterns": list(rule.arg_patterns),
                    "matched_arg_patterns": matched_patterns,
                    "reason": rule.reason,
                    "min_trust_tier": rule.min_trust_tier,
                    "judge": rule.judge,
                },
                "verdict": {
                    "decision": verdict.decision.value,
                    "reason": verdict.reason,
                    "rule_id": verdict.rule_id,
                    "needs_judge": verdict.needs_judge,
                },
                "skipped_before": skipped,
                "default": self.default.value,
            }
        return {
            "tool": tool,
            "args": args,
            "rendered_args": rendered_args,
            "trust_tier": trust_tier,
            "matched": False,
            "rule": None,
            "verdict": {
                "decision": self.default.value,
                "reason": "no rule matched; policy default",
                "rule_id": None,
                "needs_judge": False,
            },
            "skipped_before": skipped,
            "default": self.default.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if "default" not in data:
            raise ValueError("policy must declare an explicit 'default' decision (allow|deny|require_human)")
        rules = [_rule_from_dict(index, raw) for index, raw in enumerate(data.get("rules", []))]
        return cls(default=Decision(data["default"]), rules=rules)


def _render_args(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, default=str)


def _rule_from_dict(index: int, raw: dict[str, Any]) -> Rule:
    tools = raw.get("tools")
    if not tools:
        raise ValueError(f"rule #{index} is missing a non-empty 'tools' list")
    ceiling = raw.get("judge_ceiling")
    return Rule(
        id=raw.get("id", f"rule-{index}"),
        decision=Decision(raw["decision"]),
        tools=tuple(tools),
        arg_patterns=tuple(raw.get("arg_patterns", ())),
        reason=raw.get("reason", ""),
        min_trust_tier=raw.get("min_trust_tier"),
        judge=bool(raw.get("judge", False)),
        judge_ceiling=Decision(ceiling) if ceiling else Decision.REQUIRE_HUMAN,
    )


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        data = _load_yaml(text)
    else:
        data = json.loads(text)
    return Policy.from_dict(data)


def _load_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as err:
        raise ImportError("PyYAML is required to load .yaml policies; `pip install pyyaml` or use JSON") from err
    return yaml.safe_load(text)
