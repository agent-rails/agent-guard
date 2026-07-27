from __future__ import annotations

import argparse
import os
import subprocess
import sys

from agent_guard import (
    BlockedError,
    Decision,
    Guard,
    JsonlAuditSink,
    MemoryAuditSink,
    Policy,
    load_policy,
    with_bundled,
)
from agent_guard.guard import ApprovalRequest, deny_by_default
from agent_guard.mcp import run_proxy
from identity import Broker, ContainerRuntime, LocalAttestor, LocalRuntime, RefusedError, RuntimeSpec


def _shell(tool: str, args: dict) -> str:
    if tool not in {"shell", "exec"}:
        raise ValueError(f"unsupported tool '{tool}'")
    result = subprocess.run(args["cmd"], shell=True, capture_output=True, text=True)
    return (result.stdout + result.stderr).strip()


def _default_policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "id": "block-rm-rf",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"\brm\s+-rf\b", r"\brm\s+-fr\b"],
                    "reason": "recursive force delete blocked",
                },
                {
                    "id": "block-sql-drop",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"(?i)\bdrop\s+table\b"],
                    "reason": "destructive sql blocked",
                },
                {
                    "id": "block-disk-wipe",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"\bmkfs\b", r"\bdd\s+.*of=/dev/"],
                    "reason": "disk-destroying command",
                },
                {
                    "id": "block-fork-bomb",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r":\(\)\s*\{\s*:\s*\|\s*:"],
                    "reason": "fork bomb",
                },
                {
                    "id": "gate-force-push",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"git\s+push\b.*--force", r"git\s+push\b.*-f\b"],
                    "reason": "force-push rewrites shared history",
                },
                {
                    "id": "gate-curl-pipe-sh",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"(curl|wget)\b.*\|\s*(sh|bash)"],
                    "reason": "piping a remote script to a shell",
                },
                {
                    "id": "gate-chmod-777",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"chmod\s+-R\s+777"],
                    "reason": "world-writable recursive chmod",
                },
                {
                    "id": "gate-kubectl-delete",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"kubectl\s+delete\b"],
                    "reason": "deleting cluster resources",
                },
                {
                    "id": "gate-power",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"\b(shutdown|reboot|halt|poweroff)\b"],
                    "reason": "host power state change",
                },
                {
                    "id": "block-iptables-flush",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"iptables\s+(-F\b|--flush\b)"],
                    "reason": "flushing firewall rules disables network policy",
                },
                {
                    "id": "block-nft-flush",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"nft\s+flush\s+ruleset\b"],
                    "reason": "flushing nftables ruleset disables network policy",
                },
            ],
        }
    )


def _tty_approver(request: ApprovalRequest) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(f"\n  approve '{request.tool}: {request.args.get('cmd', request.args)}'? [{request.reason}] (y/N) ")
    return answer.strip().lower() in {"y", "yes"}


def _build_sandbox(args):
    if args.runtime == "container":
        runtime = ContainerRuntime()
        sandbox = runtime.spawn(RuntimeSpec(kind="local.container", image=args.image, network=args.network))
        return sandbox, sandbox.attest()
    runtime = LocalRuntime(tool_fn=_shell)
    sandbox = runtime.spawn(RuntimeSpec(code_digest=args.digest, kind="local.process"))
    return sandbox, sandbox.attest()


def _run(args) -> int:
    sandbox, attestation = _build_sandbox(args)

    allowlist = set(args.allow_digest)
    if args.dev_trust_runtime:
        allowlist.add(attestation.code_digest)
    result = LocalAttestor(allowlist).verify(attestation)

    try:
        token = broker_mint(result, args)
    except RefusedError as err:
        print(f"refused: {err}", file=sys.stderr)
        sandbox.close()
        return 2

    policy = load_policy(args.policy) if args.policy else _default_policy()
    audit = JsonlAuditSink(args.audit) if args.audit else MemoryAuditSink()
    guard = Guard(
        policy,
        audit=audit,
        agent_id=token.agent_id,
        trust_tier=token.trust_tier,
        approver=_tty_approver,
    )

    command = " ".join(args.command)
    print(f"[{token.agent_id} @ {token.trust_tier}] $ {command}", file=sys.stderr)
    exit_code = 0
    try:
        output = guard.wrap(sandbox.dispatch)("shell", {"cmd": command})
        if output:
            print(output)
    except BlockedError as err:
        print(f"blocked: {err}", file=sys.stderr)
        exit_code = 3
    finally:
        sandbox.close()

    if isinstance(audit, MemoryAuditSink) and args.show_audit:
        print("--- audit ---", file=sys.stderr)
        for record in audit.records:
            flag = "ran" if record.executed else "blocked"
            print(f"  [{flag}] {record.decision} :: {record.reason}", file=sys.stderr)
    return exit_code


def _mcp(args) -> int:
    server_cmd = [c for c in args.server if c != "--"]
    if not server_cmd:
        print("no server command; usage: guard mcp --policy p.yaml -- <mcp-server cmd>", file=sys.stderr)
        return 1
    policy = load_policy(args.policy) if args.policy else with_bundled(default=Decision.ALLOW).compile()
    audit = JsonlAuditSink(args.audit) if args.audit else MemoryAuditSink()
    guard = Guard(policy, audit=audit, agent_id=args.agent_id, approver=deny_by_default)
    return run_proxy(server_cmd, guard)


def broker_mint(result, args):
    secret = os.urandom(32)
    grant = set(args.scope)
    return Broker(secret=secret, ttl_seconds=args.ttl).mint(
        result, subject=args.subject, human_grant=grant, task_scope=grant
    )


def _iter_rules(policy):
    """Yield (module_name_or_None, Rule) from either Policy or CompiledPolicy."""
    rules = getattr(policy, "rules", None)
    if rules is not None:
        for rule in rules:
            yield None, rule
        return
    ordered = getattr(policy, "ordered", None)
    if ordered is not None:
        for module, rule in ordered:
            yield module.name, rule
        return
    raise TypeError(f"unsupported policy type: {type(policy)!r}")


def _rules(args) -> int:
    """List policy rules so operators can see what `guard run` will enforce."""
    if args.policy:
        policy = load_policy(args.policy)
        source = args.policy
    elif args.bundled:
        policy = with_bundled(default=Decision.ALLOW).compile()
        source = "bundled modules (same family as `guard mcp` defaults)"
    else:
        policy = _default_policy()
        source = "built-in defaults (same as `guard run` without --policy)"

    entries = list(_iter_rules(policy))

    if args.json:
        import json

        payload = {
            "source": source,
            "default": policy.default.value,
            "rules": [
                {
                    "id": rule.id,
                    "decision": rule.decision.value,
                    "tools": list(rule.tools),
                    "arg_patterns": list(rule.arg_patterns),
                    "reason": rule.reason,
                    **({"module": module} if module else {}),
                }
                for module, rule in entries
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"policy source: {source}")
    print(f"default decision: {policy.default.value}")
    print(f"rules ({len(entries)}):")
    if not entries:
        print("  (none)")
        return 0
    for module, rule in entries:
        tools = ", ".join(rule.tools)
        patterns = "; ".join(rule.arg_patterns) if rule.arg_patterns else "(any args)"
        reason = rule.reason or "(no reason)"
        label = f"{module}/{rule.id}" if module else rule.id
        print(f"  [{rule.decision.value:14}] {label}")
        print(f"      tools:    {tools}")
        print(f"      patterns: {patterns}")
        print(f"      reason:   {reason}")
    return 0


def _resolve_policy(args) -> Policy:
    if getattr(args, "policy", None):
        return load_policy(args.policy)
    return _default_policy()


def _parse_tool_args(pairs: list[str] | None) -> dict:
    """Parse repeated --arg key=value pairs into a dict for tool checks."""
    out: dict = {}
    for raw in pairs or []:
        if "=" not in raw:
            raise SystemExit(f"invalid --arg {raw!r}; expected key=value")
        key, value = raw.split("=", 1)
        if not key:
            raise SystemExit(f"invalid --arg {raw!r}; empty key")
        out[key] = value
    return out


def _check(args) -> int:
    """Dry-run a tool call against policy — no process spawn, no side effects.

    Exit codes (deliberately *not* identical to ``guard run`` for gates):
      0 allow
      3 deny / would block
      4 require_human (would gate; check never prompts)
      1 usage error

    ``guard run`` collapses a denied human gate to exit 3 because the TTY
    approver refused. ``check`` keeps 4 so CI can distinguish hard-deny from
    "needs a human" without executing anything.
    """
    import json

    tool = args.tool
    if tool == "shell":
        command = [c for c in (args.command or []) if c != "--"]
        if not command:
            print("nothing to check; usage: guard check -- <command>", file=sys.stderr)
            return 1
        tool_args = {"cmd": " ".join(command)}
        display = tool_args["cmd"]
    else:
        tool_args = _parse_tool_args(args.arg)
        remainder = [c for c in (args.command or []) if c != "--"]
        if remainder and "cmd" not in tool_args:
            tool_args["cmd"] = " ".join(remainder)
        display = f"{tool} {json.dumps(tool_args, sort_keys=True)}"

    policy = _resolve_policy(args)
    verdict = policy.evaluate(tool, tool_args, args.trust_tier)

    decision = verdict.decision.value
    rule_id = getattr(verdict, "rule_id", None) or ""
    reason = verdict.reason or ""

    if args.json:
        print(
            json.dumps(
                {
                    "tool": tool,
                    "args": tool_args,
                    "decision": decision,
                    "rule_id": rule_id or None,
                    "reason": reason,
                    "would_execute": verdict.decision is Decision.ALLOW,
                },
                indent=2,
            )
        )
    else:
        print(f"check: {display}")
        print(f"decision: {decision}")
        if rule_id:
            print(f"rule: {rule_id}")
        if reason:
            print(f"reason: {reason}")
        if verdict.decision is Decision.ALLOW:
            print("would_execute: yes")
        elif verdict.decision is Decision.DENY:
            print("would_execute: no (blocked)")
        else:
            print("would_execute: no (needs human approval)")

    if verdict.decision is Decision.ALLOW:
        return 0
    if verdict.decision is Decision.DENY:
        return 3
    return 4  # require_human


def _explain(args) -> int:
    """Show *which rule* matched a tool call and why — no execution.

    Complements a dry-run allow/deny: explain is for policy authors who need
    the first-match story (tool glob, arg regex that hit, rules skipped).

    Exit codes mirror severity for scripting:
      0 allow (or default allow)
      3 deny
      4 require_human
      1 usage error
    """
    import json

    command = [c for c in (args.command or []) if c != "--"]
    if not command:
        print("nothing to explain; usage: guard explain -- <command>", file=sys.stderr)
        return 1

    tool = args.tool
    if tool == "shell":
        tool_args = {"cmd": " ".join(command)}
    else:
        tool_args = {"cmd": " ".join(command)} if command else {}

    policy = _resolve_policy(args)
    detail = policy.explain(tool, tool_args, args.trust_tier)

    if args.json:
        print(json.dumps(detail, indent=2))
    else:
        print(f"explain: {tool} {json.dumps(tool_args, sort_keys=True)}")
        print(f"decision: {detail['verdict']['decision']}")
        if detail["matched"] and detail["rule"]:
            rule = detail["rule"]
            print(f"matched_rule: {rule['id']} (#{rule['index']})")
            print(f"tool_globs: {', '.join(rule['tools'])}")
            if rule["matched_arg_patterns"]:
                print("matched_patterns:")
                for pat in rule["matched_arg_patterns"]:
                    print(f"  - {pat}")
            elif not rule["arg_patterns"]:
                print("matched_patterns: (none — tool-only rule)")
            if rule.get("reason"):
                print(f"reason: {rule['reason']}")
        else:
            print(f"matched_rule: (none — policy default '{detail['default']}')")
            print(f"reason: {detail['verdict']['reason']}")
        skipped = detail.get("skipped_before") or []
        if skipped and args.verbose:
            print(f"skipped_before: {len(skipped)}")
            for s in skipped:
                print(f"  - {s['id']}: {s['why_skipped']}")
        dec = detail["verdict"]["decision"]
        if dec == "allow":
            print("would_execute: yes")
        elif dec == "deny":
            print("would_execute: no (blocked)")
        else:
            print("would_execute: no (needs human approval)")

    dec = detail["verdict"]["decision"]
    if dec == "allow":
        return 0
    if dec == "deny":
        return 3
    return 4


def _validate(args) -> int:
    """Validate a policy file's structure without evaluating any tool call.

    Catches load errors, bad decisions, uncompilable arg regexes, unknown
    trust tiers, and duplicate rule ids — the CI gate for policy authors
    before ``guard check`` / ``guard run``.

    Exit codes:
      0 policy is valid
      1 validation failed (or usage error)
    """
    import json
    import re
    from pathlib import Path

    from agent_guard.tiers import TRUST_TIERS, rank

    if not args.policy:
        print("usage: guard validate --policy <file.yaml|json>", file=sys.stderr)
        return 1

    path = Path(args.policy)
    errors: list[str] = []
    warnings: list[str] = []
    rule_count = 0
    default = None

    if not path.is_file():
        errors.append(f"policy file not found: {path}")
    else:
        try:
            text = path.read_text(encoding="utf-8")
            if path.suffix in {".yaml", ".yml"}:
                try:
                    import yaml
                except ImportError:
                    errors.append("PyYAML is required to validate .yaml policies; `pip install pyyaml` or use JSON")
                    data = None
                else:
                    data = yaml.safe_load(text)
            else:
                data = json.loads(text)
        except (OSError, json.JSONDecodeError, ValueError) as err:
            errors.append(f"failed to parse policy: {err}")
            data = None

        if data is None and not errors:
            errors.append("policy file is empty")
        elif isinstance(data, dict):
            if "default" not in data:
                errors.append("policy must declare an explicit 'default' decision")
            else:
                try:
                    default = Decision(data["default"]).value
                except ValueError:
                    errors.append(f"invalid default decision {data['default']!r}; expected allow|deny|require_human")

            rules = data.get("rules", [])
            if rules is None:
                errors.append("'rules' must be a list (got null)")
                rules = []
            elif not isinstance(rules, list):
                errors.append(f"'rules' must be a list (got {type(rules).__name__})")
                rules = []

            seen_ids: dict[str, int] = {}
            for index, raw in enumerate(rules):
                rule_count += 1
                loc = f"rule #{index}"
                if not isinstance(raw, dict):
                    errors.append(f"{loc}: expected a mapping, got {type(raw).__name__}")
                    continue
                rid = raw.get("id", f"rule-{index}")
                loc = f"rule #{index} ({rid})"
                if rid in seen_ids:
                    errors.append(f"{loc}: duplicate id (also used by rule #{seen_ids[rid]})")
                else:
                    seen_ids[rid] = index

                if "decision" not in raw:
                    errors.append(f"{loc}: missing 'decision'")
                else:
                    try:
                        Decision(raw["decision"])
                    except ValueError:
                        errors.append(f"{loc}: invalid decision {raw['decision']!r}; expected allow|deny|require_human")

                tools = raw.get("tools")
                if not tools:
                    errors.append(f"{loc}: missing a non-empty 'tools' list")
                elif not isinstance(tools, list):
                    errors.append(f"{loc}: 'tools' must be a list")

                patterns = raw.get("arg_patterns", []) or []
                if not isinstance(patterns, list):
                    errors.append(f"{loc}: 'arg_patterns' must be a list")
                    patterns = []
                for pat in patterns:
                    try:
                        re.compile(pat)
                    except re.error as err:
                        errors.append(f"{loc}: invalid arg_pattern {pat!r}: {err}")

                tier = raw.get("min_trust_tier")
                if tier is not None:
                    try:
                        rank(tier)
                    except ValueError:
                        errors.append(f"{loc}: unknown min_trust_tier {tier!r}; expected one of {TRUST_TIERS}")

                if raw.get("judge") and "judge_ceiling" in raw:
                    try:
                        Decision(raw["judge_ceiling"])
                    except ValueError:
                        errors.append(f"{loc}: invalid judge_ceiling {raw['judge_ceiling']!r}")

            if rule_count == 0:
                warnings.append("policy has zero rules; only the default decision applies")

            # Confirm the library loader agrees (catches any drift).
            if not errors:
                try:
                    load_policy(path)
                except Exception as err:  # noqa: BLE001 — surface any loader failure
                    errors.append(f"load_policy rejected file: {err}")
        elif data is not None:
            errors.append(f"policy root must be a mapping (got {type(data).__name__})")

    ok = not errors
    if args.json:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "path": str(path),
                    "default": default,
                    "rule_count": rule_count,
                    "errors": errors,
                    "warnings": warnings,
                },
                indent=2,
            )
        )
    else:
        status = "ok" if ok else "FAILED"
        print(f"validate: {path} — {status}")
        if default is not None:
            print(f"default: {default}")
        print(f"rules: {rule_count}")
        for w in warnings:
            print(f"warning: {w}")
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        if ok and not warnings:
            print("policy is valid")
        elif ok:
            print("policy is valid (with warnings)")

    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard", description="Run a command in a governed sandbox.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a command through the guard")
    run.add_argument("--runtime", choices=["local", "container"], default="local")
    run.add_argument("--image", help="container image (container runtime only)")
    run.add_argument("--network", action="store_true", help="allow container network (default: none)")
    run.add_argument("--policy", help="policy file (yaml/json); default blocks rm -rf / drop table, gates force-push")
    run.add_argument("--audit", help="append audit records to this JSONL file")
    run.add_argument("--subject", default=f"human:{os.environ.get('USER', 'unknown')}")
    run.add_argument("--scope", action="append", default=[], help="granted scope (repeatable)")
    run.add_argument("--allow-digest", action="append", default=[], help="allowlisted code digest (repeatable)")
    run.add_argument("--dev-trust-runtime", action="store_true", help="dev: trust the spawned runtime's digest")
    run.add_argument("--digest", default="dev", help="local runtime code digest")
    run.add_argument("--ttl", type=int, default=300)
    run.add_argument("--show-audit", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run")
    run.set_defaults(func=_run)

    mcp = sub.add_parser("mcp", help="guard a stdio MCP server (proxy every tools/call)")
    mcp.add_argument("--policy", help="policy file; default gates common dangerous tools")
    mcp.add_argument("--audit", help="append audit records to this JSONL file")
    mcp.add_argument("--agent-id", default="mcp-agent")
    mcp.add_argument("server", nargs=argparse.REMAINDER, help="-- <mcp-server command>")
    mcp.set_defaults(func=_mcp)

    rules = sub.add_parser(
        "rules",
        help="list policy rules (built-in defaults, bundled modules, or a policy file)",
    )
    rules.add_argument(
        "--policy",
        help="policy file (yaml/json); if omitted, show built-in `guard run` defaults",
    )
    rules.add_argument(
        "--bundled",
        action="store_true",
        help="show the bundled module pack (closer to `guard mcp` defaults)",
    )
    rules.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    rules.set_defaults(func=_rules)

    check = sub.add_parser(
        "check",
        help="dry-run a tool call against policy (no process spawn, no side effects)",
        description=(
            "Evaluate policy for a tool call without executing anything. "
            "Exit codes: 0=allow, 3=deny, 4=require_human (unlike `guard run`, "
            "which returns 3 when a human gate is denied), 1=usage error."
        ),
    )
    check.add_argument(
        "--policy",
        help="policy file (yaml/json); default is the same built-in policy as `guard run`",
    )
    check.add_argument(
        "--tool",
        default="shell",
        help="tool name to evaluate (default: shell, matching `guard run`)",
    )
    check.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="tool argument (repeatable); for non-shell tools, e.g. --arg query='DROP TABLE t'",
    )
    check.add_argument(
        "--trust-tier",
        default="local.process",
        help="caller trust tier used for min_trust_tier rules (default: local.process)",
    )
    check.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    check.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="for --tool shell: -- <command to evaluate>",
    )
    check.set_defaults(func=_check)

    explain = sub.add_parser(
        "explain",
        help="show which policy rule matches a command (no execution)",
    )
    explain.add_argument(
        "--policy",
        help="policy file (yaml/json); default is the same built-in policy as `guard run`",
    )
    explain.add_argument(
        "--tool",
        default="shell",
        help="tool name to evaluate (default: shell)",
    )
    explain.add_argument(
        "--trust-tier",
        default="local.process",
        help="caller trust tier used for min_trust_tier rules (default: local.process)",
    )
    explain.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    explain.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="list rules skipped before the match",
    )
    explain.add_argument("command", nargs=argparse.REMAINDER, help="-- command to explain")
    explain.set_defaults(func=_explain)

    validate = sub.add_parser(
        "validate",
        help="validate a policy file (structure, regexes, trust tiers) without evaluating calls",
        description=(
            "Structural policy check for CI. Does not evaluate a tool call "
            "(use `guard check` for that). Exit 0 if valid, 1 on errors."
        ),
    )
    validate.add_argument(
        "--policy",
        required=True,
        help="policy file (yaml/json) to validate",
    )
    validate.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    validate.set_defaults(func=_validate)

    return parser


def _run_guard(args) -> int:
    command = [c for c in args.command if c != "--"]
    if not command:
        print("nothing to run; usage: guard run -- <command>", file=sys.stderr)
        return 1
    args.command = command
    return _run(args)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.func is _run:
        return _run_guard(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
