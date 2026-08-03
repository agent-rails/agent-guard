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
from agentguard_identity import Broker, ContainerRuntime, LocalAttestor, LocalRuntime, RefusedError, RuntimeSpec


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


def _check(args) -> int:
    """Evaluate an arbitrary {"tool": ..., "args": {...}} payload from stdin
    -- no execution. Companion to `guard explain`: explain's CLI only wraps
    a command string as {"cmd": ...}; check takes any tool/args shape (a
    file write's {"content": ...}, for instance), so callers who aren't
    Python (a shell hook, for instance) can still reuse the same
    deterministic Guard/Policy engine `guard run` uses, including writing
    to an audit sink via --audit.

    Exit codes match `guard explain`:
      0 allow (or default allow)
      3 deny
      4 require_human
      1 usage error / malformed payload
    """
    import json

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as err:
        print(f"malformed JSON payload on stdin: {err}", file=sys.stderr)
        return 1

    tool = payload.get("tool")
    tool_args = payload.get("args")
    if not tool or not isinstance(tool_args, dict):
        print('payload must be {"tool": "...", "args": {...}}', file=sys.stderr)
        return 1

    policy = _resolve_policy(args)
    audit = JsonlAuditSink(args.audit) if args.audit else MemoryAuditSink()
    guard = Guard(policy, audit=audit, agent_id=args.agent_id, trust_tier=args.trust_tier)

    _allowed, verdict = guard.decide(tool, tool_args)
    # check never executes the underlying action itself -- the caller (e.g. a
    # hook script) does that separately based on the exit code, so executed
    # is always False here, same as explain's "no execution" positioning.
    guard.record(tool, tool_args, verdict, executed=False)

    if args.json:
        print(
            json.dumps(
                {
                    "tool": tool,
                    "decision": verdict.decision.value,
                    "rule_id": verdict.rule_id,
                    "reason": verdict.reason,
                }
            )
        )
    else:
        print(f"check: {tool} {json.dumps(tool_args, sort_keys=True, default=str)}")
        print(f"decision: {verdict.decision.value}")
        print(f"rule_id: {verdict.rule_id or '(none)'}")
        print(f"reason: {verdict.reason}")

    if verdict.decision is Decision.ALLOW:
        return 0
    if verdict.decision is Decision.DENY:
        return 3
    return 4


# Starter policy for `guard init`. Dict form is the source of truth; YAML/JSON
# serializers derive from it so an installed wheel works without package data.
_STARTER_POLICY: dict = {
    "default": "allow",
    "rules": [
        {
            "id": "block-sql-drop",
            "decision": "deny",
            "tools": ["sql", "db_*"],
            "arg_patterns": [r"(?i)\bdrop\s+table\b", r"(?i)\btruncate\b"],
            "reason": "destructive SQL is never allowed for an agent",
        },
        {
            "id": "block-rm-rf",
            "decision": "deny",
            "tools": ["shell", "bash", "exec"],
            "arg_patterns": [r"\brm\s+-rf\b", r"\brm\s+-fr\b"],
            "reason": "recursive force delete is blocked",
        },
        {
            "id": "gate-force-push",
            "decision": "require_human",
            "tools": ["shell", "bash", "git"],
            "arg_patterns": [r"git\s+push\b.*--force", r"git\s+push\b.*-f\b"],
            "reason": "force-push rewrites shared history; a human must approve",
        },
        {
            "id": "gate-prod-writes",
            "decision": "require_human",
            "tools": ["http_*", "api_*"],
            "arg_patterns": ["(?i)prod", "(?i)production"],
            "reason": "writes to production surfaces require a human gate",
        },
        {
            "id": "prod-write-needs-attested-runtime",
            "decision": "allow",
            "tools": ["prod_write", "deploy"],
            "min_trust_tier": "remote.microvm",
            "reason": (
                "high-authority tools only from a hardware-attested runtime; local identities cannot self-elevate"
            ),
        },
    ],
}

_INIT_HEADER = """\
# agent-guard starter policy — edit freely, then:
#   guard rules --policy <this-file>
#   guard explain --policy <this-file> -- rm -rf /tmp/x
#   guard run --policy <this-file> --dev-trust-runtime -- echo hi
#
# First matching rule wins. default is required (no silent fallback).

"""


def _render_starter(path_suffix: str) -> str:
    """Serialize `_STARTER_POLICY` to YAML or JSON text."""
    import json

    if path_suffix == ".json":
        return json.dumps(_STARTER_POLICY, indent=2) + "\n"
    try:
        import yaml
    except ImportError as err:
        raise ImportError("PyYAML is required to write .yaml policies; `pip install pyyaml` or use .json") from err
    # default_flow_style=False keeps lists readable like policy.example.yaml
    body = yaml.safe_dump(_STARTER_POLICY, sort_keys=False, default_flow_style=False)
    return _INIT_HEADER + body


def _init(args) -> int:
    """Write a starter policy file operators can edit and pass to --policy.

    Refuses to overwrite an existing path unless ``--force``. After write,
    loads the file through ``load_policy`` so a broken starter never ships.
    """
    from pathlib import Path

    path = Path(args.path)
    suffix = path.suffix.lower()
    if suffix == "":
        path = path.with_suffix(".yaml")
        suffix = ".yaml"
    if suffix not in {".yaml", ".yml", ".json"}:
        print(
            f"unsupported policy extension {suffix!r}; use .yaml, .yml, or .json",
            file=sys.stderr,
        )
        return 1

    if path.exists() and not args.force:
        print(
            f"refusing to overwrite existing {path}; pass --force to replace",
            file=sys.stderr,
        )
        return 1

    try:
        body = _render_starter(suffix if suffix != ".yml" else ".yaml")
    except ImportError as err:
        print(str(err), file=sys.stderr)
        return 1

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")

    try:
        policy = load_policy(path)
    except Exception as err:  # noqa: BLE001 — surface any loader failure
        path.unlink(missing_ok=True)
        print(f"wrote then failed to load starter policy: {err}", file=sys.stderr)
        return 1

    print(f"wrote starter policy: {path}")
    print(f"default: {policy.default.value}")
    print(f"rules: {len(policy.rules)}")
    print(f"next: guard rules --policy {path}")
    print(f"      guard explain --policy {path} -- rm -rf /tmp/x")
    return 0


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

    check = sub.add_parser(
        "check",
        help='evaluate a {"tool": ..., "args": {...}} payload from stdin (no execution)',
        description=(
            "Companion to `guard explain` for tool shapes explain's {\"cmd\": ...}-only "
            "CLI can't express. Reads JSON from stdin, evaluates via Guard, exits with "
            "the same code convention as explain (0 allow, 3 deny, 4 require_human)."
        ),
    )
    check.add_argument("--policy", help="policy file (yaml/json); default is the same built-in policy as `guard run`")
    check.add_argument("--audit", help="append audit records to this JSONL file")
    check.add_argument("--agent-id", default="check-caller")
    check.add_argument(
        "--trust-tier",
        default="local.process",
        help="caller trust tier used for min_trust_tier rules (default: local.process)",
    )
    check.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    check.set_defaults(func=_check)

    init = sub.add_parser(
        "init",
        help="write a starter policy file you can edit and pass to --policy",
        description=(
            "Scaffold a starter policy (same shape as policy.example.yaml). "
            "Refuses to overwrite unless --force. Loads the file after write "
            "so a broken starter never ships."
        ),
    )
    init.add_argument(
        "path",
        nargs="?",
        default="policy.yaml",
        help="output path (default: policy.yaml); .json writes JSON instead of YAML",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing file",
    )
    init.set_defaults(func=_init)

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
