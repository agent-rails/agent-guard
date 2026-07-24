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
