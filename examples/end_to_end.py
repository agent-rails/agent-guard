from __future__ import annotations

from agent_guard import BlockedError, Decision, Guard, MemoryAuditSink, PolicyModule, PolicyRegistry
from agentguard_identity import Broker, LocalAttestor, LocalRuntime, RefusedError, RuntimeSpec
from agentguard_identity.token import sign


def real_tools(tool: str, args: dict) -> str:
    return f"EXECUTED {tool}({args})"


def policy():
    org = PolicyModule.from_dict(
        {
            "name": "org-base",
            "namespace": "*",
            "layer": 100,
            "rules": [
                {
                    "id": "no-drop",
                    "decision": "deny",
                    "tools": ["sql"],
                    "arg_patterns": [r"(?i)drop table"],
                    "reason": "destructive sql banned",
                },
                {
                    "id": "prod-needs-microvm",
                    "decision": "allow",
                    "tools": ["prod_write"],
                    "min_trust_tier": "remote.microvm",
                    "reason": "prod writes only from a hardware-attested runtime",
                },
            ],
        }
    )
    sql = PolicyModule.from_dict(
        {
            "name": "sql-defaults",
            "namespace": "sql*",
            "layer": 0,
            "rules": [{"id": "reads-ok", "decision": "allow", "tools": ["sql"], "reason": "reads fine"}],
        }
    )
    return PolicyRegistry(default=Decision.DENY).register(org).register(sql).compile()


def main() -> None:
    print("=== four pillars, end to end (local runtime) ===\n")

    # WHERE: spawn an isolated local runtime
    runtime = LocalRuntime(tool_fn=real_tools)
    sandbox = runtime.spawn(RuntimeSpec(code_digest="sha256:agent-image-v1", kind="local.container"))

    # WHO: attest the runtime, then mint a scoped short-lived identity
    attestor = LocalAttestor(allowlist={"sha256:agent-image-v1"})
    attestation = sandbox.attest()
    result = attestor.verify(attestation)
    print(f"attestation: verified={result.verified} tier={result.trust_tier} ({result.reason})")

    secret = b"local-dev-secret"
    broker = Broker(secret=secret, ttl_seconds=300)
    try:
        token = broker.mint(
            attestor,
            attestation,
            subject="human:frank",
            human_grant={"read:repo", "write:branch", "sql"},
            task_scope={"read:repo", "sql", "prod_write"},
        )
    except RefusedError as err:
        print(f"broker refused: {err}")
        return

    print(f"identity:    {token.agent_id} sandbox={token.sandbox_id}")
    print(f"scopes:      {list(token.scopes)}  (human_grant intersect task_scope)")
    print(f"tier:        {token.trust_tier}\n")

    # WHAT + DID: guard authorizes on a VERIFIED token, audits every call.
    # Guard.from_token() re-verifies the signature (and the PoP proof, when the token
    # is holder-bound) rather than trusting agent_id/trust_tier as caller-supplied
    # strings — the whole point of minting through a Broker is that the guard checks
    # it, not that the guard is told to believe it.
    encoded_token = sign(token, secret)
    audit = MemoryAuditSink()
    guard = Guard.from_token(encoded_token, secret, policy(), audit=audit)
    guarded = guard.wrap(sandbox.dispatch)

    attempts = [
        ("sql", {"query": "SELECT * FROM users"}),
        ("sql", {"query": "DROP TABLE users"}),
        ("prod_write", {"target": "prod-db", "op": "write"}),
    ]
    for tool, args in attempts:
        try:
            print(f"ALLOWED  {tool} -> {guarded(tool, args)}")
        except BlockedError as err:
            print(f"BLOCKED  {tool} -> {err}")

    sandbox.close()

    print("\n=== audit (attributed to the agent identity) ===")
    for record in audit.records:
        flag = "ran" if record.executed else "blocked"
        print(f"[{flag}] {record.agent_id} {record.tool}: {record.reason}")

    blocked = sum(1 for r in audit.records if not r.executed)
    assert blocked == 2, f"expected 2 blocked, got {blocked}"
    print(
        "\nprod_write blocked: the local identity's tier (local.container) is below the "
        "remote.microvm the policy requires. A local agent cannot self-elevate."
    )


if __name__ == "__main__":
    main()
