from __future__ import annotations

from agent_guard import Guard, MemoryAuditSink, Policy
from agentguard_identity import Broker, LocalAttestor, LocalRuntime, RuntimeSpec
from agentguard_identity.token import sign


def real_tools(tool: str, args: dict) -> str:
    return f"EXECUTED {tool}({args})"


def policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "deny",
            "rules": [{"id": "allow-reads", "decision": "allow", "tools": ["read"]}],
        }
    )


def main() -> None:
    print("=== proof-of-possession: a stolen encoded token alone is not enough ===\n")

    runtime = LocalRuntime(tool_fn=real_tools)
    attestor = LocalAttestor(allowlist={"sha256:agent-image-v1"})
    secret = b"local-dev-secret"

    # The legitimate sandbox spawns with pop_enabled=True: it generates its own
    # Ed25519 keypair, and the private key never leaves the sandbox.
    victim = runtime.spawn(RuntimeSpec(code_digest="sha256:agent-image-v1", pop_enabled=True))
    result = attestor.verify(victim.attest())
    # pop_thumbprint() -> the token's cnf claim. Holding this token alone is no longer
    # sufficient to use it — the presenter must also sign a fresh proof with the key
    # that produced this thumbprint.
    token = Broker(secret=secret).mint(
        result, "human:frank", {"read"}, {"read"}, pop_thumbprint=victim.pop_thumbprint()
    )
    encoded_token = sign(token, secret)
    print(f"minted a HOLDER-BOUND token: cnf={token.cnf[:12]}...\n")

    # Simulate the token leaking — a log line, a network capture, whatever. An
    # attacker who captured `encoded_token` also spins up their own sandbox and tries
    # to use it with their own key.
    attacker = runtime.spawn(RuntimeSpec(code_digest="sha256:agent-image-v1", pop_enabled=True))
    forged_proof = attacker.prove_possession(encoded_token)
    try:
        Guard.from_token(encoded_token, secret, policy(), audit=MemoryAuditSink(), pop_proof=forged_proof)
        print("EXPLOIT SUCCEEDED — this would be a bug")
    except ValueError as err:
        print(f"attacker's own sandbox key rejected: {err}")

    # The legitimate holder proves possession with the key that actually matches cnf.
    real_proof = victim.prove_possession(encoded_token)
    guard = Guard.from_token(encoded_token, secret, policy(), audit=MemoryAuditSink(), pop_proof=real_proof)
    guarded = guard.wrap(victim.dispatch)
    print(f"legitimate holder: {guarded('read', {'path': '/tmp/x'})}")

    victim.close()
    attacker.close()

    print(
        "\nA plain (non-holder-bound) token — Broker.mint() without pop_thumbprint — "
        "still works exactly as before PoP existed; this is opt-in, not a breaking change."
    )
    try:
        Guard.from_token(encoded_token, secret, policy(), audit=MemoryAuditSink())
        print("BUG: should have required a proof")
    except ValueError as err:
        print(f"holder-bound token without any proof: {err}")


if __name__ == "__main__":
    main()
