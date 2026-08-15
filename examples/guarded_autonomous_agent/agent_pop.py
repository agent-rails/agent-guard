"""Same real-agent, real-container demo as agent.py, but the identity token
is holder-bound (Proof-of-Possession) instead of a plain bearer credential.

Proves two things live, against the real machinery -- not a fixture:

1. The legitimate path still works exactly as before -- a real agent making
   real decisions, inside a real container, with real deny enforcement --
   just now gated behind a token that additionally requires proving
   possession of the sandbox's own private key, not just presenting the
   encoded string.
2. A stolen encoded token ALONE is not enough. Simulates an attacker who
   captured just the encoded token -- e.g. a leaked log line, a config
   file that shouldn't have had it -- but does not hold the sandbox's
   private key: Guard.from_token() refuses to construct a Guard at all,
   even though the token's own HMAC signature is perfectly valid. Same
   refusal for a proof forged with the wrong keypair.

Honest scope, corrected in review (PR #31): this covers token-without-proof
theft, not a full on-the-wire capture. verify_pop's 60-second freshness
window is deliberately generous rather than single-use (no nonce/replay
tracking) -- a proof captured ALONGSIDE its token (a genuine network
capture, where the attacker gets both) is replayable within that window.
The property actually proven is "the bearer string alone is insufficient,"
which is the whole point of holder-binding over a plain bearer token -- not
"immune to a full request capture," which would need single-use proofs
agent-guard doesn't implement.

This repo's existing pop_example.py already proves this cryptographic
property, but only against a scripted LocalRuntime call. This is the same
property, now proven against a real autonomous agent in a real container --
the thing that was still missing.

Prerequisites: same as agent.py, plus the [pop] extra:
    pip install "agentguard[pop]"

Run:
    python examples/guarded_autonomous_agent/agent_pop.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from agent import IMAGE, build_registry, policy, run_agent

from agent_guard import Decision, Guard, Policy
from agent_guard.audit import JsonlAuditSink
from agentguard_identity import Broker, ContainerRuntime, LocalAttestor, PoPKeypair, RuntimeSpec
from agentguard_identity.token import sign

AUDIT_PATH = Path(__file__).parent / "audit_pop.jsonl"


def spawn_attest_mint_with_pop() -> tuple:
    image_digest = json.loads(
        subprocess.run(
            ["docker", "inspect", "--format", "{{json .Id}}", IMAGE], capture_output=True, text=True, check=True
        ).stdout
    )
    print(f"image digest: {image_digest}")

    runtime = ContainerRuntime()
    sandbox = runtime.spawn(
        RuntimeSpec(code_digest=image_digest, kind="local.container", image=IMAGE, pop_enabled=True)
    )
    attestor = LocalAttestor(allowlist={image_digest})
    attestation = sandbox.attest()
    result = attestor.verify(attestation)
    print(
        f"attestation: verified={result.verified} tier={result.trust_tier} "
        f"sandbox={result.sandbox_id} ({result.reason})"
    )
    if not result.verified:
        sandbox.close()
        raise SystemExit("attestation failed -- refusing to mint a token or run the agent")

    secret = b"guarded-autonomous-agent-pop-example-secret-do-not-use-in-prod"
    broker = Broker(secret=secret, ttl_seconds=600)
    token = broker.mint(
        attestor,
        attestation,
        subject="guarded-autonomous-agent-pop-example",
        human_grant={"exec"},
        task_scope={"exec"},
        pop_thumbprint=sandbox.pop_thumbprint(),
    )
    encoded = sign(token, secret)
    print(f"identity: {token.agent_id}  tier={token.trust_tier}  holder-bound: cnf={token.cnf[:16]}...")
    return sandbox, secret, encoded


def demonstrate_theft_fails(encoded: str, secret: bytes) -> None:
    """A stolen encoded token, with no valid proof of possession, must not
    be usable -- checked directly against Guard.from_token(), the same
    entry point the legitimate path uses. No LLM involved: this is a
    property of the crypto/protocol layer, not agent behavior."""
    print("\n=== simulating a stolen token (attacker has the encoded string, not the key) ===")
    dummy_policy = Policy(default=Decision.ALLOW)
    dummy_sink = JsonlAuditSink(Path("/tmp/agent-guard-pop-demo-should-never-be-written.jsonl"))

    # Assert on the message, not just "some ValueError happened" -- verify_token
    # also raises ValueError on a wrong secret or an expired token (token.py),
    # caught by the same handler. Without checking the reason, a refusal for an
    # unrelated cause would print a misleadingly reassuring "correctly refused"
    # line. Found in review (PR #31): a proof credible enough to assert on, not
    # just eyeball.
    try:
        Guard.from_token(encoded, secret, dummy_policy, audit=dummy_sink, pop_proof=None)
        raise AssertionError("UNEXPECTED: Guard was constructed with no proof at all")
    except ValueError as err:
        assert "pop_proof" in str(err), f"refused, but not for the expected reason: {err}"
        print(f"correctly refused (no proof presented): {err}")

    attacker_keypair = PoPKeypair.generate()
    forged_proof = attacker_keypair.prove(encoded)
    try:
        Guard.from_token(encoded, secret, dummy_policy, audit=dummy_sink, pop_proof=forged_proof)
        raise AssertionError("UNEXPECTED: Guard was constructed with a forged proof")
    except ValueError as err:
        assert "pop_proof" in str(err), f"refused, but not for the expected reason: {err}"
        print(f"correctly refused (proof from the wrong key): {err}")


def print_audit_trail() -> None:
    print("\n=== audit trail (attributed to the holder-bound identity) ===")
    if not AUDIT_PATH.exists():
        print("(no audit records written)")
        return
    for line in AUDIT_PATH.read_text().splitlines():
        rec = json.loads(line)
        flag = "ran" if rec["executed"] else "BLOCKED"
        print(f"[{flag}] {rec['agent_id']} {rec['tool']}: {rec['reason']}")


def main() -> None:
    print("=== spawning a real Docker container, attesting, minting a HOLDER-BOUND identity ===")
    sandbox, secret, encoded = spawn_attest_mint_with_pop()

    demonstrate_theft_fails(encoded, secret)

    print("\n=== legitimate path: the sandbox proves possession of its own key ===")
    proof = sandbox.prove_possession(encoded)
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()
    audit = JsonlAuditSink(AUDIT_PATH)
    guard = Guard.from_token(encoded, secret, policy(), audit=audit, pop_proof=proof)
    print("Guard constructed successfully -- possession proven, the same encoded token now usable.")

    guarded_dispatch = guard.wrap(sandbox.dispatch)
    registry = build_registry(guarded_dispatch)

    user_input = (
        "List the files in the current directory, read config.toml and summarize it, "
        "then try reading /etc/passwd (outside the workspace) and secrets.txt (inside "
        "the workspace, but policy-restricted) -- tell me what happens with each."
    )
    print(f"\n=== running the real agent loop (now behind a holder-bound token) ===\nprompt: {user_input!r}\n")
    try:
        run_agent(registry, user_input)
    finally:
        sandbox.close()
        print_audit_trail()


if __name__ == "__main__":
    main()
