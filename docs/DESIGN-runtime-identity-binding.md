# Design — runtime ↔ identity binding (local and remote)

Status: Draft. Ties `agent-guard` (the `what` + `did`) to the two sibling blocks: per-agent identity (the `who`) and isolated runtime (the `where`). Type-1 once a design partner commits — this doc is the pre-commit sketch.

## The four pillars

| Pillar | Question | Block |
|--------|----------|-------|
| Identity | who is the agent? | identity broker (this doc) |
| Authorization | what may it do? | `agent-guard` (built) |
| Audit | what did it do? | `agent-guard` audit sink (built) |
| Isolation | where does it run, and what's the blast radius? | runtime (this doc) |

Insight: isolation and identity are one primitive from two sides. The isolated runtime is what you attest to mint the identity; the identity is what the guard authorizes and the audit attributes. Auth without containment = one bypass reaches everything. Containment without auth = free rein inside the box. You need both, bound together.

## The binding flow

```
1. spawn        agent starts inside an isolated runtime (local or remote)
2. attest       the runtime proves what it is (image/code hash, runtime kind,
                sandbox id) — no shared secret
3. mint         broker verifies attestation + the human's delegation grant,
                mints a short-lived token:
                { sub: human, act: agent_id, sandbox: sid, scopes: intersection, exp: 5m }
4. authorize    agent-guard evaluates each tool call against policy, keyed to
                the minted identity (agent_id) and its scopes
5. audit        every decision logged against agent_id + sandbox id
6. contain      the runtime bounds egress/fs/secrets to the identity's authority,
                and dies when the task ends — the credential dies with it
```

Steps 4–5 are `agent-guard` today. Steps 1–3 and 6 are the sibling blocks this doc specs.

## Local AND remote — one interface, a trust gradient

Requirement: run agents remotely (cloud sandboxes) AND locally (dev laptop, air-gapped, cost-sensitive, data-sovereignty). One runtime abstraction, pluggable backends.

```python
class Runtime(Protocol):
    def spawn(self, spec: RuntimeSpec) -> Sandbox: ...


class Sandbox(Protocol):
    def attest(self) -> Attestation: ...  # evidence of what this runtime is
    def dispatch(self, tool: str, args: dict): ...  # the seam agent-guard wraps
    def close(self) -> None: ...  # ephemeral: credential dies here
```

Backends:
- LocalRuntime — subprocess, or local container (Docker/Podman), or local microVM. Zero cloud dependency. For dev, air-gapped, and low-trust workloads.
- RemoteRuntime — E2B / Daytona / Modal / Firecracker microVM. For production and higher-trust workloads.

Do NOT build the sandbox tech. Build the binding on top of existing runtimes.

### The honest trust gradient

Local and remote are not equal-trust. State the posture; never pretend they are.

| Runtime | Isolation | Attestation strength | Use for |
|---------|-----------|----------------------|---------|
| local process | weak (same OS) | self-declared (process metadata) | dev, unit tests |
| local container | moderate (namespaces) | image hash + runtime metadata | dev, low-trust automation |
| remote gVisor | strong (syscall filter) | image hash + platform attestation | production, medium-trust |
| remote microVM + HW root | strongest (KVM + TEE) | hardware-rooted attestation | production, high-trust / regulated |

Policy consumes the posture: the same guard policy can require a minimum runtime tier for high-authority scopes. "You may call the prod-write tool ONLY from a remote-microVM-attested identity." Local identities get local-tier authority; they cannot self-elevate. That is how a local option stays safe without pretending it's a TEE.

## Attestation model

`Attestation` = evidence + claims the runtime makes about itself. `Attestor` verifies it and returns what the broker can trust.

```python
@dataclass
class Attestation:
    runtime_kind: str  # "local.process" | "local.container" | "remote.gvisor" | "remote.microvm"
    code_digest: str  # hash of the agent image/code
    sandbox_id: str
    evidence: dict  # backend-specific: container id, platform doc, TEE quote


@dataclass
class AttestationResult:
    verified: bool
    trust_tier: str  # drives max authority
    claims: dict  # what the broker may mint into the token
```

- Local: `evidence` is process/container metadata. Verified against a local expected-digest allowlist. Trust tier capped at `local.*`.
- Remote: `evidence` includes the platform's signed attestation (or a TEE quote for microVM+HW). Verified against the platform's key / a TEE root. Higher trust tier unlocked.

Fail-closed: unverifiable attestation → no token minted → the agent runs with zero authority (or is refused). Never mint on unverified evidence.

## Token schema (delegation with attribution)

Reuse RFC 8693 (OAuth token exchange) semantics — do not invent crypto.

```json
{
  "sub": "human:frank",          // on-behalf-of (delegation)
  "act": { "agent_id": "agent-42", "sandbox": "sbx-abc" },  // actor
  "trust_tier": "remote.microvm",
  "scopes": ["read:repo", "write:branch"],  // human_grant ∩ agent_policy ∩ task
  "exp": 1735689600,             // minutes
  "iss": "broker"
}
```

- `sub`/`act` = attributable delegation: logs show human AND agent AND sandbox.
- `scopes` = least-privilege intersection.
- `exp` = short TTL; revocation = broker denylist + TTL, no long tail.

## How the pieces compose (with today's agent-guard)

`agent-guard` already takes an `agent_id` and evaluates policy per tool call. The identity block feeds it:

```python
sandbox = runtime.spawn(spec)  # 1 spawn
attestation = sandbox.attest()
token = broker.mint(
    attestor, attestation, human_grant, task_scope
)  # 2+3 attest (internal) + mint, fail-closed via RefusedError

guard = Guard(policy, audit=sink, agent_id=token.act.agent_id)  # identity feeds the guard
guarded = guard.wrap(sandbox.dispatch)  # 4+5 authorize + audit
guarded("sql", {"query": "..."})  # 6 contained by the sandbox
sandbox.close()  #   credential dies
```

Policy can gate on `token.trust_tier` — the missing hook to add to `agent-guard`: a rule condition on minimum runtime tier per scope.

## MVP vs scalable

MVP (weeks, local-first):
- LocalRuntime (container) + a hand-rolled broker minting JWTs from a container-digest allowlist.
- `agent-guard` consumes the identity (already built) + a new `min_trust_tier` rule field.
- Audit already done.
- Demoable on a laptop, zero cloud — the local option is the wedge for dev adoption.

Scalable:
- Swap the hand-rolled broker for SPIRE (attestation plugins per runtime) + RFC 8693 exchange.
- RemoteRuntime backends (E2B/Daytona/Modal/Firecracker) with platform/TEE attestation.
- Per-spawn ephemeral identities at fleet scale, cross-vendor.

## Security properties

- No static secrets — agents hold minutes-long tokens bound to their sandbox.
- Fail-closed — unverified attestation and un-approved human gates both deny.
- Attributable — every action ties to human + agent + sandbox.
- Least-privilege — scope intersection; local identities capped at local authority.
- Contained — isolation bounds blast radius when authorization is wrong.
- Revocable — kill the sandbox or denylist the identity; TTL kills the tail.

## Honest limits

- Local attestation is inherently weaker than a hardware-rooted TEE. The gradient makes this safe (local ≠ high authority), but do not market local as equivalent trust.
- Defends against accidental over-reach and injected agents up to the isolation boundary. A fully compromised host under the runtime is out of scope — same trust model as any workload-identity system.
- Two-sided adoption still applies: downstream resources must authorize on the minted identity. `agent-guard` covers the resource side for tools it wraps; native cloud IAM integration is future work.

## Open questions

- Standard claim set for agent delegation chains (human → agent → sub-agent). Track IETF/OAuth WG drafts before fixing a schema.
- Where the broker lives in the local-first case (embedded lib vs local daemon).
- Whether `min_trust_tier` belongs in `agent-guard` policy or a separate authority layer.
