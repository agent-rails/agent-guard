# agent-guard — walkthrough

A guided tour of what agent-guard solves, how it works, and how to run it.

## The problem

Agents run with their operator's full permissions and no record of what they did. One prompt injection reaches everything the human can touch. agent-guard puts a policy-as-code boundary in front of the tool call, so an agent physically cannot run an irreversible action that policy forbids — and every attempt is auditable.

## The model — four pillars, one flow

```
agent -> guard.wrap(dispatch) -> [policy check] -> allow      -> run
                                     |              deny       -> BlockedError (never runs)
                                     |              require_human -> approver
                                     v
                                  audit sink (every attempt, attributed to the agent identity)
```

- Identity — who the agent is and where it runs (a scoped, short-lived, attested per-agent token; scopes are `human_grant ∩ task_scope`).
- Authorization — what it may do (deterministic policy, first match wins).
- Audit — what it did (every call, allowed or blocked, attributed).
- Isolation — where it runs, mapped to a trust tier the policy can require.

## Features

### Deterministic policy engine

Rules are tool-glob + arg-regex + a decision (`allow` / `deny` / `require_human`), evaluated first-match:

```
$ guard explain -- rm -rf /tmp/x
decision: deny
matched_rule: block-rm-rf (#0)
matched_patterns:  \brm\s+-rf\b
would_execute: no (blocked)
```

`explain` shares one matching implementation with the enforcement path, so what it shows is exactly what will be enforced.

### A sensible built-in danger set

`guard rules` lists the active policy. The built-in defaults cover `rm -rf`, `drop table`, `mkfs`/`dd`, fork-bombs, force-push, `curl | sh`, `chmod 777`, `kubectl delete`, host power changes, and iptables/nftables flush.

### Trust tiers and no self-elevation

The minted identity carries the runtime's trust tier; a rule can require a minimum:

```
BLOCKED prod_write -> requires trust tier 'remote.microvm'; caller runtime is 'local.container'
```

A local agent cannot self-elevate to run a prod action it isn't attested for.

### Isolation plane (pluggable by tier)

| Tier | Backend | Isolation |
|------|---------|-----------|
| `local.container` | docker/podman (runc) | shared kernel — not escape-safe, dev/trusted only |
| `remote.gvisor` | docker + gVisor (`runsc`) | user-space kernel, real added isolation |
| `remote.microvm` | E2B/Firecracker (managed) | hardware-virtualized micro-VM (next) |

A tier is attested only when actually provided. If you request `remote.gvisor` but `runsc` isn't installed, spawn raises rather than silently falling back to runc — claiming isolation it didn't provide is treated as a bug.

### Deterministic egress

`EgressPolicy` is fail-closed and outside the agent's influence: default deny (`--network=none`), `allow_all` opens the default network, and a host allowlist fails loud until an egress proxy ships (no silent full-network grant).

### Audit

Every call is recorded and attributed to the agent identity, via a JSONL, in-memory, webhook, or fan-out sink. Wrap any sink in `SigningAuditSink` to HMAC-sign each record — detects tampering by a party that doesn't hold the signing secret; does not defend against a compromised producer (which already holds the secret it would sign a forgery with) or suppression (a producer that simply never emits a record leaves no gap).

### Holder-bound tokens (proof-of-possession)

A minted token is a bearer credential by default — the encoded string alone is enough to use it, however obtained. Spawn a sandbox with `RuntimeSpec(pop_enabled=True)` and it generates an Ed25519 keypair; mint with `pop_thumbprint=sandbox.pop_thumbprint()` and the token becomes holder-bound. Using it then requires `sandbox.prove_possession(encoded)` — a fresh, single-token-scoped signed proof — passed to `Guard.from_token(..., pop_proof=proof)`. A captured token with no proof, or a proof from a different sandbox's key, is rejected even though the token's own signature is valid. Requires `pip install "toolcall-authz[pop]"`; omitted entirely, behavior is unchanged.

### Harness-agnostic

Use it in-process with `guard.wrap()`, or as an MCP proxy that gates every `tools/call` of any stdio MCP server.

## How to run it

Install:

```bash
pip install toolcall-authz                # core (pulls in google-re2)
pip install "toolcall-authz[yaml]"        # + YAML policy files
```

Python, in 30 seconds:

```python
from agent_guard import Guard, Policy, JsonlAuditSink

policy = Policy.from_dict(
    {
        "default": "allow",
        "rules": [
            {
                "id": "no-drop",
                "decision": "deny",
                "tools": ["sql"],
                "arg_patterns": [r"(?i)\bdrop\s+table\b"],
                "reason": "no destructive sql",
            }
        ],
    }
)
guard = Guard(policy, audit=JsonlAuditSink("audit.jsonl"), agent_id="agent-42")
guarded = guard.wrap(my_dispatch)  # wrap whatever runs a tool in your harness
guarded("sql", {"query": "SELECT 1"})  # runs, audited
guarded("sql", {"query": "DROP TABLE users"})  # raises BlockedError, never executes
```

CLI:

```bash
guard run -- <cmd>       # run a command through the guard
guard explain -- <cmd>   # show which rule matches (no execution)
guard rules              # list active policy rules
guard mcp --policy p.yaml -- <mcp-server cmd>   # proxy + gate an MCP server
```

Full four-pillars demo, no cloud:

```bash
python examples/end_to_end.py
```

Proof-of-possession demo (holder-bound token, forged-proof rejection):

```bash
pip install "toolcall-authz[pop]"
python examples/pop_example.py
```

gVisor isolation tier (needs docker + gVisor `runsc`):

```python
from agentguard_identity import ContainerRuntime, RuntimeSpec

sbx = ContainerRuntime().spawn(RuntimeSpec(kind="remote.gvisor", runtime="runsc", image="busybox", network=False))
sbx.attest().runtime_kind  # 'remote.gvisor' only if runsc actually ran, else spawn raised
```

## Design note — why policy-as-code, and where an LLM judge fits

Policy-as-code is the foundation, not the whole answer.

It must be the enforcement floor because it is the one layer you can prove: deterministic, fast, fail-closed, version-controlled, testable — and not attackable by the agent, since the boundary lives outside the model's influence. An LLM asked to authorize its own tool calls is a prompt-injection surface; a static rule is not.

Pure static rules strain at scale in four places: the semantic long tail (regex can't read intent), the ambiguous middle band (binary rules over- or under-block), authoring burden across many teams and tools, and context-blindness. The scalable design keeps policy-as-code as the floor and layers on top of it:

- An LLM judge for the ambiguous band only, bounded by a ceiling — it can tighten a verdict (for example allow to require_human) but never grant beyond what static policy permits. Advisory within hard bounds, never the outer boundary.
- Federated, layered policy modules so authoring scales across teams without one giant ruleset.
- Per-agent least-privilege identity plus trust tiers, so default-deny and scope intersection cap blast radius structurally instead of needing a rule for everything.

What to avoid: judging every call with an LLM (attackable, slow, non-deterministic, unprovable) and learned/statistical allow-deny classifiers (opaque, drift-prone, unauditable). Neither belongs on a security boundary.
