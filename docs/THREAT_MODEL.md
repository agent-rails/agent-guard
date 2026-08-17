# Threat model

What agent-guard defends against, per pillar, framed as Prevent / Contain / Detect — and, just as deliberately, what it does not defend against. Every claim below is grounded in this project's actual code and tests, not aspiration; where a gap was found and closed during development, that's described here and cross-checked directly against the current source and test suite (see `docs/Evaluation.md` for the full findings history), not merely asserted.

## Assets

- **Agent identity** — the minted `Token` (trust tier, scopes, `cnf` binding) and, when PoP is enabled, the sandbox's private key.
- **Authorization decisions** — whether a given tool call or file write proceeds.
- **The audit trail** — the record of what was decided and why.
- **The host** — files, secrets, and network reachable from wherever the agent's tool calls actually execute.

## Actors and trust boundaries

| Actor | Trust level |
|---|---|
| The human operator | Trusted, but can misconfigure a policy or skip `from_token` |
| The AI agent itself | Semi-trusted — assumed capable of being prompt-injected or hallucinating a destructive action; **not** assumed malicious by design, but the boundary is built as if it could be |
| Content fetched by the agent (web pages, tool output, files) | Untrusted — the classic prompt-injection vector |
| A remote/external execution node | Trust varies by attested tier; a `local.container` identity is not trusted the same as a `remote.microvm` one |
| A downstream verifier of tokens or audit records | Trusts only what it can cryptographically check — a bearer token or an unsigned record is trusted on possession alone |

## Pillar 1 — Identity (`agentguard_identity`)

**Prevent:**
- Hand-typed trust-tier escalation. `Guard.from_token()` requires an encoded, HMAC-signed token and re-verifies it — a caller cannot simply pass `trust_tier="remote.microvm"` as a string and be believed. *(Closed after being found exploitable: the first version accepted a bare, hand-constructable `Token` object — fixed and reproduced live before/after.)*
- Self-signed tokens from an empty or unset secret. `sign()`/`verify()` reject an empty secret. *(Same review cycle — the original code accepted `secret=b""` silently.)*
- Bearer-token theft. Proof-of-possession (opt-in): a holder-bound token (`cnf` claim) requires a fresh, single-token-scoped proof signed by the sandbox's own Ed25519 private key. A captured encoded token with no proof, or a proof from a different sandbox's key, is rejected even though the token's own signature is valid.

**Contain:**
- Scopes are `human_grant ∩ task_scope` — an agent's authority is capped at the intersection the human explicitly granted for the task, not everything the human could do.
- Tokens are short-lived (TTL-bound); revocation is TTL + a denylist, no long tail.

**Detect:** every decision an identity authorizes is attributed in the audit trail to `agent_id`/`sandbox_id`.

**Explicit non-goals:**
- The plain `Guard(...)` constructor still trusts a caller-supplied `trust_tier` string by design — it exists for local/no-identity use, and the security property only holds once `from_token` is actually the entry point. A caller who skips `from_token` self-elevates; this is documented, not hidden.
- PoP defends against *token theft* (the encoded string leaking without the key). It does not defend against a fully compromised sandbox that exfiltrates the private key too — same trust model as any workload-identity system.
- A fully compromised execution host is out of scope for every identity guarantee here.

## Pillar 2 — Authorization (`agent_guard.Policy`/`Guard`)

**Prevent:**
- Destructive tool calls (`rm -rf`, `DROP TABLE`, force-push, etc.) via deterministic, first-match-wins regex policy. A policy with no explicit `default` is rejected at load — no silent fallback. Matching runs on RE2 (linear-time by construction), not stdlib `re` — a policy-author-written pattern matched against attacker-controlled content cannot be forced into catastrophic backtracking, a real live-reproduced DoS this project used to be exposed to (see below).
- Malicious content landing on disk via `Edit`/`Write` — the same policy engine evaluates a synthetic `{"tool": "write", "args": {"content": ...}}` call, denying pipe-to-shell, `eval`/`exec`, credential/sensitive-path word references, and symlink creation.

**Contain:** default is `allow`, not paranoid default-deny — a false positive degrades to a logged, visible finding rather than blocking real work outright, for anything not on the explicit deny list. An optional `VelocityLimiter` (see the volume/sequence residual below) additionally caps per-agent, per-tool call rate over a time window, so a burst of individually-in-policy calls is contained even when no single call trips a rule — downstream of the RE2 engine, never inside it.

**Detect:** every matched rule (deny or allow-tier) carries a `rule_id`/`reason` in the audit trail; unmatched calls are distinguishable (`rule_id: null`) from calls that matched an allow-tier rule.

**Real false positives/negatives found and their resolution** (this is real evaluation data, not a hypothetical list — see `Evaluation.md`):
- A `base64`-shaped regex denied legitimate lockfile integrity hashes (`sha512-...` in `yarn.lock`) — downgraded from deny to allow-but-logged; the original HIGH severity was calibrated for skill-file instructions specifically, a narrower and riskier context than general writes.
- Evaluating with `{"path": ..., "content": ...}` together denied any file merely *named* `secrets.yaml` regardless of content, because the policy engine renders the whole args dict into one matched string. Fixed as a calling-convention rule (content-only), with a test that reproduces the old pitfall on purpose so it stays visible.
- The credential/sensitive-path rule is a **literal word match, not a credential-shape detector** — `password=`, `api_key=`, `PRIVATE_KEY=` assignments are not caught. This is a known, tested, and documented limitation (a test asserts the gap explicitly), not a silent one.
- A plausible, non-exotic policy-author pattern (`(\w+)+\d`) hung the process for 5+ seconds on a 31-byte adversarial payload via catastrophic backtracking, reproduced live -- the matching engine itself was the exposed surface, not any one shipped pattern. Fixed by migrating `arg_patterns` matching from stdlib `re` to RE2, which structurally cannot backtrack catastrophically; not a heuristic detector layered on top of the old engine.

**Explicit non-goals:**
- No LLM judges a security-critical decision on its own output — an `LLMJudge` may only *tighten* a verdict toward `require_human` within a rule's ceiling, never grant beyond what static policy already permits.
- Static regex cannot catch a novel attack the policy author never anticipated, disguised as otherwise-benign content. Defense-in-depth (isolation, tiers) is the mitigation for this class, not elimination of it.

## Pillar 3 — Audit (`SigningAuditSink`)

**Prevent:** tampering by a party that does not hold the HMAC signing secret.

**Detect:** a signed record's integrity is independently verifiable via `verify_record`.

**Explicit non-goals (stated in the sink's own docstring, not discovered after the fact — though the *first* version of this docstring overclaimed and had to be corrected):**
- Does **not** defend against a compromised producer — the process signing records also holds the secret, so it can sign a forged record just as validly as a real one.
- Does **not** detect suppression — a producer that simply never emits a record for an action leaves no gap to find.

## Pillar 4 — Isolation (runtime tiers)

**Prevent:** claiming an isolation tier stronger than what actually ran. `ContainerRuntime.spawn` raises rather than silently falling back to `runc` when `gVisor` was requested but unavailable — claiming isolation it didn't provide is treated as a bug, not a convenience.

**Contain:** `EgressPolicy` defaults to deny (`--network=none`); the `local.container` tier is explicitly documented as **not** escape-safe (shared kernel) — it is a dev/trusted-code tier, not a security boundary, and the docs say so rather than implying otherwise.

**Explicit non-goal:** host-allowlist egress is unimplemented and fails loud (`NotImplementedError`) rather than silently granting full network access — a real gap, but a visible one.

## Pillar 5 — the `guard check` CLI surface

This is the newest, and the one where the actual attack surface is a different shape: an **untrusted caller** (a shell hook, potentially fed adversarial input) sending arbitrary JSON on stdin.

**Prevent:** malformed-but-syntactically-valid JSON (a bare array, `null`, a non-string `tool`) previously reached unvalidated code paths and crashed with an unhandled traceback that leaked absolute filesystem paths to stderr — found in review, fixed to fail closed with a clean, documented error (exit 1) instead. Verified live against the original crash payloads both before and after the fix.

**Explicit non-goal:** `check` never executes the underlying action itself (`executed` is always `False` in its audit records) — it is a decision oracle; the caller is responsible for acting on the exit code, and nothing here guarantees the caller does so correctly.

## Residual risks, consolidated

- **Prompt injection causing the agent to construct a plausible-looking but genuinely novel malicious call** is not eliminated by a deterministic ruleset — only mitigated by keeping the ruleset narrow, tested, and paired with isolation as a second layer. `examples/guarded_autonomous_agent/agent_injection_scenario.py` tests this directly: a prompt-injection payload planted in a file the agent reads as ordinary due diligence, with the task prompt narrowed so the injection is the strongest explanation for a read of the restricted file — not strictly the only one, since locating the target file requires a directory listing that also reveals the restricted file's existence (a second review pass caught this residual too; existence-knowledge is not the same as a motive). Honest result from two live runs, not the result originally hoped for: the agent's own alignment (Claude Opus) recognized and refused the injected instruction both times, so this scenario has NOT demonstrated an injection reaching a real tool call — that remains unverified. What IS true regardless, by construction rather than by this test: `Policy.evaluate()` takes only `(tool, args, trust_tier)` — it has no parameter for the agent's reasoning — so it cannot distinguish a manipulated call from a directly-instructed one, which is exactly what `agent.py`'s direct-instruction test already proves unconditionally. An earlier version of this doc entry claimed the injection scenario itself proved manipulation happened; that claim didn't survive review (caught before merge) — the agent's own audit-log read order and its own refusal text contradicted it. Left here as a corrected record, not scrubbed, since the correction is itself part of this project's evaluation history.
- **Credential-shape detection does not exist** — only literal keyword matching. A real secret without one of the matched words is invisible to this policy.
- **The policy engine is blind to volume and sequence — volume is now partially addressed, sequence is not.** `Policy.evaluate(tool, args, trust_tier)` has no session state — no call counter, no velocity tracking, no notion of "this tool called 500 times" or "a read of X followed by a write to Y." It gates each call in isolation and correctly, deterministically allows or denies that one call. This is the same shape as the Hugging Face intrusion cited elsewhere in this project's docs as validation (17,600 actions, no single one exotic): the *static* engine would pass every one of those calls individually.
  - **What is now closed:** an optional `VelocityLimiter` (`agent_guard.velocity`) sits strictly downstream of the deterministic RE2 engine — the engine is untouched. Wired into `Guard.decide()`, it caps per-agent, per-tool-pattern call *count* within a sliding time window; a call that would otherwise be allowed is denied once the window is full, recorded in the audit trail as a first-class deny (`rule_id: "velocity-limit"`) identical in shape to a policy-authored one. It is opt-in (constructor default `None`, so every existing caller is unchanged) and fail-closed: if the limiter itself errors, the call is denied, never silently allowed. `tests/test_velocity.py::test_huggingface_shape_individually_in_policy_calls_denied_on_accumulation` exercises exactly the HF shape — 17,600 individually-in-policy calls, stopped at the configured budget.
  - **What is still open, stated precisely:** (1) The MVP limiter is **call-count velocity only** — it does **not** detect *sequence* or *pattern* ("read secret X then write to public Y"); a slow, individually-in-budget exfiltration below the rate threshold is invisible to it. (2) The shipped `InMemoryVelocityLimiter` is **in-memory** — a process restart resets every counter, so an attacker who can restart the host resets their own velocity budget. The `VelocityLimiter` protocol exists precisely so a durable backend (Redis, etc.) can replace it without touching `Guard`; that backend is not shipped here. (3) Limits are per-agent; **coordinated volume spread across many agent identities** is below each individual budget and not caught. Isolation and egress-deny remain the blast-radius containment for what velocity does not catch.
- **Every security review this project has had was same-vendor** (a same-model-family adversarial reviewer, standing in for an unavailable cross-vendor pass). Genuine cross-vendor reasoning diversity — the thing most likely to catch a blind spot this project's own model family shares — has not yet happened for any of this work.
- **The project has never been published or run outside this development process.** Nothing here has adversarial-in-the-wild experience; every finding to date came from structured internal review, not real-world attack traffic.
