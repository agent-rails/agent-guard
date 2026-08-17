# Design

The "why" document. `README.md` is how to use agent-guard; `docs/WALKTHROUGH.md` is a guided tour; this is the reasoning behind the shape it took — including the decisions that got revised mid-flight, and why.

## The thesis

An agent running with its operator's full permissions, with no record of what it did, is a single prompt injection away from touching everything the human could touch. The fix has to live **outside the model's influence** — a static, provable boundary in front of the tool-dispatch seam, not a request to the model to police itself.

That constraint drives almost every other decision in this project:

- **Deterministic policy, not an LLM judging its own output.** A rule either matches or it doesn't; the decision is reproducible, testable, and not attackable by the thing it's supposed to constrain. An `LLMJudge` exists, but it can only *tighten* a verdict toward `require_human` within a rule's ceiling — it is advisory within hard bounds set by static policy, never the boundary itself.
- **Identity, authorization, and audit as three distinct concerns**, not one blob. `agentguard_identity` has zero dependency on `agent_guard`; `agent_guard` depends on identity only through *verification* (`from_token`, PoP), never the reverse. Identity answers *who/where*; the guard answers *what*; the audit sink answers *did*. That asymmetric coupling is deliberate and correct — authorization has to verify identity to mean anything — while identity stays independently testable and reusable with zero knowledge of how it's consumed.

## Four pillars, one flow

```
spawn (isolated runtime) -> attest -> mint scoped token -> guard authorizes on tier -> audit
```

Identity mints a scoped, short-lived, attested per-agent token so the guard authorizes on *who the agent is* and *where it runs*, not the human's inherited permissions. `scopes = human_grant ∩ task_scope` — an agent can never end up with more authority than the human explicitly granted for the specific task, no matter what the policy would otherwise allow.

## The recurring pattern: extract-and-adapt, not blind-copy or reinvent

Three separate points in this project's development landed on the same resolution, and it's worth naming as a standing design principle rather than three coincidences:

**Proof-of-possession.** The obvious move was "adopt DPoP (RFC 9449)" wholesale, since it's the established pattern behind cloud agent-identity models. But DPoP proper binds a proof to an HTTP method + URI — agent-guard's actual seam is `dispatch(tool, args)`, a function call, not an HTTP request. Adopting DPoP's ceremony as-is would have meant carrying fields that don't map to anything real here. The resolution: extract DPoP's core cryptographic primitive (a holder-signed, freshness-bound proof over a specific credential) and drop the HTTP-specific binding. Not "reinvent crypto," not "adopt someone else's protocol ceremony" — take the substance, leave the packaging.

**Write-content scanning.** The instinct was to write new bash regex heuristics for scanning file-write content, mirroring an existing standalone script (`scan-skill.sh`). That would have meant a second, drifting implementation of pattern-matching logic this project had already built, tested, and hardened as `Policy`/`Guard`. The resolution: frame a file write as a synthetic tool call (`{"tool": "write", "args": {"content": ...}}`) and evaluate it through the *same* engine — one policy file, one set of tests, two call sites (a CLI and a library call) that structurally cannot drift apart.

**Tool-call observability** (a design question raised *about* this project, from the outside, mid-session): the instinct was to build a new hook that logs every tool call to a new file for later mining. Checking first: the harness this project runs under already writes a comprehensive, structured log of every tool call, with more fidelity than a new hook would capture, to disk. The right move was a parser reading what already exists, not a fourth logging mechanism.

The shared shape: before building, ask whether an existing primitive already covers the actual requirement, and if a spec or pattern *almost* fits, extract what's substantively needed and discard the ceremony that was built for someone else's shape of problem.

## External validation, checked live not assumed

[Cloudflare's cloudflare-os](https://github.com/cloudflare/cloudflare-os) independently ships a "Gatekeeper" -- a proxy Worker that holds an external credential and can require approval before an agent's action proceeds. Different platform (Cloudflare Workers-specific, not portable), different implementation, but the same shape this project's `Guard` + `require_human` already is: a credential-holding layer in front of tool dispatch, gating on policy. Worth citing as independent validation that "credential-holding proxy in front of agent actions" is a recognized pattern, not a one-off design choice -- not an integration target, since it's tied to Cloudflare's own runtime primitives (Durable Objects, Dynamic Worker Facets) rather than being a portable library.

[Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) (hosted under the verified `microsoft` GitHub org, but primarily one individual's project -- 857 of ~2000 commits from a single author who is not a Microsoft employee, not a centrally-built Microsoft product; its "AARM"/"ATF" compliance badges are self- or single-person-verified, not independent standards -- checked live before citing, not taken at face value) independently arrives at the same "credential-holding layer in front of tool dispatch, gating on policy" shape at much larger scope (multi-language SDKs, formal RFC-2119 specs, 992 conformance tests). Two things worth naming, not adopting wholesale:

- Its audit log is Merkle-chained (`docs/specs/AUDIT-COMPLIANCE-1.0.md`), proving record *completeness and order*, not just per-record integrity. This project's `SigningAuditSink` only proves a given record wasn't altered after the fact -- it does not prove a record wasn't silently dropped from the log entirely. A real, named gap, tracked in `THREAT_MODEL.md` rather than closed here.
- Its identity spec states explicitly: "Every agent has a human sponsor. No orphan agents." Neither this project nor `agent-warrant` states that as an explicit principle, even though both structurally assume a human/org is accountable for every agent identity issued. Worth stating outright rather than leaving implicit.

Their `did:mesh:<hex>` identifier is a custom, non-W3C-registered DID method -- the same "ceremony without function" critique `agent-warrant/docs/DESIGN.md` already applied to `did:key` would apply here too; not a reason to adopt it.

[Hugging Face's technical post-mortem](https://huggingface.co/blog/agent-intrusion-technical-timeline) of a real July 2026 incident (verified live: hosted on huggingface.co, real named authors, cross-linked to OpenAI's own incident disclosure) is the most directly relevant validation this project has -- not a design pattern shipped by a vendor, an actual attack. An autonomous agent running an OpenAI-model capability evaluation escaped its sandbox, chained through a third-party host, and ran a 4.5-day, ~17,600-action intrusion into Hugging Face's production infrastructure. Their own stated root causes: unsafe dataset-config processing (an injection class this project's own `arg_patterns`/RE2 matching exists to catch), exposed cloud metadata, over-broad shared long-lived access tokens -- exactly the shape `agent-warrant`'s per-agent `Grant`/holder-binding model exists to prevent (no single shared token with sweeping scope reused across trust boundaries), and exactly the residual risk `agent-warrant/docs/THREAT_MODEL.md` already discloses under "Revocation" (TTL-only, no denylist). Their own framing: *"machine-speed offense makes ordinary weaknesses more expensive for defenders"* -- every individual flaw was mundane; volume (17,600 attempts, most failing) is what made the one working chain findable. Direct, independent validation of this project's core thesis: policy gating and per-agent identity are not theoretical hardening, they close exactly the gaps a real incident exploited. The *volume* half of that framing is what the optional `VelocityLimiter` (`agent_guard.velocity`) addresses: it sits strictly downstream of the deterministic RE2 engine and caps per-agent, per-tool call rate, so a burst of individually-in-policy calls is stopped even though no single call is exotic — deliberately not folded into the static engine, which stays a pure per-call decision. It closes the volume dimension only; *sequence*/pattern detection and durability across restarts remain open and are disclosed as such in `THREAT_MODEL.md`.

## Reuse, not reimplementation: the two-sided contract

Every place this project reuses its own machinery is a deliberate bet that a single, well-tested implementation beats two similar-but-separately-maintained ones:

- The **policy engine** (`Policy.evaluate`) is the one place `arg_patterns` regex matching happens — for shell commands, SQL queries, and file-write content alike. A bug fixed here is fixed everywhere it's used.
  - That engine is [RE2](https://github.com/google/re2) (`google-re2`), not stdlib `re`. `arg_patterns` is policy-author-written but matched against attacker/agent-controlled content -- a backtracking engine lets a plausible, non-exotic pattern (`(\w+)+\d`, a beginner's attempt at "repeated tokens then a digit") be forced into catastrophic backtracking by a few dozen bytes of crafted content. Reproduced live before this was fixed: that exact pattern hung the process for 5+ seconds on a 31-byte payload, with no protection. RE2 guarantees linear-time matching by construction, making that vulnerability class structurally impossible rather than merely rare -- the same reason WAFs and IDS engines matching untrusted patterns against untrusted input use it. Patterns are precompiled once per `Rule` (not once per `evaluate()` call), which is also the fix for rule-count/content-length scaling, not just safety. Cost: RE2's syntax is a strict subset of Perl/PCRE (no backreferences, no lookaround) -- a pattern using either fails to compile at policy-load time with a clear error -- and this is why the core package is no longer zero-dependency, and why the Python floor moved to 3.10 (no `google-re2` wheel for 3.9).
- The **audit mechanism** (`AuditSink` implementations, including `SigningAuditSink`) is the one place a decision gets recorded — `guard run`, `guard check`, and the Python `Guard.call()` API path all produce the same record shape.
- The **CLI** grew a second entry point (`guard check`, alongside `guard explain`) specifically because the existing one couldn't express an arbitrary args shape — rather than let a policy exist that only Python callers could use, the gap became a small, tested CLI addition instead of a permanent Python-only carve-out.

## What's honestly still rough

This document is not a claim that the design is finished. Concretely, as of this writing:

- The credential-detection rule is a keyword match, not a shape detector — stated in `THREAT_MODEL.md`, not glossed over here.
- Every review this project has had was same-vendor (see `THREAT_MODEL.md`'s residual risks). That's a real gap for a security-critical library, not a footnote.
- The project has never been published or run against real-world adversarial traffic — every finding to date came from structured internal review of a codebase whose authors already knew what they were looking for.
- The audit log is per-record signed, not hash-chained — a compromised writer could drop a record silently without detection. See the Microsoft Agent Governance Toolkit citation above; not closed here.

See `docs/THREAT_MODEL.md` for the full per-pillar threat coverage and non-goals, `docs/Evaluation.md` for what was actually tested and what it found, and `docs/Architecture.md` for the component/sequence diagrams.
