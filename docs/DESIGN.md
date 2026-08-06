# Design

The "why" document. `README.md` is how to use agent-guard; `docs/WALKTHROUGH.md` is a guided tour; this is the reasoning behind the shape it took — including the decisions that got revised mid-flight, and why.

## The thesis

An agent running with its operator's full permissions, with no record of what it did, is a single prompt injection away from touching everything the human could touch. The fix has to live **outside the model's influence** — a static, provable boundary in front of the tool-dispatch seam, not a request to the model to police itself.

That constraint drives almost every other decision in this project:

- **Deterministic policy, not an LLM judging its own output.** A rule either matches or it doesn't; the decision is reproducible, testable, and not attackable by the thing it's supposed to constrain. An `LLMJudge` exists, but it can only *tighten* a verdict toward `require_human` within a rule's ceiling — it is advisory within hard bounds set by static policy, never the boundary itself.
- **Identity, authorization, and audit as three distinct concerns**, not one blob. `agentguard_identity` does not import `agent_guard`, and vice versa — the block boundary is deliberate. Identity answers *who/where*; the guard answers *what*; the audit sink answers *did*. Coupling them would make each harder to reason about, test, and reuse independently.

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

See `docs/THREAT_MODEL.md` for the full per-pillar threat coverage and non-goals, `docs/Evaluation.md` for what was actually tested and what it found, and `docs/Architecture.md` for the component/sequence diagrams.
