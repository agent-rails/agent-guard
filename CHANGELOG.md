# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes (see Stability below).

## [Unreleased]

### Fixed

- Audit: a tool call terminated by a `BaseException` (for example `KeyboardInterrupt`
  from Ctrl-C, or `SystemExit`) left no audit record at all, even though the guard had
  already released the call and the tool's side effects may have landed. `Guard.call`
  and the `@guarded` decorator caught only `Exception`, so these passed straight through
  the audit path. Both now record `executed=True` with a typed error noting that dispatch
  did not return and the side-effect outcome is unknown, then re-raise the original
  exception unchanged. `Guard.wrap` inherits the fix via `Guard.call`. If the audit sink
  itself fails on this path — with an ordinary `Exception` *or* with a `BaseException` of
  its own — the original terminating exception instance still propagates, with the sink
  error chained as `__cause__`; on this path the terminating signal is never replaced by
  an audit error, so a sink raising `SystemExit(1)` can no longer mask a dispatch's
  `SystemExit(3)` or turn a Ctrl-C into an ordinary-looking exit. Not breaking: no schema
  change, and the existing `Exception` handling on the dispatch path is untouched.
- Audit: `MultiAuditSink.write` caught only `Exception`, so a `BaseException` from one
  sink aborted the fan-out and every sink queued behind it was skipped — including the
  durable local sink that exists precisely to survive a flaky remote, falsifying the
  class's own "attempts every sink" contract. The realistic trigger is the same Ctrl-C:
  one landing inside `WebhookAuditSink`'s blocking POST lost the record entirely. Every
  sink is now attempted; a terminating signal is re-raised as itself once the fan-out
  completes rather than being folded into the `RuntimeError` aggregate (which would
  swallow it), with any ordinary sink errors from the same fan-out chained as `__cause__`.
  Ordinary-`Exception` aggregation behaviour is unchanged.
- Tradeoff: a Ctrl-C mid-dispatch now blocks behind a synchronous audit write before
  propagating, where it was previously instant. Measured ~1.2s with two stubbed sinks;
  worst case is `n_sinks * 5s` with `WebhookAuditSink`'s default `timeout=5.0` and
  `MultiAuditSink`'s serial fan-out. Durable audit of a possibly-applied side effect is
  the point of the fix, so this is a deliberate exchange, not a regression — but an
  operator expecting Ctrl-C to return the prompt immediately will notice it.
- Reach in the default configuration: under `agentguard run` *without* `--audit`, the
  sink is a `MemoryAuditSink` and the `--show-audit` dump sits after the `try/finally`,
  so a `BaseException` propagates past it and the new record is written and then
  discarded with the process. Only `--audit <file>` (a `JsonlAuditSink`) actually
  persists it. The fix is real for embedded/library use and for `--audit`; it changes
  nothing observable in the bare `agentguard run` default.

## [0.2.0] - 2026-08-06

- **Breaking**: `arg_patterns` regex matching (`Policy`/`Rule`) now runs on RE2 (`google-re2`), not stdlib `re`. A policy-author-written pattern matched against attacker-controlled content could be forced into catastrophic backtracking by a small crafted payload -- a plausible pattern (`(\w+)+\d`) hung the process 5+ seconds on 31 bytes with no protection. RE2 guarantees linear-time matching by construction, eliminating that vulnerability class rather than mitigating it. Cost: RE2's syntax has no backreferences or lookaround (a pattern using either now fails to load with a clear error, not silently); the core package is no longer zero-dependency; Python floor moved from 3.9 to 3.10 (no `google-re2` wheel for 3.9). No shipped policy used either construct.
- CLI: `guard check` — companion to `guard explain` for tool shapes explain's
  `{"cmd": ...}`-only CLI can't express. Reads a `{"tool": ..., "args": {...}}`
  payload from stdin, evaluates via `Guard` (so it can also write to an audit
  sink via `--audit`), exits with the same code convention as `explain`. The
  bundled `policy.write-content-scan.example.yaml` example policy (added earlier)
  was previously reachable only from Python — this gives it a CLI path too.

## [0.1.0] - 2026-08-02

Initial public release. (An earlier `v0.0.1` git tag existed but was never published to PyPI or released on GitHub — this is the actual first release; nothing prior to it was ever installable.)

- Federated, layered, cached policy engine (`Policy`, `PolicyModule`, `PolicyRegistry`) with per-verdict explainability (`module` / `layer` / `rule_id` / `reason`).
- Runtime trust-tier enforcement (`min_trust_tier`).
- Fenced LLM judge (`LLMJudge`, `ReferenceJudge`) — clamps to a ceiling, fail-closed.
- Audit sinks: JSONL, webhook/SIEM, fan-out, memory.
- Local-first identity block: attest -> mint scoped token; local + container + remote (E2B) runtimes.
- Integration surfaces: `guard mcp` MCP gateway, `@guarded` decorator, `guard.wrap`.
- Bundled policy modules for shell / git / postgres / filesystem / kubernetes.
- `guard run` governed terminal execution.
- CLI: `guard init` writes a starter policy file (YAML or JSON), refuses overwrite
  without `--force`, and loads the file after write so a broken starter never ships.
- `Guard.from_token()` requires an encoded, signed token string and verifies it
  internally, rather than accepting a bare `Token` object (which could be
  hand-constructed with any `trust_tier`, bypassing `min_trust_tier` policy entirely).
- `agentguard_identity.token.sign()`/`verify()` reject an empty secret; previously
  accepted silently, which allowed self-signing a top-tier token with no `Broker` or
  attestation involved.
- Audit: `SigningAuditSink` — HMAC-signs each audit record via a wrapped sink. Detects
  tampering by a party without the signing secret; does not defend against a
  compromised producer (see docstring for the honest boundary).
- Identity: proof-of-possession for holder-bound tokens (`[pop]` extra). A `Token` can
  carry a `cnf` claim (an Ed25519 public-key thumbprint); `Guard.from_token()` then
  requires a fresh `PoPProof` signed by the matching private key. Wired into
  `LocalSandbox`/`ContainerSandbox`/`RemoteSandbox` via `RuntimeSpec.pop_enabled` —
  opt-in, no change to existing bearer-token behavior when unused.
- **Breaking (pre-release)**: the identity companion package is distributed as
  `agentguard_identity`, not `identity` — the latter collides with an existing,
  unrelated PyPI package (an MSAL-based auth library). Caught before this first
  release, so this is not a migration for anyone; `from agentguard_identity import ...`
  is the only form that has ever shipped.

## Stability

- Public API is everything exported from `agent_guard` and `agentguard_identity` top-level packages.
- On `0.x`: breaking changes may land in minor releases, called out here and in the release notes. Pin to `~=0.2.0` (or an exact version) if you need stability.
- At `1.0`: semver is enforced — breaking changes only in majors, with a deprecation period.
- Ships PEP 561 type information (`py.typed`); downstream type-checkers see inline types.
