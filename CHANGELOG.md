# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes (see Stability below).

## [Unreleased]

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
- On `0.x`: breaking changes may land in minor releases, called out here and in the release notes. Pin to `~=0.1.0` (or an exact version) if you need stability.
- At `1.0`: semver is enforced — breaking changes only in majors, with a deprecation period.
- Ships PEP 561 type information (`py.typed`); downstream type-checkers see inline types.
