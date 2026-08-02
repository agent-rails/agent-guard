# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes (see Stability below).

## [Unreleased]

## [0.1.0] - 2026-08-02

- CLI: `guard init` writes a starter policy file (YAML or JSON), refuses overwrite
  without `--force`, and loads the file after write so a broken starter never ships.
- **Security**: `Guard.from_token()` now requires an encoded, signed token string and
  verifies it internally, rather than accepting a bare `Token` object (which could be
  hand-constructed with any `trust_tier`, bypassing `min_trust_tier` policy entirely).
- **Security**: `identity.token.sign()`/`verify()` reject an empty secret; previously
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

## [0.0.1]

Initial release.

- Federated, layered, cached policy engine (`Policy`, `PolicyModule`, `PolicyRegistry`) with per-verdict explainability (`module` / `layer` / `rule_id` / `reason`).
- Runtime trust-tier enforcement (`min_trust_tier`).
- Fenced LLM judge (`LLMJudge`, `ReferenceJudge`) — clamps to a ceiling, fail-closed.
- Audit sinks: JSONL, webhook/SIEM, fan-out, memory.
- Local-first identity block: attest -> mint scoped token; local + container + remote (E2B) runtimes.
- Integration surfaces: `guard mcp` MCP gateway, `@guarded` decorator, `guard.wrap`.
- Bundled policy modules for shell / git / postgres / filesystem / kubernetes.
- `guard run` governed terminal execution.

## Stability

- Public API is everything exported from `agent_guard` and `identity` top-level packages.
- On `0.x`: breaking changes may land in minor releases, called out here and in the release notes. Pin to `~=0.0` (or an exact version) if you need stability.
- At `1.0`: semver is enforced — breaking changes only in majors, with a deprecation period.
- Ships PEP 561 type information (`py.typed`); downstream type-checkers see inline types.
