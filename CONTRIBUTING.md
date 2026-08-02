# Contributing

Thanks for looking. agent-guard is early and moving — issues, real-world policies, and backends are all welcome. Read this first.

## What this is

A small, harness-agnostic library that wraps the tool-dispatch seam every agent has and decides `allow` / `deny` / `require_human` per call, with per-agent identity and an audit trail. It composes into any agent stack; it is not a framework you adopt.

## Run it

```bash
pip install -e ".[dev]"
python -m pytest -q            # fast + deterministic; docker-gated smoke tests skip without an engine
python examples/end_to_end.py  # the four pillars on your laptop
guard run --dev-trust-runtime -- echo hi
```

## Design stance (changes are measured against these)

- Fail loud at the edge. A policy with no `default` is rejected. Unverified attestation mints nothing. No silent fallbacks — if a dependency is missing, raise, don't degrade.
- Fail-closed on authorization. Missing judge, judge error, un-approved human gate → deny. The safe posture is the default.
- Capability is code, not prompt. What an agent may do is what policy and identity permit — a guarantee, not an instruction.
- Decoupled blocks. `agentguard_identity` does not import `agent_guard`; examples wire them. Keep the seams clean.
- Cross-vendor, cross-harness. Nothing may hard-depend on one model vendor or one agent framework. The LLM judge is a `complete(prompt) -> str` callable so you bring your own model.
- Explainable. Every verdict carries `module` / `layer` / `rule_id` / `reason`. Don't add a decision path that can't answer "why was this blocked?"

## Tests

- Co-locate tests, keep them fast and deterministic, no network or real containers.
- Backends that need external services (containers, E2B) are tested with injected fakes — see `tests/test_judge_and_remote.py`. Add live smoke tests behind an env-gate, never in the default suite.
- Every new rule field, sink, or backend needs coverage, including its failure mode.

## PR workflow

1. Branch from `main`. Keep diffs small and atomic — one concern per PR.
2. Open a draft PR first; mark ready after self-review.
3. State what you changed, why, and what you deliberately did NOT change.
4. Conventional commits: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.

## Good places to start

See the open issues labeled `good first issue` and `help wanted`. High-value areas: real backend verification (Docker/E2B), audit sinks (SIEM/OpenTelemetry), and real-world policy modules for common MCP servers.

## Releasing

Publishing uses PyPI Trusted Publishing (OIDC) — no API token stored. One-time setup: on PyPI, add a trusted publisher for this repo (`.github/workflows/release.yml`, environment `pypi`). Then to cut a release: bump `version` in `pyproject.toml`, tag `vX.Y.Z`, and push the tag — the `release` workflow builds and publishes. Validate locally first with `python -m build && twine check dist/*`.

## License

By contributing you agree your contributions are licensed under [Apache-2.0](LICENSE).
