# Benchmarks

Numbers measured live on this development machine, not estimated. Re-run the commands shown to reproduce; none of this is a formal, controlled benchmark environment (no dedicated hardware, no statistical trial design) — treat these as order-of-magnitude reference points, not SLA claims.

## `guard check` latency

```bash
for i in $(seq 1 8); do
  /usr/bin/time -p sh -c 'echo "{\"tool\": \"write\", \"args\": {\"content\": \"print(1)\"}}" \
    | guard check --policy policy.write-content-scan.example.yaml > /dev/null' 2>&1 | grep real
done
```

| Run | Wall time |
|---|---|
| 1st (cold) | 1.74s — one-time outlier, not reproduced on any subsequent run; not investigated further since it never recurred, but reported honestly rather than discarded |
| 2nd–8th | 0.08s – 0.10s |

**Steady state: ~90ms per invocation.** This is dominated by Python/CLI process startup (`argparse`, imports), not policy evaluation itself — the actual `Policy.evaluate()` call is a handful of regex matches over one rendered string, effectively free next to interpreter startup. Relevant for anyone considering `guard check` as a per-call hook (a Claude Code `PreToolUse` hook firing on every `Edit`/`Write`, for instance): this is the real, measured cost of that design, not a guess — see `docs/DESIGN.md`'s note on this exact tradeoff.

## Test suite

```bash
pytest --collect-only -q   # count
pytest -q                  # runtime
```

| Metric | Value |
|---|---|
| Test files | 19 |
| Tests collected | 192 |
| Result | 190 passed, 2 skipped |
| Full-suite wall time | ~6.2s |

**Corrected during review:** an earlier draft of this table reported "168 passed" from a manually `-k`-filtered run that excluded docker/gVisor/E2B-related tests wholesale. That was unnecessarily conservative — the suite already gates those tests properly with `pytest.mark.skipif` (only tests genuinely needing an unavailable environment skip: live Docker, gVisor, or an E2B account).

**Updated again, later the same development period:** the wall time jumped from ~1.1s to ~6.2s and skips dropped from 5 to 2 — not a regression, an environment change. Docker (and later a real container engine) became available partway through this project's development, so tests that used to skip now genuinely run: real container spawns, real gVisor attestation, real `guard`-check round-trips against live processes. The two still-skipped tests need `E2B_API_KEY` (a cloud account) and `runsc` specifically (gVisor's own binary, distinct from Docker itself) — neither is available on this machine. Slower now because more of the suite is doing real work, not because anything got less efficient.

Still cheap enough to run before every commit without friction, which is why the development process this session used (run the suite after every change, not just before a PR) was viable throughout — including through the additional real-container examples added later (see `docs/Evaluation.md`'s "Real autonomous-agent examples" section).

## Rule coverage vs. the script it was migrated from

```bash
grep -c 'report_finding' ~/.claude/scripts/scan-skill.sh          # 18
grep -c '^  - id:' policy.write-content-scan.example.yaml         # 11
```

18 distinct pattern checks in the original standalone script vs. 11 rules in the migrated policy — the gap is deliberate, not a regression: frontmatter-structural checks (YAML-frontmatter-aware, line-anchored) don't translate to a flat regex-over-content model and were left in the original script rather than force-fit (see `docs/DESIGN.md` and the policy file's own header comment for the specific list of what didn't migrate and why).

## Package size

```bash
python -m build && ls -la dist/*.whl
```

`agentguard-0.1.0-py3-none-any.whl`: **~44.8 KB**. Core install has zero runtime dependencies (`dependencies = []` in `pyproject.toml`); the `[pop]` extra adds `cryptography`, which is the only optional dependency this project has ever needed.

## Codebase size

```bash
find agent_guard agentguard_identity -name "*.py" | xargs wc -l | tail -1
```

**2,423 lines** across both packages combined (`agent_guard` + `agentguard_identity`), excluding tests. Small enough that the ~45 KB wheel isn't surprising — this stayed a focused library, not a framework, through every feature added this session (identity, PoP, write-content-scan, `guard check`), including the fixes found by review after each one shipped.
