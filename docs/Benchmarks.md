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
pytest -q                  # runtime (excluding docker/gVisor/E2B-gated tests)
```

| Metric | Value |
|---|---|
| Test files | 18 |
| Tests collected | 183 |
| Tests run (excluding env-gated: docker/gVisor/E2B) | 168 passed |
| Full-suite wall time | 0.68s |

Sub-second for the full non-gated suite — cheap enough to run before every commit without friction, which is why the development process this session used (run the suite after every change, not just before a PR) was viable at all.

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

**2,373 lines** across both packages combined (`agent_guard` + `agentguard_identity`), excluding tests. Small enough that the full-suite sub-second test run and the ~45 KB wheel aren't surprising — this stayed a focused library, not a framework, through every feature added this session (identity, PoP, write-content-scan, `guard check`).
