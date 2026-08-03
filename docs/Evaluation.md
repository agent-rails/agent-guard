# Evaluation

What was actually tested, how, and what it found. This is real development history, not a constructed benchmark — every finding below happened, was independently re-verified by execution (not trusted from a commit message), and was fixed before merge. Read alongside `docs/THREAT_MODEL.md`'s residual risks: the methodology here is same-vendor internal review, and that limit is real, not a footnote.

## Methodology

Every non-trivial change went through the same loop, not a one-time audit:

1. **Adversarial review** (`worf`, a same-model-family reviewer standing in for an unavailable cross-vendor pass) — explicitly told to try to break the change, not confirm it works. Every review is labeled `cross_vendor: false` in its own output; agreement between it and the original author is weaker evidence than a genuinely different architecture would provide, and every review says so.
2. **Live reproduction, not trust** — every fix worf proposed was independently reproduced by executing the original exploit against the *old* code, then confirming it failed against the *new* code, before the fix was considered done. Several findings below were themselves caught this way (a review claim turned out to be wrong on first read, and re-testing found the actual truth).
3. **Fix-and-re-review loop** — a fix commit got its own follow-up review scoped to just that commit, not a rubber-stamp. Several fixes introduced *new* bugs that a second pass caught (see below) — the loop existing at all is what caught those.

## Findings, by development stage

### Identity hardening (`Guard.from_token`, `sign`/`verify`)

| Finding | Severity | How found | Verified |
|---|---|---|---|
| `from_token` accepted a bare, hand-constructable `Token` object — defeats the entire point of requiring a verified token | HIGH | worf, adversarial review | Reproduced live: forged `Token(trust_tier="remote.microvm", ...)` granted top tier before the fix, rejected after |
| `sign()`/`verify()` accepted an empty secret silently | HIGH | worf, adversarial review | Reproduced live: a self-signed token with `secret=b""` worked before the fix, rejected after |
| `SigningAuditSink`'s docstring claimed defense against a "compromised producer" — false, since the producer holds the same secret it signs with | HIGH (doc/threat-model accuracy) | worf | Corrected to the honest, narrower guarantee; test added asserting a party *with* the secret can still forge (locks in the limit rather than hiding it) |
| A "regression test" for the NaN-freshness fix mutated a valid proof's timestamp *after* signing, so it failed at signature verification, never reaching the code path it claimed to guard | MEDIUM (test validity) | worf, mutation-testing the test itself | Confirmed by removing the fix and watching the old test still pass; rewrote to sign a genuinely NaN-timestamped proof |

### Proof-of-possession (`identity/pop.py`)

| Finding | Severity | How found | Verified |
|---|---|---|---|
| `verify_pop`'s own docstring promised "never raises" — a malformed base64 `public_key` or non-ASCII `token_binding` raised uncaught exceptions instead | MEDIUM | worf | Reproduced both crash inputs live before the fix, confirmed clean `False` returns after |
| `ContainerSandbox`'s PoP wiring had zero non-Docker test coverage — a regression could pass CI silently since the only tests touching it were Docker-gated and skipped | LOW | worf | Confirmed the gap was genuinely closable without Docker (pure Python construction), added 3 tests |

### Write-content-scan policy (`policy.write-content-scan.example.yaml`)

| Finding | Severity | How found | Verified |
|---|---|---|---|
| README claimed `guard check` worked from the CLI — it didn't exist yet (`guard`'s subcommands were `run`/`mcp`/`rules`/`explain`/`init`) | HIGH | worf | Confirmed live: `guard check` returned an argparse error |
| Evaluating with `{"path": ..., "content": ...}` together denied any file merely *named* `secrets.yaml`/`tokens.ts`, regardless of content — the policy engine renders the whole args dict into one matched string | HIGH | worf | Reproduced live: benign content, sensitive filename → denied before the fix, allowed after (content-only calling convention) |
| `base64`-shaped pattern denied legitimate `yarn.lock`/`package-lock.json` integrity hashes | HIGH | worf | Reproduced the exact lockfile-hash string, confirmed deny before / allow-but-logged after |
| Two tests passed for the wrong reason: one matched on the literal word "credentials" (not a credential shape), the other's `rule_id` assertion no longer held after `base64-blob`'s severity changed | MEDIUM | worf | Renamed/rewritten to assert what they actually test; a new test explicitly documents the credential-shape-detection gap as a known limitation rather than pretending it's covered |
| Deny-before-allow rule ordering (a load-bearing safety property — first-match-wins means a deny rule appended after an allow rule could be silently masked) was held only by hand-ordering the YAML file, with nothing pinning it | LOW | worf | Added a test asserting the invariant directly, so a future edit that violates it fails a named test instead of silently degrading |

### `guard check` CLI

| Finding | Severity | How found | Verified |
|---|---|---|---|
| A JSON array/scalar/null/bool, or `{"tool": 123, ...}`, crashed with an unhandled traceback leaking absolute filesystem paths to stderr, instead of the documented clean "usage error" | HIGH | worf | Reproduced all five original crash payloads live before the fix; confirmed clean exit-1 messages after, with **mutation testing** (reverting the fix and re-running the new tests, watching them go red) confirming the new tests weren't vacuous |
| A `subprocess.run` monkeypatch test for "check never executes anything" could never actually fire, since `_check` never wires a dispatch function at all — the test was structurally incapable of failing | LOW | worf | Replaced with a test patching `Guard.call`/`Guard.wrap` directly — the actual mechanism that would prove the claim if it were ever violated |

### Package naming (`identity` → `agentguard_identity`)

| Finding | Severity | How found | Verified |
|---|---|---|---|
| Top-level `identity` package name collided with an existing, unrelated published PyPI package (an MSAL-based auth library) — both would install a same-named directory into `site-packages/`, undefined result | HIGH | worf, cross-checked against a live PyPI fetch | Confirmed the real PyPI package exists; confirmed the built wheel's own contents before and after the rename |

### Documentation accuracy (found without worf, by direct verification)

| Finding | Severity | How found | Verified |
|---|---|---|---|
| README claimed "Published as `agentguard` on PyPI" — false; nothing has ever been published | HIGH (factual claim) | Direct `curl` against the PyPI API | 404 confirmed live, both before and after every subsequent fix |
| The first fix's install syntax (`url#egg=package[extra]`) only worked because it was tested against an outdated `pip` (21.2.4) — current `pip` (26.0.1) rejects it outright | HIGH | worf, then independently reproduced | Confirmed the exact failure on current `pip`, confirmed the corrected PEP 508 direct-reference syntax works on **both** old and new `pip`, including with a branch ref |
| A quote-escaping style difference caused 3 consecutive CI failures — `ruff check` (run locally throughout) and `ruff format --check` (never run locally) are separate checks; only the former was ever verified before push | HIGH (process gap) | CI failure, root-caused directly (not by worf) | Fixed; both checks now run locally before every push |

## What this reveals, in aggregate

- **The dominant error class was overclaiming in docs/tests relative to what the code actually does** — a nonexistent CLI subcommand, an audit sink's docstring claiming a defense it didn't provide, tests whose names implied more coverage than their assertions delivered. Not memory-safety bugs or crypto flaws — confident, plausible-sounding claims that didn't hold up under a second, adversarial read.
- **Nearly every "fix" round introduced or revealed something new**, which is why the loop (review → fix → re-review) mattered more than any single review pass. A fix for one finding twice broke something else (the PoP wiring, the `guard check` stdin-encoding change) that only a follow-up pass caught.
- **Version/environment assumptions were a real, repeated source of false confidence** — an install command tested on stale `pip`, a linter check never run locally even though CI ran it. "Verified locally" quietly meant "verified against this one environment" more than once.
- **No cross-vendor review has happened for any of this.** Every finding above came from a same-model-family reviewer. That is the single largest unaddressed gap this evaluation can honestly report, not a caveat to bury — see `docs/THREAT_MODEL.md`.
