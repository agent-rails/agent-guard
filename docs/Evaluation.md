# Evaluation

What was tested and what it found — real development history, not a constructed benchmark. Every finding below was verified by execution and fixed. Read alongside `docs/THREAT_MODEL.md`'s residual risks.

## Findings, by development stage

### Identity hardening (`Guard.from_token`, `sign`/`verify`)

| Finding | Severity | Resolution |
|---|---|---|
| `from_token` accepted a bare, hand-constructable `Token` object — defeats the entire point of requiring a verified token | HIGH | Forged `Token(trust_tier="remote.microvm", ...)` granted top tier before the fix, rejected after |
| `sign()`/`verify()` accepted an empty secret silently | HIGH | A self-signed token with `secret=b""` worked before the fix, rejected after |
| `SigningAuditSink`'s docstring claimed defense against a "compromised producer" — false, since the producer holds the same secret it signs with | HIGH (doc/threat-model accuracy) | Corrected to the honest, narrower guarantee; test added asserting a party *with* the secret can still forge (locks in the limit rather than hiding it) |
| A "regression test" for the NaN-freshness fix mutated a valid proof's timestamp *after* signing, so it failed at signature verification, never reaching the code path it claimed to guard | MEDIUM (test validity) | Removing the fix left the old test passing; rewritten to sign a genuinely NaN-timestamped proof |

### Proof-of-possession (`identity/pop.py`)

| Finding | Severity | Resolution |
|---|---|---|
| `verify_pop`'s own docstring promised "never raises" — a malformed base64 `public_key` or non-ASCII `token_binding` raised uncaught exceptions instead | MEDIUM | Both crash inputs raised before the fix; clean `False` returns after |
| `ContainerSandbox`'s PoP wiring had zero non-Docker test coverage — a regression could pass CI silently since the only tests touching it were Docker-gated and skipped | LOW | Gap closable without Docker (pure Python construction); 3 tests added |

### Write-content-scan policy (`policy.write-content-scan.example.yaml`)

| Finding | Severity | Resolution |
|---|---|---|
| README claimed `guard check` worked from the CLI — it didn't exist yet (`guard`'s subcommands were `run`/`mcp`/`rules`/`explain`/`init`) | HIGH | `guard check` returned an argparse error |
| Evaluating with `{"path": ..., "content": ...}` together denied any file merely *named* `secrets.yaml`/`tokens.ts`, regardless of content — the policy engine renders the whole args dict into one matched string | HIGH | Benign content with a sensitive filename denied before the fix, allowed after (content-only calling convention) |
| `base64`-shaped pattern denied legitimate `yarn.lock`/`package-lock.json` integrity hashes | HIGH | The exact lockfile-hash string: deny before, allow-but-logged after |
| Two tests passed for the wrong reason: one matched on the literal word "credentials" (not a credential shape), the other's `rule_id` assertion no longer held after `base64-blob`'s severity changed | MEDIUM | Renamed/rewritten to assert what they actually test; a new test explicitly documents the credential-shape-detection gap as a known limitation rather than pretending it's covered |
| Deny-before-allow rule ordering (a load-bearing safety property — first-match-wins means a deny rule appended after an allow rule could be silently masked) was held only by hand-ordering the YAML file, with nothing pinning it | LOW | Added a test asserting the invariant directly, so a future edit that violates it fails a named test instead of silently degrading |

### `guard check` CLI

| Finding | Severity | Resolution |
|---|---|---|
| A JSON array/scalar/null/bool, or `{"tool": 123, ...}`, crashed with an unhandled traceback leaking absolute filesystem paths to stderr, instead of the documented clean "usage error" | HIGH | All five crash payloads triggered before the fix; clean exit-1 messages after. Reverting the fix turns the new tests red, confirming they aren't vacuous |
| A `subprocess.run` monkeypatch test for "check never executes anything" could never actually fire, since `_check` never wires a dispatch function at all — the test was structurally incapable of failing | LOW | Replaced with a test patching `Guard.call`/`Guard.wrap` directly — the actual mechanism that would prove the claim if it were ever violated |

### Package naming (`identity` -> `agentguard_identity`)

| Finding | Severity | Resolution |
|---|---|---|
| Top-level `identity` package name collided with an existing, unrelated published PyPI package (an MSAL-based auth library) — both would install a same-named directory into `site-packages/`, undefined result | HIGH | The real PyPI package exists; the built wheel's contents confirmed before and after the rename |

### Documentation accuracy

| Finding | Severity | Resolution |
|---|---|---|
| README claimed "Published as `agentguard` on PyPI" — false; nothing has ever been published | HIGH (factual claim) | PyPI API returns 404 for the package |
| The first fix's install syntax (`url#egg=package[extra]`) only worked because it was tested against an outdated `pip` (21.2.4) — current `pip` (26.0.1) rejects it outright | HIGH | The exact failure reproduces on current `pip`; the corrected PEP 508 direct-reference syntax works on **both** old and new `pip`, including with a branch ref |
| `ruff check` and `ruff format --check` are separate checks; a quote-escaping style difference passed `ruff check` but failed `ruff format --check` | HIGH | Fixed; both checks are part of the lint step |

### Core matching engine (`Policy._render_args`)

| Finding | Severity | Resolution |
|---|---|---|
| `_render_args` used `json.dumps` to flatten args for regex matching; JSON escapes a real newline as the literal characters backslash+n, and since `n` is a word character, that silently defeated every `\b`-anchored deny rule whenever the flagged content started a new line -- the single most common real-world position for it | HIGH | Direct `re.search` against the rendered string reproduces the bug; the fix resolves it with the same repro before/after |
| The fix itself introduced a NEW regression: preserving real newlines meant a bare `.` (no DOTALL) no longer crossed them, so the `pipe-to-shell` rule's `curl ... \<newline>\| sh` pattern silently stopped matching a valid shell line-continuation -- a bypass the OLD buggy code had accidentally still caught | HIGH | Continuation-split payload: denied under old code, allowed under the first fix, denied again after correcting the pattern to `[\s\S]*?` |
| Nested list/dict/tuple arg values still hit the original word-boundary bug via `str()`'s `repr()`, which re-escapes embedded newlines the same way `json.dumps` did | MEDIUM | A list-wrapped value containing a newline triggers it; added `_flatten_value` to recurse to actual string leaves before joining |
| `sorted(dict.items())` in the new nested-value handling crashes with `TypeError` on a dict with mixed/uncomparable key types -- a regression from the old `str(value)` render, which just stringified without sorting | LOW | A mixed int/str-keyed dict triggers the `TypeError`; fixed by sorting on `str(key)` instead |

### Real autonomous-agent examples (`examples/guarded_autonomous_agent/`)

Every example before this point proved the mechanism against scripted, hardcoded tool-call sequences. These prove it against a genuinely autonomous Claude agent making its own decisions via the real Anthropic API, inside a real Docker container agent-guard actually spawned and attested.

| Finding | Severity | Resolution |
|---|---|---|
| The first version built shell commands directly from model-supplied paths (`f"cat {path}"`, executed via `docker exec ... sh -c`) -- command injection, and it also fully defeated the deny policy: shell globs (`/e?c/passwd`), quote-splitting, and direct injection (`config.toml; id`) all bypassed a regex denylist over pre-shell text | BLOCKER | All five bypasses executed root shell commands inside the container; fixed with structural path validation (pure lexical `posixpath.normpath`, a character denylist, `shlex.quote` as defense-in-depth) plus a real, separate Policy-layer deny scenario so the demo still exercises actual authorization, not just input sanitization |
| The holder-bound-identity (PoP) example's theft simulation caught bare `ValueError` without checking the message -- a wrong secret or expired token would raise the same exception type and print a misleadingly reassuring "correctly refused" line for the wrong reason | MEDIUM | With a wrong secret, the old code printed a false-positive "correctly refused"; the new code asserts `"pop_proof"` appears in the message, catching the mismatch |
| The same PoP example's docstring claimed protection against "a captured network hop" -- overstated. `verify_pop`'s 60-second freshness window is deliberately generous, not single-use (no nonce/replay tracking), so a proof captured *alongside* its token (a genuine on-the-wire capture) is replayable within that window | MEDIUM | Corrected to the honest claim actually proven: the bearer string alone is insufficient (the point of holder-binding over a plain bearer token), not immunity to a full request capture |
| A prompt-injection scenario overclaimed the agent was "genuinely manipulated" into a denied call, but the prompt ("read each file") already predicted that read regardless of any injection -- a confound; the restricted file was read LAST, in listing order not injection-priority order, and the agent's own text explicitly said it did not follow the injected instruction, in both runs | BLOCKER | Prompt narrowed so nothing else explains a restricted-file read except the injection; re-run twice with the confound removed -- the agent's own alignment (Claude Opus) recognized and refused the injection both times. The scenario reports this honest negative result |
| The confound was not fully eliminated: locating the target file still requires a directory listing that reveals the restricted file's existence through a channel independent of the injection (existence-knowledge, not a motive) -- "the only explanation available" overstated this | MEDIUM | Softened to "the strongest explanation available, not strictly the only one," conditioned on whether a listing occurred; the updated detection logic is verified against fabricated audit records since the branch has never fired on a real (resistant) run |
