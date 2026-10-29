# Changelog

Notable changes. This project follows [Semantic Versioning](https://semver.org). While on `0.x`, minor versions may include breaking changes (see Stability below).

## [Unreleased]

### Added

- `guard hook claude-code --policy PATH --audit PATH --mode enforce|observe`: a Claude Code `PreToolUse` adapter for the Bash tool. Bash maps to tool `shell` with args `{"cmd": command}`; `description`, `timeout` and `run_in_background` go to the audit record only. Any `tool_name` other than exactly `Bash` is a fault. In enforce mode a deny exits 2 with a stop-and-ask reason; `require_human` returns `permissionDecision: "ask"` only in permission modes `default`, `acceptEdits`, `plan` and `dontAsk`, and exits 2 in any other, missing or non-string mode; allow exits 0 with empty stdout; any fault exits 2. It never emits `allow`. A given policy that fails to load blocks and never falls back to defaults. Observe mode always exits 0 and audits the would-be decision. The audit file is opened with `O_NOFOLLOW` (a symlinked path is a fault) and set to `0600` on every write. The stored command gets best-effort masking of the listed shapes (URL userinfo in any scheme, `Authorization`/`Bearer`, `X-Api-Key`, secret-named assignments including quoted values, `--password`, `curl -u user:pass`, `mysql -p<pass>`, known token prefixes); other secrets in command text are stored. The hook flags are a persisted wire format in users' settings files. This is a guardrail tier, not a security boundary; see `docs/claude-code-hook.md`.
- `guard install claude-code --mode enforce|observe [--scope user|local|project] [--policy PATH] [--audit PATH] [--check] [--uninstall]`: one command to wire the hook. Matcher `^Bash$`, `timeout: 10`, `onFailure: "block"` in enforce mode on Claude Code 2.1.295 and later. The command uses an absolute interpreter with `python -I`; in enforce mode a shell wrapper turns any exit other than 0 or 2 into 2, and in observe mode `|| exit 0` turns any failure into a pass. The agent-visible recovery hint names only `guard install claude-code --check`; the uninstall step is printed to the terminal by install and by `--check` when it reports a problem. Without `--policy`, install writes a hook-specific starter policy (separate from `guard init`, which is unchanged): deny `rm` with recursive and force flags in any case, order or long form; require a human for force push in any form and for Bash commands that name `guard install`, `agent_guard`, `disableAllHooks`, `.claude/settings` or the written policy and audit paths. Install refuses invalid settings, removes its existing entries and appends one new entry, writes atomically through symlinks with a UTC-stamped backup (backups accumulate; nothing prunes them), aborts if the file changed (a writer between the final check and the rename is still overwritten), runs the exact installed command through a fault probe, a benign call and a deny canary, and rolls back on any failure or exception, including Ctrl-C. `--check` refuses an entry whose command is not exactly what install writes or whose interpreter is not the one running `guard`, never runs it, re-runs the self-test on the rebuilt command, and flags a stale matcher or a missing `onFailure`.
- `guard report [--audit PATH]`: a local summary of the hook's audit log that separates `NOT FIRING`, `FIRING, FAULTING`, `FIRING, CLEAN` and `FIRING`, with first and last event, enforced and observed outcome counts, top rules, events per session, fault count, and a `disableAllHooks` warning. Self-test events are excluded. Rows that are not objects or lack a timezone-aware ISO `ts` are counted as unreadable, and printed agent ids, rule ids, paths and warnings have control characters escaped. No network access.
- `guard report --flagged`: also lists `deny` and `require_human` decisions, any outcome, grouped by rule id (`policy default` when there is none), one line per call with timestamp, agent id, decision, outcome, `cmd_len` and an escaped 160-code-point excerpt of the stored command; `flagged calls: none` when there are none. Matching rows with missing or malformed fields are not listed and are counted on a `flagged rows skipped` line. Self-test and fault rows are excluded, and output without the flag is unchanged. It reads the audit log only: `observed` is not `executed`, and it lists what the policy flagged without judging whether the policy is right.
- `guard replay --policy CANDIDATE [--audit PATH] [--against-policy CURRENT] [--must-block FILE]`: re-evaluates the stored command of every decision row in the hook's audit log with `Policy.evaluate("shell", {"cmd": ...})` against the candidate and against `--against-policy`, or against the logged decision when that flag is absent (that baseline mixes every policy live while the log was written). It lists every row whose decision changes, grouped by transition (`deny -> allow`), with timestamp, agent id, rule before and after, and an escaped 160-code-point excerpt. Self-test, fault and unreadable rows are excluded and counted; decision rows without a string `args.cmd` or `args.cmd_sha256`, or without a valid logged decision when that is the baseline, are counted as skipped. It evaluates the stored text, so it also counts the rows whose stored text differs from the command that ran (masked, or cut at 2048 bytes). `--must-block FILE` takes a JSON array of non-empty command strings, evaluates each as one command against the candidate, and lists every one the candidate allows; `require_human` is not a breach. Exits 3 when any must-block command is allowed, otherwise 0 (changes alone do not fail it). Exits 1 with no report when the audit file is missing or unreadable or has a line nested too deeply to parse, no row is replayable, a policy fails to load, a policy has a `judge` rule, or the must-block file is unreadable, not a JSON array, empty, or holds an entry that is not a non-empty string. Reads only: no network, no judge, no audit writes, and it never applies the candidate.
- CI runs the hook, install and report suites on Linux and macOS.

- `guard run --outcome-file PATH` publishes the run's outcome as JSON, separate from the exit status (`outcome` is `completed`, `blocked`, `refused`, `spawn_failed` or `usage_error`; `exit_code` is the command's own status, `null` unless it ran). Exit codes 2 and 3 collided with command statuses because `guard`'s verdict and the command's status shared one channel. `guard` writes the file only after the command exits, atomically through an exclusively created staging file (mode `0600`), so a missing file means no outcome was published for this invocation, not that the command did not run. Before parsing arguments it removes a stale file at `PATH` only if it is recognisably a guard outcome, and it never deletes any other file; once arguments parse it clears `PATH` and checks that it is writable, so an unusable path fails before the command runs. The file's integrity is the filesystem permission on `PATH`: under `--runtime local` the command runs as the invoking user and can modify paths that user can, so place `PATH` where the command cannot write or use `--runtime container`. If publishing fails the command's exit code is kept and the failure is printed to stderr. `--outcome-file` may not be the `--audit` file (checked by path and file identity before anything is cleared). Exit codes are unchanged.
- `Guard.call()` and `@guarded` now write a call-bound release event before dispatch and a terminal event afterward. Both share a call ID and SHA-256 digest over the agent, trust tier, tool, arguments, and policy verdict. `unresolved_releases()` identifies retained release events without a matching terminal event. MCP result reconciliation remains outside this change because the proxy does not observe downstream outcomes.
- Lifecycle fields are optional and excluded from the signed body when absent, preserving verification of existing per-record HMACs.
- If persisting the release event fails, dispatch is not called and a best-effort terminal event with `outcome="not_dispatched"` and `executed=false` closes the release, so `unresolved_releases()` no longer reports a call that never ran. If that close-out write also fails, the release stays unresolved, which now means either possibly-applied or never dispatched.

### Changed

- **Breaking (0.x):** async tool functions and async dispatch callables are rejected with `AsyncDispatchError`. In 0.2.0 an `async def` tool wrapped by `@guarded` or `Guard.call` returned a coroutine that the caller could await, but its audit record claimed success before the body ran. There is no async surface yet; call async tools through your own boundary or wait for an `acall()`.
- **Breaking (0.x):** custom human approvers must return `ApprovalGrant(call_id, call_digest)` for the exact request; previous boolean callbacks now fail closed. `ApprovalRequest` exposes the call binding and verdict context.
- **Breaking (0.x):** tool arguments are frozen into one canonical JSON form at the boundary, and that single form is what the policy evaluates, the approver is shown, the digest binds, the audit records and the tool receives. Arguments must be JSON-serializable: a `datetime`, `bytes`, `set`, NaN, a lone surrogate, mixed-type dict keys or a circular reference is now blocked with an audited `decision`/`blocked` record (`rule_id="args-not-canonical"`, empty `args`) and `BlockedError`; `Guard.decide()` returns `(False, deny)`. Previously these dispatched. Tuples arrive as lists and non-string dict keys as strings. Nesting deeper than 64 levels is blocked the same way. An LLM judge receives a detached copy, so it cannot change what is dispatched after static policy has run. `guard mcp` and `guard check` inherit this: a `tools/call` or payload with NaN or other non-canonical arguments is now denied (it was forwarded or allowed before), and its audit record carries empty `args` (decided by an internal marker, not by a rule id, so a policy rule cannot blank the arguments of other calls). A message nested too deeply to parse is rejected by `guard mcp` and makes `guard check` exit 1, where both previously crashed.
- **Breaking (0.x):** `@guarded` binds positional arguments to the function's parameter names, so the policy, approver, digest and audit record cover them (previously positional arguments bypassed all four). The function now runs on the canonical copy, not the caller's objects: a mutable out-parameter is no longer written through, and a non-JSON argument such as a lock or socket is blocked. A keyword passed through `**kwargs` that shadows a positional-only parameter name raises `TypeError`. Omitted default values are bound too, so the policy sees what the tool will run with; a default that is not JSON-serializable blocks the call. Decorating an instance method or classmethod now blocks every call, because `self` and `cls` are not JSON; decorate a plain function instead. A `functools.partial` that freezes positional arguments is rejected at decoration time because those values would be invisible to the policy; bind them by keyword.
- **Breaking (0.x):** one allowed call now produces two `executed=true` records (`release` and `terminal`). Consumers that count executions must filter on `event`.

### Fixed

- The Claude Code hook's starter `block-rm-rf` rule no longer reads a `--rm` flag as the `rm` command. `docker run --rm img pwsh -NoProfile` was denied because `\brm\b` matches after a hyphen and `-NoProfile` looks like a recursive force flag. A double-dash `--rm` that follows whitespace or a hyphen is now skipped; `rm` after a single hyphen (`${x:-rm}`, `git-rm`, `x-rm`) or a `--rm` glued to other text (`v=--rm`) is still matched. The rule remains a text pattern over the command, not command identification: a command word built at run time (variables, `eval`, functions, command substitution) can evade it, as it could before. The starter policy is written only when no policy file exists, so an existing policy file keeps the old pattern until it is edited or deleted and regenerated.
- CLI: `guard run --outcome-file` could clear the configured policy file when both options referred to the same path, then fail while loading the now-missing policy. The CLI now rejects outcome/policy path aliases before clearing either file; direct, symlink, and hard link collisions leave the policy intact.
- CLI: `guard run` and `guard explain` re-joined the command's argv with spaces before
  handing it to `shell=True`, so the command that executed was not the command the
  operator typed: `guard run -- sh -c 'exit 42'` ran `sh -c exit 42` and exited 0, quoting
  that suppresses glob expansion was stripped and then re-interpreted, and whitespace
  inside an argument was collapsed. The audit record and the policy engine saw the same
  mangled string, so this was a fidelity defect and not a policy bypass. Both commands now
  render argv with `shlex.join`, so the shell re-parses exactly the argv that was passed
  and the recorded `cmd` is a faithful, re-executable rendering. **Breaking:** shell
  operators in separate arguments (`;`, `|`, `&&`, `$VAR`, globs) are now quoted and
  reach the command literally. To use shell syntax, pass it as one argument to a shell:
  `guard run -- sh -c 'a | b'`. A `--` that is part of the command (`rm -- -f`) is now
  kept; only the leading separator is removed. Policy rules match over the rendered
  string, which is unchanged for unquoted tokens. For the `shell` tool an argument that
  contains whitespace or shell metacharacters is now quoted, so a custom rule anchored
  with `$` or spanning such an argument may need updating; `guard explain --tool <other>`
  still joins with spaces, since quoting means nothing to a non-shell tool. Closes #48.
- Audit: passing an `async def` callable as `dispatch` wrote `terminal`/`returned` at coroutine creation, before the tool body had run, so the audit trail attested a successful call that had not happened and any later failure went unaudited. `Guard.call`, `Guard.wrap` and `@guarded` now raise `AsyncDispatchError` (a `TypeError`) when dispatch returns an awaitable or an async generator, which is what `async def` produces. A coroutine that never started is closed and the terminal event is `raised`; anything else (a `Task`, `Future`, async generator) may already be running or run later, is left untouched, and is recorded as `unknown`. Other lazy results (sync generators, async iterator objects, async iterables) are ordinary values and stay `returned`.
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
  `SystemExit(3)` or turn a Ctrl-C into an ordinary-looking exit. If a normal dispatch
  exception and a terminal audit write both fail with ordinary exceptions, the dispatch
  exception remains primary and the audit failure is chained above any cause it already
  carried; an operator signal (`KeyboardInterrupt`, `SystemExit`) raised by the sink
  outranks an ordinary dispatch exception and propagates instead. The same precedence applies to the best-effort `not_dispatched` close-out: an operator signal raised while closing a failed release replaces the release error, which stays as `__context__`. Chaining skips a link that would create a `__cause__` cycle, such as a sink re-raising the dispatch exception object itself. Existing records without lifecycle fields keep their
  original HMAC verification behavior.
- Audit: `MultiAuditSink.write` caught only `Exception`, so a `BaseException` from one
  sink aborted the fan-out and every sink queued behind it was skipped — including the
  durable local sink that exists precisely to survive a flaky remote, falsifying the
  class's own "attempts every sink" contract. The realistic trigger is the same Ctrl-C:
  one landing inside `WebhookAuditSink`'s blocking POST lost the record entirely. A first
  `KeyboardInterrupt` or `SystemExit` from a sink no longer aborts the fan-out: the
  remaining sinks are still attempted and the signal is re-raised as itself afterwards,
  rather than being folded into the `RuntimeError` aggregate (which would swallow it).
  Two deliberate limits bound that hold. A *second* operator signal aborts the fan-out
  immediately and the remaining sinks are not attempted — a repeated Ctrl-C is an
  unambiguous instruction to stop, and an operator must not be able to lose their escape
  hatch by having audit hold it; the *first* signal is still what propagates, so a later
  sink can never replace the exception type or the `SystemExit` code, and the second
  instance is attached to it as `__context__`. And only `KeyboardInterrupt` and
  `SystemExit` are held at all: `asyncio.CancelledError`, `GeneratorExit` and every other
  `BaseException` propagate at once with the remaining sinks unattempted, because holding
  a cancellation across a later blocking sink write is how cooperative cancellation and
  `Task.cancel()` timeouts get broken. Ordinary-`Exception` aggregation behaviour is
  unchanged, except that the aggregate is now chained onto the signal *above* any
  `__cause__` the signal already carried rather than overwriting it.
- Tradeoff: a Ctrl-C mid-dispatch now blocks behind a synchronous audit write before
  propagating, where it was previously instant. There is no general bound on that delay.
  A `WebhookAuditSink` costs on the order of its `timeout` (default 5s) per sink, but
  that is nominal rather than a ceiling: `timeout` is handed to
  `urllib.request.urlopen`, which applies it per socket operation and not as a deadline
  for the whole request, so a server that trickles bytes resets it on every read. And
  `MultiAuditSink` fans out to arbitrary sinks, so a third-party sink that retries
  internally can delay termination indefinitely. The escape hatch is a second Ctrl-C,
  which aborts the fan-out immediately and propagates the first signal — repeated
  interrupts end the wait even where no per-sink bound applies. Durable audit of a
  possibly-applied side effect is the point of the fix, so the first interrupt's delay is
  a deliberate exchange, not a regression — but an operator expecting Ctrl-C to return the
  prompt immediately will notice it.
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
