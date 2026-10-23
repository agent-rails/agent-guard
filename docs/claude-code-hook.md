# Claude Code hook adapter

`guard hook claude-code` is a Claude Code `PreToolUse` hook that runs every Bash tool call through an agent-guard policy before it executes. `guard install claude-code` wires it into Claude Code settings in one command and self-tests it. `guard report` shows whether it is firing.

## Tier: guardrail, not a boundary

This is a **guardrail tier**. It stops honest agent mistakes and non-adaptive prompt injection that issue a recognisable Bash command that the policy names, such as `rm -rf ...` or `git push --force` in the starter policy. It is **not a security boundary**, and it does not stop an adaptive or compromised agent:

- At user, local or project scope, the hook, its policy, its audit log, the Python environment and the Claude Code settings files are all writable by the same user the agent's Bash tool runs as. An agent that wants to can edit or remove the hook, or start a nested `claude --bare` or `--safe-mode` session (both skip hooks).
- Policy rules are regular expressions over command text. The starter catches case and flag-order variants of `rm -rf` and `git push --force` within one simple command, but shell indirection still defeats it. Known gaps: quoting inside the name (`r''m -rf`, `"rm" -rf`), variables or aliases (`$RM -rf`, `X=-rf; rm $X`), command substitution and backticks, abbreviated long options (`--recur`), base64 or other encoded payloads piped to `sh`, interpreter one-liners (`python -c 'shutil.rmtree(...)'`), `find -delete`, flags split across `;`, `&&` or `|`, and writing a script and then running it. The control-plane rule matches the policy and audit paths literally, so `~`, `$HOME`, relative or variable spellings of those paths are not caught.
- Each call is judged alone. A sequence of individually harmless calls is not detected.

For containment, use credentials scoped to the task, network egress controls, Claude Code's own sandboxing, or a container. The hook complements these. It does not replace them.

## Quick start

```bash
pip install toolcall-authz
guard install claude-code --mode observe     # audit only, never blocks
# ... use Claude Code normally for a while ...
guard report                                 # what would have been blocked
guard install claude-code --mode enforce     # turn on blocking
```

`--mode` is required. No default is chosen for you, so the hook cannot be observing while you believe it is enforcing.

Without `--policy`, install writes a hook-specific starter policy to `${XDG_CONFIG_HOME:-~/.config}/agent-guard/claude-code-policy.json` if that file does not exist yet. It is separate from the `guard init` starter and has three `shell` rules:

| Rule | Decision | Matches |
|---|---|---|
| `block-rm-rf` | deny | `rm` with recursive and force flags in any case, order or long form (`-rf`, `-fR`, `-r -f`, `--recursive --force`) within one simple command |
| `gate-agent-guard-control-plane` | require_human | `guard install`, `agent_guard`, `disableAllHooks`, `.claude/settings`, and the literal policy and audit paths written at install |
| `gate-force-push` | require_human | `git ... push` with `--force`, `--force-with-lease`, `-f` in a flag group, or a `+refspec` |

With `--policy`, your file is used as is and gets none of these rules. The audit log defaults to `${XDG_STATE_HOME:-~/.local/state}/agent-guard/claude-code.jsonl`, mode `0600`.

| Flag | Meaning |
|---|---|
| `--mode enforce\|observe` | Required to install. `observe` never blocks and audits the would-be decision |
| `--scope user\|local\|project` | `~/.claude/settings.json` (default), `.claude/settings.local.json`, or `.claude/settings.json` in the current directory. Project scope commits a machine-specific path and lets the repository control the hook |
| `--policy PATH`, `--audit PATH` | Use your own policy or audit file |
| `--check` | Re-validate the installed entry and re-run the self-test. Refuses an entry whose command is not exactly what install writes, or whose interpreter is not the one running `guard`, and never runs it |
| `--uninstall` | Remove only the agent-guard entry |

## What install does

1. Reads the settings file and refuses to touch it if it is not valid JSON or if `hooks` or `hooks.PreToolUse` has an unexpected type.
2. Loads the policy through the same loader the hook uses and refuses if it does not load.
3. Builds one hook entry with matcher `^Bash$`, `timeout: 10`, and, in enforce mode on Claude Code 2.1.295 or later, `onFailure: "block"`. The command is:

   ```text
   <absolute python> -I -m agent_guard.cli hook claude-code --policy <abs> --audit <abs> --mode enforce || { [ $? -eq 2 ] || echo 'agent-guard hook failed, command blocked. Recovery from a terminal: guard install claude-code --check.' >&2; exit 2; }
   <absolute python> -I -m agent_guard.cli hook claude-code --policy <abs> --audit <abs> --mode observe || exit 0
   ```

   The interpreter path is absolute, so the hook does not depend on the `PATH` Claude Code gives hooks and cannot be redirected by a shim earlier on `PATH`. `-I` makes Python ignore `PYTHONPATH` and user site-packages. The shell wrapper turns every exit code other than 0 and 2 into 2, so a missing interpreter (127), an import error (1) or a `SIGKILL` (137) blocks instead of letting the command through. The observe wrapper does the opposite: any non-zero exit, including an argparse error from a version-skewed install, becomes 0, so observe never blocks.
4. Removes every existing agent-guard entry, identified by the command prefix `-I -m agent_guard.cli hook claude-code`, and appends one new `^Bash$` group at the end of `PreToolUse`. A group that held only agent-guard entries is dropped; other hooks and settings are left untouched.
5. Writes atomically. A symlinked settings file is written through to its target. The original file is copied to `<name>.agent-guard-backup-<UTC timestamp>`, and the write aborts if the file changed after it was read. Backups accumulate, one per write of an existing file (install, uninstall, and the rollback after a failed self-test); nothing prunes them. A writer that changes the file between the final check and the rename is overwritten; that window is narrow but not closed.
6. Runs the exact installed command through `sh -c` with a minimal `PATH`: a malformed Bash event must exit 2 (0 in observe), a benign `echo` must exit 0 with empty stdout, and a deny canary (`rm -rf /tmp/agent-guard-selftest-canary`) must be blocked by a policy deny. If either of the first two fails, or anything raises during the self-test, including Ctrl-C, the settings file is rolled back and the error is re-raised. If the policy does not deny the canary, install succeeds with a warning that the deny path is unproven.
7. Prints `command verified; firing inside Claude Code not verified`. The self-test proves the command, not that Claude Code loads it. Run `guard report` after a session to confirm it fired.

## Decisions

| Policy verdict | Enforce | Observe |
|---|---|---|
| `allow` | exit 0, empty stdout: Claude Code's own permission flow decides | exit 0 |
| `deny` | exit 2, reason on stderr telling the agent to stop and ask the user | exit 0, audited as `deny` |
| `require_human` in permission mode `default`, `acceptEdits`, `plan` or `dontAsk` | exit 0 with `permissionDecision: "ask"` | exit 0, audited as `require_human` |
| `require_human` in any other, missing or non-string permission mode (`bypassPermissions`, `auto`, a case variant, a future mode) | exit 2 | exit 0 |
| Any fault: malformed input, a tool other than exactly `Bash`, missing or broken policy, unwritable or symlinked audit, internal error | exit 2 with the recovery hint | exit 0 with a notice on stderr |

The hook never emits `permissionDecision: "allow"`. Allow would skip Claude Code's own permission prompt, so a policy with `default: allow` would auto-approve every call it does not list.

A broken or missing policy file blocks every Bash call. It never falls back to built-in defaults, because a fallback would let anyone who can delete the policy switch enforcement off.

## Mapping

The Bash tool maps to agent-guard tool `shell` with args `{"cmd": command}`. Only `command` is evaluated. `description`, `timeout` and `run_in_background` are written to the audit record but never matched, so model-written description text cannot trigger or dodge a rule.

Write policy rules for `shell`, not `Bash`. A rule with `tools: ["Bash"]` matches nothing. An event whose `tool_name` is anything other than exactly `Bash` (`bash`, `BASH`, ` Bash`, `Write`, an MCP tool) is a fault, so a hand-edited matcher fails closed instead of reaching the policy under an unmapped name.

This release matches Bash only. Write, Edit, MultiEdit, NotebookEdit and MCP tools are not checked.

## Fail-closed by Claude Code version

| Failure | Claude Code 2.1.295 and later (`onFailure: "block"`) | Earlier versions |
|---|---|---|
| Policy deny or adapter fault | blocked (exit 2) | blocked (exit 2) |
| Interpreter missing, import error, killed | blocked (wrapper and `onFailure`) | blocked (wrapper) |
| Hook exceeds its 10 s timeout | blocked | **runs**: Claude Code discards a timed-out hook and continues |
| Settings file fails Claude Code's validation | **hook not loaded** | **hook not loaded** |

In `-p` mode Claude Code silently ignores a settings file that fails validation. Run `guard install claude-code --check` after editing settings by hand. `--check` also flags an entry whose matcher is no longer `^Bash$`, and an enforce entry without `onFailure` on a version that supports it. Re-run install to fix either.

## After a deny, the agent may rephrase

A deny tells the agent to stop and ask the user. A model can still try an equivalent command the policy does not match. Observe-mode data shows what the agent did when nothing was blocked, so it does not predict how the agent behaves once blocks start.

## guard report

```bash
guard report [--audit PATH] [--flagged]
```

Reads the local audit log. Nothing leaves the machine. The first status line separates four states:

| Status | Meaning |
|---|---|
| `NOT FIRING` | No checked calls. The hook is not installed, is disabled, or never ran (exit 1) |
| `FIRING, FAULTING` | Faults only. In enforce mode every Bash call is being blocked |
| `FIRING, CLEAN` | Calls checked, none denied, gated or faulted |
| `FIRING` | Calls checked, with denies, asks or faults |

Rows that are not objects or lack a timezone-aware ISO `ts` are counted as unreadable. Agent ids, rule ids, paths and warnings are printed with control characters escaped. It also prints first and last event times, counts of enforced and observed outcomes, top rules, events per session, the fault count, and a warning if `disableAllHooks` is set in a settings file that applies to the current directory. Self-test events are excluded.

### guard report --flagged

`--flagged` appends a list of every call the policy denied or sent to a human: decision `deny` or `require_human`, with any outcome (`observed`, `blocked` or `ask`). Calls are grouped by rule id, largest group first, and a call without a rule id is listed under `policy default`. Each line shows the timestamp, agent id, decision, outcome, `cmd_len` and the first 160 characters of the stored command, with control characters escaped. Self-test and fault rows are excluded. With no such calls it prints `flagged calls: none`. Without the flag the report output is unchanged.

```text
flagged calls: 2
block-rm-rf (1)
  2026-10-23T09:00:00+00:00  claude-code:<session>  deny  observed  cmd_len=13  rm -rf /tmp/x
gate-force-push (1)
  2026-10-23T09:05:00+00:00  claude-code:<session>  require_human  observed  cmd_len=16  git push --force
```

Use it to review observe-mode data before switching to enforce. Its limits:

- It reads the audit log only. It does not look at the host, the shell or Claude Code's transcript.
- `observed` is not `executed`. An observed call was not blocked by the hook, but Claude Code's own permission prompt may still have rejected it, and the list cannot tell whether it ran or what it touched.
- It lists the calls the policy would deny or ask about, as recorded when each call was checked. It does not re-evaluate them against a policy edited since. It does not judge whether the policy is right: a listed call may be a false positive to fix in the policy, and a dangerous call the policy does not match never appears.
- The excerpt comes from the stored command, which is masked and truncated as described under Audit.

## Audit

Each call writes one record: `agent_id` `claude-code:<session_id>[:<subagent id>]`, `tool` `shell`, the decision, `rule_id`, `executed: false` (the hook releases nothing, Claude Code executes), `call_id` `cc:<tool_use_id>`, and `outcome` (`blocked`, `ask`, `deferred` or `observed`). Faults write `event: "fault"`.

The audit file is opened with `O_NOFOLLOW`, so a symlink at the audit path is refused (a fault, exit 2 in enforce), and its mode is set to `0600` on every write, including a file that already existed with wider permissions. Only the final path component is protected against symlinks.

The stored command gets best-effort masking of the listed shapes; other secrets in command text are stored. Masked: userinfo in any `scheme://user:pass@` URL, `Authorization` and `Bearer` values, `X-Api-Key` headers, `*token*=`/`*secret*=`/`*password*=`/`*api_key*=`/`*auth*=` assignments including quoted values with spaces, `--password <value>`, `curl -u user:pass`, `mysql`/`mysqldump`/`mysqladmin`/`mariadb` `-p<pass>`, and `sk-`, `ghp_`, `github_pat_`, `AKIA` and `xox?-` prefixes. It is also truncated to 2 KiB, with `cmd_sha256` and `cmd_len` covering the full command. A low-entropy secret can still be guessed from the hash. Policy always evaluates the unredacted command.

## What the agent sees

When the hook blocks, Claude Code shows the agent the hook's stderr together with the full hook command string. That string includes the policy and audit paths and the recovery hint, which names only `guard install claude-code --check`. The uninstall command does not appear in any agent-visible text; `--check` prints it to the terminal when it reports a problem, and install prints it on success. Treat the paths as known to the agent.

## Recovery: the hook blocks every command

A deleted policy, a policy edit that no longer loads, a full disk, or a removed Python environment makes every Bash call fail closed. The block message reads `agent-guard fault, command blocked` or `agent-guard hook failed, command blocked`. From a terminal outside Claude Code:

```bash
guard install claude-code --check          # names the broken part: policy, interpreter, matcher, command
guard install claude-code --mode enforce   # re-install after fixing it
guard install claude-code --uninstall      # or remove the hook
```

If `guard` itself is gone, restore the newest `settings.json.agent-guard-backup-<timestamp>` next to the settings file, or delete the entry whose command contains `agent_guard.cli hook claude-code`. Whether a running session picks up a settings edit is not verified, so restart Claude Code afterwards.

## Do not wire `guard check` as a hook

`guard check` exits 3 for deny, 4 for require_human and 1 for errors. Claude Code treats every exit code other than 0 and 2 as a non-blocking error and runs the command. Wired directly as a `PreToolUse` hook, `guard check` blocks nothing. Use `guard hook claude-code` through `guard install claude-code`.
