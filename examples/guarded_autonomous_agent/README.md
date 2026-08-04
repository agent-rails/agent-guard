# Guarded autonomous agent

`end_to_end.py` and `pop_example.py` prove agent-guard's mechanism with a
scripted, hardcoded sequence of tool calls. This example proves the same
mechanism against an agent that genuinely decides its own tool calls, by
calling the real Anthropic API -- not a fixture standing in for one.

```
spawn a real Docker container -> attest it -> mint a scoped identity token
   -> a real Claude-driven agent decides its own tool calls
   -> path validation rejects anything that would escape the workspace or
      inject shell metacharacters, BEFORE a call ever reaches agent-guard
   -> every remaining call runs through Guard.from_token() before executing
      INSIDE the container
   -> allowed calls execute and are audited; policy-denied calls are
      blocked and audited
```

## What it demonstrates

- `local.container` here means what it says: tool calls execute inside a
  container agent-guard actually spawned and attested, not a claim the agent
  makes about itself.
- The agent isn't told what it's allowed to do -- it finds out by trying. In
  the default prompt, it lists files, reads a config file (allowed), tries
  `/etc/passwd` (rejected -- outside the workspace, caught by path
  validation before agent-guard is even called), and tries `secrets.txt`
  (present in the workspace, but denied by an actual agent-guard Policy
  rule -- a real, audited authorization decision, not a filesystem-level
  rejection).
- The denial isn't a crash: the agent sees a normal tool-result error, and
  correctly explains to the user what happened and why.
- The audit trail attributes every decision agent-guard actually made,
  allowed and denied, to the one verified identity minted for this run.

## Two layers, deliberately not one

An earlier version of this example built shell commands directly from
model-supplied paths (`f"cat {path}"`) and relied on a regex denylist
(matching literal substrings like `/etc/`) as the only defense. Adversarial
review found that trivially bypassable -- shell globs (`/e?c/passwd`),
quote-splitting (`/e''tc/passwd`), and outright command injection
(`config.toml; id`) all defeated it, and a regex over pre-shell text was
never going to be a real control. See the PR history for the finding.

The fix has two layers doing two different jobs, and both matter:

1. **Structural validation** (`_safe_workspace_path` + `shlex.quote`) --
   rejects anything that isn't a safe, in-workspace path before a shell
   command is ever constructed. This prevents injection and traversal. It
   is not agent-guard's job; it's basic input handling any tool boundary
   needs regardless of what authorizes the call afterward.
2. **agent-guard's Policy engine** -- makes the actual authorization
   decision on calls that pass validation. `secrets.txt` is a perfectly
   valid, in-workspace path -- structural validation has nothing to say
   about it. Denying it is a real Policy decision, audited like any other.

Conflating the two (as the earlier version did) meant the "security
boundary" was actually just the regex, doing both jobs badly. Separating
them means each layer does the job it's actually good at.

## Prerequisites

```bash
docker build -t agent-guard-demo:v1 examples/guarded_autonomous_agent/
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

## Run

```bash
python examples/guarded_autonomous_agent/agent.py
# or with your own prompt:
python examples/guarded_autonomous_agent/agent.py "list the files here and read notes.md"
```

## Holder-bound identity (Proof-of-Possession)

`agent_pop.py` runs the exact same real agent, real container, and real
policy as `agent.py` above, but the identity token is holder-bound instead
of a plain bearer credential. This repo's `pop_example.py` already proves
the underlying cryptographic property (a stolen encoded token alone is not
usable without the matching private key) -- but only against a scripted
`LocalRuntime` call. This is the same property, proven against a real
autonomous agent in a real container.

```bash
pip install "agentguard[pop]"
python examples/guarded_autonomous_agent/agent_pop.py
```

It runs, in order:

1. **Theft simulation** -- constructs a `Guard` from the encoded token alone
   (no proof), then again with a proof forged by a *different* keypair.
   Both refused by `Guard.from_token()`, even though the token's own HMAC
   signature is valid in both cases -- direct against the real API, no LLM
   involved, since this is a property of the crypto layer, not agent
   behavior.
2. **The legitimate path** -- the sandbox that actually holds the private
   key proves possession, `Guard.from_token()` succeeds, and the same real
   agent from `agent.py` runs normally behind it.

## Prompt injection, not direct instruction

`agent.py` and `agent_pop.py` both test the agent following a DIRECT user
instruction ("try reading /etc/passwd"). `agent_injection_scenario.py`
tests something different: an innocuous prompt ("explore this workspace
and summarize it") where the only path to a denied call is a
prompt-injection payload planted in `workspace/CHANGELOG.md` -- content
the agent has no reason to suspect and reads as ordinary due diligence.

`THREAT_MODEL.md` names this class explicitly as a residual risk:
prompt injection is "mitigated, not eliminated" by a deterministic
ruleset. This is the first time that specific claim was exercised
against the real pipeline rather than asserted.

```bash
python examples/guarded_autonomous_agent/agent_injection_scenario.py
```

Verified live: the agent read the injected file, was manipulated into
constructing exactly the call the injection asked for (`cat
/workspace/secrets.txt`), and agent-guard's Policy layer denied it --
confirmed from the raw audit record, not just the agent's own account.
The agent's own final response also correctly identified and called out
the injection attempt in its own text -- but that's a bonus, not the
control. The control is architectural: agent-guard's Policy engine
evaluates the CALL, not the agent's reasoning, so it doesn't matter
whether the agent's own judgment can be trusted. A manipulated agent and
a directly-instructed agent produce the same shape of call if they both
try to read a restricted file, and the Policy can't tell them apart --
which is exactly why it isn't fooled by either.

## Attribution

The tool/provider seam (`Tool`, `ToolRegistry`, `AnthropicProvider`) is
adapted from [voltagebots/agent-from-scratch](https://github.com/voltagebots/agent-from-scratch),
a small from-scratch agent loop built for teaching. Reproduced minimally here
rather than added as a dependency, so this example stays self-contained --
consistent with every other example in this directory.
