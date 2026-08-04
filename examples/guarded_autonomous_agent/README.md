# Guarded autonomous agent

`end_to_end.py` and `pop_example.py` prove agent-guard's mechanism with a
scripted, hardcoded sequence of tool calls. This example proves the same
mechanism against an agent that genuinely decides its own tool calls, by
calling the real Anthropic API — not a fixture standing in for one.

```
spawn a real Docker container -> attest it -> mint a scoped identity token
   -> a real Claude-driven agent decides its own tool calls
   -> every call runs through Guard.from_token() before executing INSIDE the container
   -> allowed calls execute and are audited; denied calls are blocked and audited
```

## What it demonstrates

- `local.container` here means what it says: tool calls execute inside a
  container agent-guard actually spawned and attested, not a claim the agent
  makes about itself.
- The agent isn't told what it's allowed to do — it finds out by trying. In
  the default prompt, it lists files, reads a config file (allowed), and then
  attempts to read `/etc/passwd` (denied) — a genuine autonomous decision,
  not a scripted step.
- The denial isn't a crash: the agent sees a normal tool-result error, and
  correctly explains to the user what happened and why.
- The audit trail attributes every decision — allowed and denied — to the one
  verified identity that was actually minted for this run.

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

## Attribution

The tool/provider seam (`Tool`, `ToolRegistry`, `AnthropicProvider`) is
adapted from [voltagebots/agent-from-scratch](https://github.com/voltagebots/agent-from-scratch),
a small from-scratch agent loop built for teaching. Reproduced minimally here
rather than added as a dependency, so this example stays self-contained —
consistent with every other example in this directory.
