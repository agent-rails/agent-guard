"""A real, autonomous Claude agent, wrapped in agent-guard end to end.

Every other example in this directory (end_to_end.py, pop_example.py) proves
the identity/policy/audit mechanism with a scripted, hardcoded sequence of
tool calls. This one proves the same mechanism against an agent that
genuinely decides its own tool calls by calling the Anthropic API -- not a
fixture standing in for one.

The tool/provider seam (Tool, ToolRegistry, AnthropicProvider) is adapted
from https://github.com/voltagebots/agent-from-scratch (a small, from-scratch
agent loop built for teaching, MIT-equivalent spirit, not vendored as a
dependency -- reproduced minimally here so this example stays self-contained
and zero-extra-git-clones, per this repo's existing example style). Only the
provider/tool-registry seam is reused; the agent-guard wiring below is new.

WHERE the agent runs: a real Docker container, spawned by ContainerRuntime.
ContainerSandbox.dispatch() only executes shell commands inside that
container (EXEC_TOOLS = {"shell", "exec"}) -- so the two tools exposed to the
model (list_files, read_file) are backed by shell equivalents (ls, cat) run
INSIDE the attested container, not by local Python file I/O. That is what
makes the trust_tier real rather than aspirational: `local.container` here
means the tool calls actually executed inside a container agent-guard
attested, not that the agent merely claims to be sandboxed.

Prerequisites:
    docker build -t agent-guard-demo:v1 examples/guarded_autonomous_agent/
    pip install anthropic
    export ANTHROPIC_API_KEY=sk-ant-...

Run:
    python examples/guarded_autonomous_agent/agent.py
    python examples/guarded_autonomous_agent/agent.py "your own prompt here"
"""

from __future__ import annotations

import json
import posixpath
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import anthropic

from agent_guard import Decision, Guard, Policy, Rule
from agent_guard.audit import JsonlAuditSink
from agentguard_identity import Broker, ContainerRuntime, LocalAttestor, RuntimeSpec
from agentguard_identity.token import sign

IMAGE = "agent-guard-demo:v1"
MODEL = "claude-opus-4-8"
MAX_TOKENS = 4096
AUDIT_PATH = Path(__file__).parent / "audit.jsonl"


# --- Tool / Provider seam, adapted from agent-from-scratch (see module docstring) ---


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    fn: Callable[[dict[str, Any]], str]

    def to_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def schemas(self) -> list[dict[str, Any]]:
        return [tool.to_schema() for tool in self._tools.values()]

    def dispatch(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        tool = self._tools.get(name)
        if tool is None:
            return f"Error: unknown tool '{name}'", True
        try:
            return tool.fn(args), False
        except Exception as err:  # noqa: BLE001 - boundary catch: convert to a model-readable error
            return f"Error: {err}", True


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class ModelResponse:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    raw_content: Any


class Provider(Protocol):
    def generate(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse: ...


class AnthropicProvider:
    def __init__(self, model: str = MODEL, max_tokens: int = MAX_TOKENS) -> None:
        self._client = anthropic.Anthropic()
        self._model = model
        self._max_tokens = max_tokens

    def generate(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse:
        response = self._client.messages.create(
            model=self._model, max_tokens=self._max_tokens, tools=tools, messages=messages
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        tool_calls = [
            ToolCall(id=block.id, name=block.name, args=block.input)
            for block in response.content
            if block.type == "tool_use"
        ]
        return ModelResponse(
            text=text, tool_calls=tool_calls, stop_reason=response.stop_reason, raw_content=response.content
        )


# --- agent-guard wiring ---


def policy() -> Policy:
    # Escaping the workspace (../, absolute paths, shell metacharacters) is
    # rejected structurally by _safe_workspace_path before a call ever
    # reaches here -- a regex denylist over a shell-injectable string is not
    # a real control (see PR #30 review: glob/quote-split/injection all
    # defeated an earlier version of this rule). What agent-guard's Policy
    # engine is actually demonstrated on here is a real, in-bounds decision:
    # a file that exists, is reachable, and is still policy-denied.
    return Policy(
        default=Decision.ALLOW,
        rules=[
            Rule(
                id="no-sensitive-file",
                decision=Decision.DENY,
                tools=["exec"],
                arg_patterns=[r"\bsecrets\.txt\b"],
                reason="secrets.txt is in the workspace but policy-denied regardless",
            ),
        ],
    )


WORKSPACE_ROOT = "/workspace"
# Shell metacharacters, quotes, and glob characters -- found live (see PR #30
# review) that a regex-only denylist on the rendered command (e.g. matching
# the literal substring "/etc/") is trivially defeated by any of these:
# "; id", "/e?c/passwd" (glob), "/e''tc/passwd" (quote-split), "/*/passwd".
# A denylist over pre-shell text cannot be the control -- validate the
# resolved path lexically instead, then additionally shell-quote it.
_DISALLOWED_PATH_CHARS = set(";&|`$(){}<>\n\"'*?[]~\x00")


def _safe_workspace_path(raw: str) -> str:
    """Resolve a model-supplied path against WORKSPACE_ROOT using pure
    lexical normalization (posixpath.normpath -- no filesystem access,
    since this path is for the CONTAINER's filesystem, not the host's) and
    reject anything that would escape the workspace or contains a shell
    metacharacter/quote/glob character. Raises ValueError -- the caller
    turns that into a model-readable tool error via ToolRegistry.dispatch's
    own broad except, same as any other tool failure.

    This is purely lexical, matching the target: the CONTAINER's
    filesystem, which this process can't stat. A path that's lexically
    inside /workspace could still resolve outside it at runtime via a
    symlink planted in the image -- not reachable today (the image's
    workspace/ has three regular files, no symlinks, verified at build
    time), but worth knowing if this image ever grows one."""
    if not raw or any(ch in raw for ch in _DISALLOWED_PATH_CHARS):
        raise ValueError(f"path rejected: contains a disallowed character ({raw!r})")
    joined = raw if raw.startswith("/") else posixpath.join(WORKSPACE_ROOT, raw)
    normalized = posixpath.normpath(joined)
    if normalized != WORKSPACE_ROOT and not normalized.startswith(WORKSPACE_ROOT + "/"):
        raise ValueError(f"path escapes the workspace root: {raw!r} -> {normalized!r}")
    return normalized


def build_registry(guarded_dispatch: Callable[[str, dict], Any]) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        Tool(
            name="list_files",
            description="List files and directories at a path. Use to explore the filesystem.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": []},
            fn=lambda args: guarded_dispatch(
                "exec", {"cmd": f"ls -la {shlex.quote(_safe_workspace_path(args.get('path', '.')))}"}
            ),
        )
    )
    registry.register(
        Tool(
            name="read_file",
            description="Read the full contents of a text file.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            fn=lambda args: guarded_dispatch("exec", {"cmd": f"cat {shlex.quote(_safe_workspace_path(args['path']))}"}),
        )
    )
    return registry


def spawn_and_mint() -> tuple:
    image_digest = json.loads(
        subprocess.run(
            ["docker", "inspect", "--format", "{{json .Id}}", IMAGE], capture_output=True, text=True, check=True
        ).stdout
    )
    print(f"image digest: {image_digest}")

    runtime = ContainerRuntime()
    sandbox = runtime.spawn(RuntimeSpec(code_digest=image_digest, kind="local.container", image=IMAGE))
    attestor = LocalAttestor(allowlist={image_digest})
    result = attestor.verify(sandbox.attest())
    print(
        f"attestation: verified={result.verified} tier={result.trust_tier} "
        f"sandbox={result.sandbox_id} ({result.reason})"
    )
    if not result.verified:
        sandbox.close()
        raise SystemExit("attestation failed -- refusing to mint a token or run the agent")

    secret = b"guarded-autonomous-agent-example-secret-do-not-use-in-prod"
    broker = Broker(secret=secret, ttl_seconds=600)
    token = broker.mint(result, subject="guarded-autonomous-agent-example", human_grant={"exec"}, task_scope={"exec"})
    print(f"identity: {token.agent_id}  tier={token.trust_tier}  scopes={list(token.scopes)}")

    encoded = sign(token, secret)
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()
    audit = JsonlAuditSink(AUDIT_PATH)
    guard = Guard.from_token(encoded, secret, policy(), audit=audit)
    return sandbox, guard


def run_agent(registry: ToolRegistry, user_input: str) -> None:
    provider = AnthropicProvider()
    messages: list[dict] = [{"role": "user", "content": user_input}]
    while True:
        response = provider.generate(messages, registry.schemas())
        if response.text:
            print(response.text)
        if response.stop_reason != "tool_use":
            return
        messages.append({"role": "assistant", "content": response.raw_content})
        results = []
        for call in response.tool_calls:
            print(f"  [tool] {call.name}({json.dumps(call.args)})")
            output, is_error = registry.dispatch(call.name, call.args)
            print(f"  [result{'(error)' if is_error else ''}] {output[:300]}")
            results.append({"type": "tool_result", "tool_use_id": call.id, "content": output, "is_error": is_error})
        messages.append({"role": "user", "content": results})


def print_audit_trail() -> None:
    print("\n=== audit trail (attributed to the verified identity) ===")
    if not AUDIT_PATH.exists():
        print("(no audit records written)")
        return
    for line in AUDIT_PATH.read_text().splitlines():
        rec = json.loads(line)
        flag = "ran" if rec["executed"] else "BLOCKED"
        print(f"[{flag}] {rec['agent_id']} {rec['tool']}: {rec['reason']}")


def main() -> None:
    print("=== spawning a real Docker container, attesting, minting an identity ===")
    sandbox, guard = spawn_and_mint()
    guarded_dispatch = guard.wrap(sandbox.dispatch)
    registry = build_registry(guarded_dispatch)

    user_input = " ".join(sys.argv[1:]) or (
        "List the files in the current directory, read config.toml and summarize it, "
        "then try reading /etc/passwd (outside the workspace) and secrets.txt (inside "
        "the workspace, but policy-restricted) -- tell me what happens with each."
    )
    print(f"\n=== running the real agent loop ===\nprompt: {user_input!r}\n")
    try:
        run_agent(registry, user_input)
    except anthropic.APIStatusError as err:
        print(f"\nAnthropic API error: {err}")
    finally:
        sandbox.close()
        print_audit_trail()


if __name__ == "__main__":
    main()
