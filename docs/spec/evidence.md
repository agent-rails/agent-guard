# Evidence record specification

The audit record (`agent_guard.audit.AuditRecord`) is the evidence unit. This document lists every field, the exact bytes that are signed, which fields are claims and which are stamped by a trusted executor, and how the record maps to OpenTelemetry GenAI conventions.

## Wire form

One JSON object per line (JSONL). `record_dict` produces it: every `AuditRecord` field is present except the v2 evidence fields and `schema_version`, which are omitted when unset. A record with no v2 fields therefore has the same wire form as before v2 existed.

## Fields

Core fields, always present.

| Field | Type | Meaning |
|---|---|---|
| `ts` | string | UTC ISO 8601 time the record was built (`datetime.now(timezone.utc).isoformat()`). |
| `agent_id` | string | Identity the `Guard` was constructed with. |
| `tool` | string | Tool name the decision applies to. |
| `args` | object | Canonical JSON arguments the policy evaluated. Empty when the arguments could not be canonicalised. |
| `decision` | string | `allow`, `deny` or `require_human`. |
| `reason` | string | Why the verdict was reached. |
| `rule_id` | string or null | Rule that matched; null for the policy default. |
| `executed` | bool | The guard released the call. Not proof that the tool completed. |
| `sig` | string or null | Base64url HMAC-SHA256 added by `SigningAuditSink`. Null when unsigned. |
| `error` | string or null | Failure detail when a released call did not return cleanly. |

Lifecycle fields, optional.

| Field | Type | Meaning |
|---|---|---|
| `event` | string or null | `decision`, `release`, `terminal` or `fault`. Null on records written before lifecycle events existed. |
| `call_id` | string or null | Random id shared by the events of one call. |
| `call_digest` | string or null | SHA-256 binding agent id, trust tier, tool, canonical arguments and verdict. |
| `outcome` | string or null | Terminal outcome: `returned`, `raised`, `unknown`, `not_dispatched`, or `fault`/`observed` from the hook. |

v2 evidence fields, optional, all strings.

| Field | Meaning |
|---|---|
| `trace_id` | Correlation id for one task across components. |
| `task_root` | Hash of the task root the authority descends from. |
| `grant_hash` | Hash of the grant or chain leaf that authorised the call. |
| `tenant_id` | Tenant the authority belongs to. |
| `principal` | Human or service the root authority was issued for. |
| `actor` | Identity that performed the call, as resolved from the verified chain. |
| `parent_actor` | Identity that delegated to `actor`. |
| `host` | Host the call ran on. |
| `purpose` | Persona label of the task (what the agent is for). `guard detect` uses it as the persona key, falling back to `actor`, then `agent_id`. |

`schema_version` (integer, optional). Stamped as `2` when any v2 evidence field is set and none was given explicitly. Absent means the record predates v2.

## Signed bytes

`sign_record` computes HMAC-SHA256 over the following bytes and encodes the result as URL-safe base64.

1. Take the record with `sig` set to null.
2. Drop every optional field that is null: `event`, `call_id`, `call_digest`, `outcome`, each v2 evidence field (including `purpose`), and `schema_version`. A field that is set, including the empty string, is kept.
3. Serialise with `json.dumps(sort_keys=True, separators=(",", ":"))` and encode as UTF-8. Non-ASCII characters are escaped as `\uXXXX` (the `json.dumps` default).

Consequences, each covered by tests in `tests/test_audit_v2.py`:

- A record with no optional fields signs to the same bytes it signed to before the lifecycle and v2 fields existed. `sig` and `error` stay in the body as `null` when unset.
- Setting any v2 field, `purpose` or `schema_version` changes the signed bytes, so a signature made without the field no longer verifies once the field is added, and removing a signed field also fails verification.
- The signed bytes change only through a field being set. `schema_version` is signed whenever present, so changing it invalidates the signature.
- `verify_record` also returns false when `schema_version` is not an integer, is not 1 or 2, or disagrees with the record: absent with any v2 field present, 1 with a v2 field present, or 2 with none.

Limits. The HMAC key is shared by signer and verifier: a compromised producer can sign forged records, and signing does not show that a record was never suppressed. Replay of a whole signed record is not detected; there is no sequence number or hash chain.

## Claims and stamped fields

A claim is a value supplied by the process that writes the record. A stamped field is set by a trusted executor from something it verified. A reader should treat a claim as evidence of what the producer said, not of what happened.

| Field | Class | Source |
|---|---|---|
| `ts` | claim | Clock of the writing process. |
| `agent_id` | claim | Constructor argument of `Guard`. Backed by a verified token only when the guard was built with `Guard.from_token`. |
| `tool`, `args` | claim | Supplied by the caller of the guard. |
| `decision`, `reason`, `rule_id` | stamped | Computed by the policy engine in the guard process. |
| `executed`, `event`, `call_id`, `call_digest`, `outcome`, `error` | stamped | Set by the guard lifecycle. `executed` means released, not completed. |
| `principal`, `actor`, `parent_actor` | stamped | Must come from a verified delegation chain and be written by the executor. Never copied from agent-supplied input. |
| `task_root`, `grant_hash`, `tenant_id` | stamped | Must come from the verified grant the executor checked. |
| `purpose` | stamped when taken from a verified signed task root, otherwise a claim | A claim defeats persona detection, because the agent controls its own baseline. |
| `trace_id` | claim | Correlation only; carries no authority. |
| `host` | claim | Self-reported by the writing process. |
| `schema_version` | stamped | Derived from the record's fields. |

Implementation status in this repository: `AuditRecord` and `build_record` accept the v2 fields from the caller, and nothing in `Guard` populates them. The rule that `principal`, `actor` and `parent_actor` are stamped from a verified chain is a requirement on the executor that writes them; no executor in this repository enforces it.

## Mixed versions

- Writers omit unset v2 fields, so a v1 stream and a v2 stream can share one file.
- This version verifies both: v1 records verify under their original bytes, v2 records under the bytes above. An explicit `schema_version` of 1 is accepted only when no v2 field is set.
- A reader that rebuilds records with `AuditRecord(**row)` from an older release rejects rows that carry fields it does not know. Readers in this repository (`guard report`, `guard replay`, `guard inventory`, `guard detect`) read rows as dictionaries and ignore fields they do not use.
- `guard inventory` and `guard detect` skip `terminal` and `fault` rows when counting decisions, and treat rows with a missing or non-string identity as malformed and count them.
- The audit schema has no delegation depth field. `guard detect` reports its depth check as skipped.

## OpenTelemetry GenAI mapping

The GenAI conventions have status Development. Names below were read from `open-telemetry/semantic-conventions-genai` at commit `e6658f14c9d9ea0760825f029cb82e7673f48fab` (`docs/gen-ai/execute-tool.md`, `docs/gen-ai/gen-ai-agent-spans.md`, `docs/registry/attributes/gen-ai.md`, `docs/registry/entities/gen-ai.md`) through `gh api`. Re-check before relying on them; the names can change while the status is Development.

| Audit field | OpenTelemetry | Notes |
|---|---|---|
| record as a whole | span `gen_ai.execute_tool`, `gen_ai.operation.name` = `execute_tool` | A `release`/`terminal` pair describes one tool execution. |
| `tool` | `gen_ai.tool.name` | Required on the execute-tool span. |
| `args` | `gen_ai.tool.call.arguments` | Opt-In and may hold sensitive data; the audit log already stores arguments. |
| `agent_id`, `actor` | `gen_ai.agent.name` or `gen_ai.agent.id` | Partial. `gen_ai.agent.name` must be low cardinality; `gen_ai.agent.id` is a stable provider-assigned id for hosted agents and not for in-memory instances. Map only when the value fits. |
| `error` | `error.type` | Partial. `error.type` is a low-cardinality class; `error` is free text. `error.type` is defined in the core semantic-conventions repository, which was not checked. |
| `trace_id` | OpenTelemetry trace context | Not a GenAI attribute. Not checked against the core specification. |
| `call_id` | none | `gen_ai.tool.call.id` is the identifier supplied by the model or provider and must not be set otherwise; `call_id` is generated by the guard. |
| `ts` | span or log record timestamp | Not an attribute. |
| `host` | none verified | Core `host.*` attributes are outside the repository checked. |
| `decision`, `reason`, `rule_id`, `executed`, `event`, `call_digest`, `outcome` | unmapped | No matching attribute in the checked files. |
| `task_root`, `grant_hash`, `tenant_id`, `principal`, `parent_actor`, `purpose`, `schema_version` | unmapped | No matching attribute in the checked files. Searching the GenAI attribute registry for tenant, principal, purpose, parent, delegation and depth found nothing relevant. |

An exporter that sends unmapped fields has to carry them as custom attributes under its own prefix. No such exporter exists in this repository; `CallableAuditSink` is the seam for one.
