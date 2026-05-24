# Patch Boundary Ledger

This ledger records every enterprise fork change that touches mature Hermes core
runtime files.

The goal is simple: keep Hermes upstream-shaped. Add enterprise modules first,
use adapter hooks second, and patch core only where a real enforcement boundary
cannot be controlled any other way.

## Current Status

Two enterprise runtime authority patches exist:

1. MVP-0 Action Firewall v0 patches the Hermes tool execution preflight in
   `agent/tool_executor.py`.
2. MVP-0 Tool-Result Sanitizer v0 patches the Hermes tool-result message helper
   in `agent/tool_dispatch_helpers.py`.

The patch is disabled by default through `enterprise.enabled: false`. It does
not patch provider egress, memory, gateway, plugin admission, or cron authority.

Sandbox Enforcement v0 extends the existing enterprise action-firewall module
without touching a new mature Hermes core runtime file.

Staged Execution v0 also extends the enterprise action-firewall module without
touching a new mature Hermes core runtime file. It records approval artifacts
for covered side effects, but does not add approved execution or rollback.

Context Hydration v0 adds enterprise artifact modules only. It does not patch a
new mature Hermes core runtime file and does not yet force provider, memory, or
gateway paths through the hydration boundary.

Developer Local Fast Path v0 extends the enterprise action-firewall module
without touching a new mature Hermes core runtime file. It is a scoped allow
policy for owner workspace file actions, not a break-glass override.

Enterprise Doctor v0 patches `hermes_cli/doctor.py` only to render a diagnostic
section from the enterprise machine-readable report. It does not add runtime
authority or change normal Hermes execution behavior.

MVP-0 Release-Gate Regression Suite adds tests and shared fake fixtures only.
It does not patch mature Hermes runtime files.

MVP-0 Closure Gate adds a local gate runner, downstream GitHub Actions workflow,
and readiness note only. It does not patch mature Hermes runtime files.

Upstream base:

```text
ca192cfb773915c9d8113352b8646d3ce9329424
```

Planning branch:

```text
codex/enterprise-planning-docs
```

## Rules

1. Every core Hermes patch must have one entry in this file.
2. Each entry must name the security invariant it enforces.
3. Each entry must explain why plugin-only or sidecar-only enforcement is not
   enough.
4. Each entry must list touched files.
5. Each entry must name enterprise-off compatibility tests.
6. Each entry must name enterprise-on security tests.
7. A PR that touches core Hermes files without updating this ledger is
   incomplete.

## Core Patch Entries

### Patch: MVP-0 Action Firewall v0

Status: implemented
Owner: cl0udz1 downstream fork
Date: 2026-05-20
Upstream base:

```text
ca192cfb773915c9d8113352b8646d3ce9329424
```

Invariant:
- A model-proposed tool call must pass enterprise pre-execution evaluation
  before any Hermes tool handler, special agent-loop tool, callback, checkpoint,
  or worker thread can create side effects.
- When enterprise mode is disabled, existing Hermes tool execution behavior must
  stay unchanged.

Why plugin/sidecar cannot enforce it:
- Hermes plugins can advise or block through hooks, but plugin-only enforcement
  is optional and cannot be the mandatory authority seam for high-risk tool
  execution.
- A sidecar outside Hermes cannot reliably stop special in-loop tools or
  concurrent worker submission after the model has already selected a tool.

Patch shape:
- Add a lazy `_enterprise_pre_tool_decision(...)` helper in
  `agent/tool_executor.py`.
- Call the helper in both sequential and concurrent preflight after existing
  plugin and guardrail checks allow the call, and before any execution
  bookkeeping or worker submission.
- Return one synthetic tool result for blocked calls, preserving the original
  `tool_call_id`.

Files touched:
- `agent/tool_executor.py`
- `enterprise/firewall/__init__.py`
- `enterprise/firewall/action.py`
- `tests/enterprise/test_action_firewall.py`

Enterprise-off compatibility:
- `tests/enterprise/test_action_firewall.py::test_action_firewall_disabled_is_a_true_noop`
- `tests/enterprise/test_action_firewall.py::test_enterprise_off_sequential_tool_execution_is_unchanged`
- `tests/run_agent/test_tool_call_guardrail_runtime.py`

Enterprise-on security gate:
- `tests/enterprise/test_action_firewall.py::test_action_firewall_blocks_approval_required_tool_and_audits`
- `tests/enterprise/test_action_firewall.py::test_action_firewall_allows_low_risk_tool_and_audits`
- `tests/enterprise/test_action_firewall.py::test_action_firewall_blocked_sequential_call_never_reaches_tool_runner`
- `tests/enterprise/test_action_firewall.py::test_action_firewall_blocked_concurrent_call_is_not_submitted`

Rollback plan:
- Set `enterprise.enabled: false` to return to normal Hermes behavior.
- If the hook itself must be removed, delete the two calls to
  `_enterprise_pre_tool_decision(...)` and remove the helper; enterprise modules
  become inert again.

Notes:
- Approval-required actions are blocked for MVP-0 because no approval queue/UI
  exists yet. A later slice should stage those actions instead of executing or
  silently denying them.
- Audit events use redacted previews and raw hashes; raw tool arguments are not
  stored in event previews.

### Patch: MVP-0 Tool-Result Sanitizer v0

Status: implemented
Owner: cl0udz1 downstream fork
Date: 2026-05-20
Upstream base:

```text
ca192cfb773915c9d8113352b8646d3ce9329424
```

Invariant:
- Tool outputs must be sanitized before they become model-visible tool
  messages.
- Secret-looking values, role-like control markers, prompt-injection phrases,
  and tool-call bait must not pass into model context raw when enterprise mode
  is enabled.
- When enterprise mode is disabled, existing Hermes tool-result messages must
  stay unchanged.

Why plugin/sidecar cannot enforce it:
- Tool-result transforms outside the message builder can be skipped by special
  tools, concurrent results, interrupt results, or future direct helper calls.
- The message helper is the shared point where Hermes assigns the `tool` role,
  `tool_name`, content, and `tool_call_id`; that is the last reliable boundary
  before provider/model context.

Patch shape:
- Add `enterprise.firewall.result.sanitize_tool_result(...)`.
- Route `make_tool_result_message(...)` through the sanitizer with a no-op
  disabled default.
- Pass agent root config from sequential and concurrent tool execution so the
  sanitizer can enforce enterprise mode without changing ordinary helper calls.
- Preserve raw result hashes and write `result_sanitized` audit events with
  redacted previews only.

Files touched:
- `agent/tool_dispatch_helpers.py`
- `agent/tool_executor.py`
- `enterprise/firewall/__init__.py`
- `enterprise/firewall/result.py`
- `tests/enterprise/test_result_firewall.py`

Enterprise-off compatibility:
- `tests/enterprise/test_result_firewall.py::test_result_sanitizer_disabled_returns_content_unchanged`
- `tests/run_agent/test_tool_name_db_persistence.py`
- `tests/run_agent/test_tool_call_guardrail_runtime.py`

Enterprise-on security gate:
- `tests/enterprise/test_result_firewall.py::test_result_sanitizer_redacts_secret_and_neutralizes_prompt_bait`
- `tests/enterprise/test_result_firewall.py::test_result_sanitizer_handles_multimodal_text_without_touching_image`
- `tests/enterprise/test_result_firewall.py::test_make_tool_result_message_routes_through_result_sanitizer`
- `tests/enterprise/test_result_firewall.py::test_runtime_tool_result_is_sanitized_before_message_append`

Rollback plan:
- Set `enterprise.enabled: false` to preserve normal Hermes behavior.
- If the hook itself must be removed, delete the sanitizer call inside
  `make_tool_result_message(...)` and keep the enterprise module inert.

Notes:
- MVP-0 sanitizes obvious deterministic patterns only. It does not claim full
  DLP, semantic prompt-injection detection, provider egress control, or memory
  quarantine.

### Patch: Chat Completions Provider Egress Guard

Status: MVP-1 slice
Owner: downstream enterprise fork
Date: 2026-05-23
Upstream base: `4e4559f6e`

Invariant:
- In enterprise mode, Chat Completions provider request payloads must pass
  through deterministic egress sanitization before provider submission.

Why plugin/sidecar cannot enforce it:
- A plugin cannot reliably see the final provider payload after Hermes applies
  provider-profile quirks, request overrides, role rewrites, tool schema
  shaping, and extra_body assembly.

Patch shape:
- Add one transport-level call after both Chat Completions payload assembly
  branches.
- Keep all sanitizer logic in `enterprise/provider_egress.py`.
- Reuse shared deterministic model-boundary sanitization.

Files touched:
- `agent/transports/chat_completions.py`
- `enterprise/provider_egress.py`
- `enterprise/sanitization.py`
- `enterprise/contracts.py`
- `enterprise/config.py`
- `enterprise/doctor.py`
- `tests/enterprise/test_provider_egress.py`
- `tests/enterprise/test_enterprise_doctor.py`

Enterprise-off compatibility:
- `tests/enterprise/test_provider_egress.py::test_provider_egress_disabled_returns_payload_unchanged`
- `tests/enterprise/test_provider_egress.py::test_chat_completions_provider_egress_disabled_preserves_transport_payload`

Enterprise-on security gate:
- `tests/enterprise/test_provider_egress.py::test_chat_completions_provider_egress_redacts_before_fake_provider`
- `tests/enterprise/test_provider_egress.py::test_chat_completions_profile_path_uses_provider_egress`

Rollback plan:
- Set `enterprise.enabled: false` to preserve normal Hermes behavior.
- If the patch itself must be removed, delete the call to
  `_apply_enterprise_provider_egress(...)` in `ChatCompletionsTransport` and
  keep the enterprise module inert.

Notes:
- Streaming posture is `request_payload_only`: request payloads are sanitized
  before Chat Completions streaming, but streamed provider responses are not
  buffered or scanned in this slice.
- This does not yet cover Codex Responses, Anthropic Messages, Bedrock,
  auxiliary model calls, embeddings, or direct provider client factories.

### Patch: Memory Manager Governance Guard

Status: MVP-1 slice
Owner: downstream enterprise fork
Date: 2026-05-24
Upstream base: `de17aea39`

Invariant:
- In enterprise mode, memory provider payloads must pass through deterministic
  governance before becoming durable memory, recall context, compression input,
  explicit memory-write mirrors, memory-provider tool inputs/results, or
  delegation observations.

Why plugin/sidecar cannot enforce it:
- Memory providers sit behind `MemoryManager`; a plugin cannot reliably govern
  every provider input/output after Hermes has selected providers, routed tool
  calls, queued prefetches, and prepared session-end extraction payloads.

Patch shape:
- Add one enterprise governance helper inside `MemoryManager`.
- Call it at the manager-level memory seams instead of patching individual
  memory providers.
- Keep sanitizer and audit logic inside `enterprise/memory_governance.py`.

Files touched:
- `agent/memory_manager.py`
- `enterprise/memory_governance.py`
- `enterprise/contracts.py`
- `enterprise/config.py`
- `enterprise/doctor.py`
- `tests/enterprise/test_memory_governance.py`
- `tests/enterprise/test_enterprise_doctor.py`

Enterprise-off compatibility:
- `tests/enterprise/test_memory_governance.py::test_memory_governance_disabled_returns_payload_unchanged`
- `tests/enterprise/test_memory_governance.py::test_memory_manager_disabled_preserves_provider_payloads`
- `tests/agent/test_memory_provider.py`

Enterprise-on security gate:
- `tests/enterprise/test_memory_governance.py::test_memory_manager_redacts_session_end_sync_and_recall_payloads`
- `tests/enterprise/test_memory_governance.py::test_memory_manager_redacts_explicit_writes_tools_and_pre_compress`

Rollback plan:
- Set `enterprise.enabled: false` to preserve normal Hermes behavior.
- If the patch itself must be removed, delete the `_govern_memory_payload(...)`
  calls in `MemoryManager` and keep the enterprise module inert.

Notes:
- This is a redaction boundary, not tenant-scoped memory isolation, semantic
  memory classification, durable quarantine review, provider-specific recall
  ACLs, or cross-provider deletion enforcement.

## Entry Template

```markdown
### Patch: <short name>

Status:
Owner:
Date:
Upstream base:

Invariant:
- <What must always be true?>

Why plugin/sidecar cannot enforce it:
- <Why this must be inside or immediately beside a Hermes authority seam?>

Patch shape:
- <Smallest code change that enforces the invariant.>

Files touched:
- <core Hermes file>
- <enterprise file>
- <test file>

Enterprise-off compatibility:
- <Tests proving normal Hermes behavior stays unchanged.>

Enterprise-on security gate:
- <Tests proving the new enforcement works.>

Rollback plan:
- <How to remove or disable the patch without damaging upstream behavior.>

Notes:
- <Tradeoffs, open questions, or upstream PR candidate notes.>
```
