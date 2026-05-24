# Patch Boundary Ledger

This ledger records every enterprise fork change that touches mature Hermes core
runtime files.

The goal is simple: keep Hermes upstream-shaped. Add enterprise modules first,
use adapter hooks second, and patch core only where a real enforcement boundary
cannot be controlled any other way.

## Current Status

Nine enterprise runtime authority patch points exist:

1. MVP-0 Action Firewall v0 patches the Hermes tool execution preflight in
   `agent/tool_executor.py`.
2. MVP-0 Tool-Result Sanitizer v0 patches the Hermes tool-result message helper
   in `agent/tool_dispatch_helpers.py`.
3. MVP-1 Provider Egress Guard patches provider payload assembly in
   `agent/transports/chat_completions.py`, `agent/transports/codex.py`,
   `agent/transports/anthropic.py`, and `agent/transports/bedrock.py`.
4. MVP-1 Memory Manager Governance Guard patches memory provider orchestration
   in `agent/memory_manager.py`.
5. MVP-1 Plugin/MCP Admission Guard patches plugin import and plugin tool
   registration in `hermes_cli/plugins.py`.
6. MVP-1 Plugin/MCP Admission Guard patches MCP server startup and MCP tool
   registration in `tools/mcp_tool.py`.
7. MVP-1 Provider Egress Guard patches auxiliary model-call kwargs in
   `agent/auxiliary_client.py`.
8. MVP-1 Provider Egress Guard patches sensitive streaming denial seams in
   `agent/chat_completion_helpers.py` and `agent/codex_runtime.py`.
9. Enterprise Doctor patches `hermes_cli/doctor.py` for diagnostics only.

The patches are disabled by default through `enterprise.enabled: false`. They do
not yet patch a real external vault/KMS, embeddings, or every direct provider
client factory.

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

### Patch: Provider Egress Guard

Status: MVP-1 slice
Owner: downstream enterprise fork
Date: 2026-05-23
Upstream base: `4e4559f6e`

Invariant:
- In enterprise mode, covered provider request payloads must pass through
  deterministic egress sanitization before provider submission.
- Covered sensitive streaming requests must be explicitly denied instead of
  streaming raw secret-bearing payloads.

Why plugin/sidecar cannot enforce it:
- A plugin cannot reliably see the final provider payload after Hermes applies
  provider-profile quirks, request overrides, role rewrites, tool schema
  shaping, and extra_body assembly.

Patch shape:
- Add route-aware transport-level calls after Chat Completions, Codex
  Responses, Anthropic Messages, and Bedrock Converse payload assembly.
- Add auxiliary model-call kwargs governance before auxiliary
  `chat.completions.create(...)` dispatch.
- Add sensitive streaming denial checks before Chat Completions streaming and
  Codex Responses streaming.
- Keep all sanitizer logic in `enterprise/provider_egress.py`.
- Reuse shared deterministic model-boundary sanitization.

Files touched:
- `agent/transports/chat_completions.py`
- `agent/transports/codex.py`
- `agent/transports/anthropic.py`
- `agent/transports/bedrock.py`
- `agent/auxiliary_client.py`
- `agent/chat_completion_helpers.py`
- `agent/codex_runtime.py`
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
- `tests/enterprise/test_provider_egress.py::test_codex_responses_transport_redacts_before_provider`
- `tests/enterprise/test_provider_egress.py::test_anthropic_messages_transport_redacts_before_provider`
- `tests/enterprise/test_provider_egress.py::test_bedrock_converse_transport_redacts_before_provider`
- `tests/enterprise/test_provider_egress.py::test_auxiliary_kwargs_are_governed_before_call`
- `tests/enterprise/test_provider_egress.py::test_sensitive_streaming_payload_is_denied_by_policy`

Rollback plan:
- Set `enterprise.enabled: false` to preserve normal Hermes behavior.
- If the patch itself must be removed, delete the call to
  `_apply_enterprise_provider_egress(...)` in `ChatCompletionsTransport` and
  keep the enterprise module inert.

Notes:
- Streaming posture is `deny_sensitive_streaming`: deterministic secret
  findings on streaming payloads deny the stream request rather than claiming
  response-stream scanning.
- This does not yet cover embeddings, image-generation provider plugins, or
  every direct provider client factory outside the main/auxiliary inference
  path.

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

### Patch: Plugin/MCP Admission Guard

Status: MVP-1 slice
Owner: downstream enterprise fork
Date: 2026-05-24
Upstream base: `81e9309ad`

Invariant:
- In enterprise mode, unapproved plugins must not import, plugin-provided tools
  must not register unless declared, unapproved MCP servers must not start, and
  undeclared MCP tools must not become model-visible registry tools.
- When enterprise mode is disabled, existing Hermes plugin and MCP behavior
  must stay unchanged.

Why plugin/sidecar cannot enforce it:
- A plugin cannot be the authority that decides whether its own code is safe to
  import.
- An external sidecar cannot reliably stop Hermes from exposing a newly
  discovered MCP tool after the MCP client has connected and registered schemas.

Patch shape:
- Add deterministic admission decisions in `enterprise/admission.py`.
- Check plugin manifests before import inside `PluginManager`.
- Check plugin-provided tools inside `PluginContext.register_tool(...)`.
- Check MCP server configs before connection and MCP tools before registry
  registration.

Files touched:
- `hermes_cli/plugins.py`
- `tools/mcp_tool.py`
- `enterprise/admission.py`
- `enterprise/contracts.py`
- `enterprise/config.py`
- `enterprise/doctor.py`
- `tests/enterprise/test_plugin_mcp_admission.py`
- `tests/enterprise/test_enterprise_doctor.py`

Enterprise-off compatibility:
- `tests/enterprise/test_plugin_mcp_admission.py::test_admission_disabled_allows_untrusted_plugin_without_audit`
- `tests/enterprise/test_plugin_mcp_admission.py::test_enterprise_off_plugin_tool_registration_is_unchanged`

Enterprise-on security gate:
- `tests/enterprise/test_plugin_mcp_admission.py::test_untrusted_plugin_is_not_imported_in_enterprise_mode`
- `tests/enterprise/test_plugin_mcp_admission.py::test_plugin_tool_admission_requires_admitted_plugin`
- `tests/enterprise/test_plugin_mcp_admission.py::test_approved_plugin_can_only_register_declared_tools`
- `tests/enterprise/test_plugin_mcp_admission.py::test_untrusted_mcp_server_is_not_started_in_enterprise_mode`
- `tests/enterprise/test_plugin_mcp_admission.py::test_mcp_tool_registration_requires_declared_tool`

Rollback plan:
- Set `enterprise.enabled: false` to preserve normal Hermes behavior.
- If the patch itself must be removed, delete the enterprise admission calls in
  `PluginManager`, `PluginContext.register_tool(...)`, `register_mcp_servers`,
  and `_register_server_tools(...)`, keeping the enterprise module inert.

Notes:
- This is an admission boundary. It does not claim plugin code sandboxing,
  code-signature verification, runtime syscall/network sandboxing, dynamic
  revocation of already-running MCP servers, or coverage of the separate memory
  and model-provider plugin discovery systems.

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
