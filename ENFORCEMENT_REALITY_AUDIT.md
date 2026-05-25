# Enforcement Reality Audit

This file separates current implementation truth from intended enterprise
architecture.

The rule: do not claim an enterprise security control exists until code and
tests prove it.

## Current Status

Enterprise package skeleton work has started, and the first runtime enforcement
seam is implemented for tool execution.

Implemented so far:

1. Enterprise default config, disabled by default.
2. Enterprise mode resolver.
3. Runtime contract dataclasses with deterministic JSON/hashing.
4. Local SQLite audit store skeleton for structured events.
5. Capability manifest schema and default core tool manifest.
6. Deterministic runtime triage engine for manifest, secret, path, network, and
   grant checks.
7. Small policy decision cache keyed by policy version, action hash, subject,
   tool, data classes, and expiry.
8. Enterprise tests for contracts, config defaults, import no-op behavior, and
   audit store append/list behavior.
9. Enterprise tests for manifest loading and required high-risk tool coverage.
10. Enterprise tests for deterministic triage denial/approval paths and cache
    expiry.
11. Action Firewall v0 for covered Hermes tool calls in sequential and
    concurrent execution.
12. Action Firewall audit events for proposed actions and policy decisions.
13. Enterprise-off and enterprise-on tests for blocked tool calls.
14. Tool-Result Sanitizer v0 for model-visible tool messages.
15. Result sanitizer audit events with raw hashes and redacted previews.
16. Enterprise-off and enterprise-on tests for sanitized tool results.
17. Sandbox profile definitions for all core manifest profiles.
18. Sandbox Enforcement v0 that observes filesystem, network, process/code, and
    explicit environment-forwarding intent before tool execution.
19. Sandbox violation audit events with redacted previews and observed side
    effect metadata.
20. Enterprise-off and enterprise-on tests for sandbox profile violations.
21. Staged Execution v0 for covered approval-required side effects.
22. Deterministic stage records with action hashes, preview URIs, idempotency
    keys, and redacted approval previews.
23. Action staged audit events for staged approval-required decisions.
24. Artifact Vault v0 for local report, diff, and evidence records.
25. Context Hydration Boundary v0 for metadata, summary, redacted, and full
    artifact views.
26. Hydration decision audit events that record route, view, budget, data
    class, and allow/deny status without storing raw hydrated content.
27. Developer Local Fast Path v0 for owner-scoped, sandbox-only, no-egress
    workspace file actions.
28. Fast-path audit metadata that records workspace roots, observed side
    effects, and the explicit fast-path detector on allowed decisions.
29. Enterprise Doctor v0 with machine-readable checks for enterprise mode,
    audit storage, firewall hook presence, manifests, triage latency config,
    sandbox profiles, result sanitizer, and streaming-policy readiness.
30. Hermes doctor renders an Enterprise Security section and reports team,
    enterprise, or regulated missing critical controls as actionable issues.
31. MVP-0 release-gate regression suite with shared fake enterprise secrets,
    fake provider capture, fake memory sink, and fake untrusted tool output
    fixtures.
32. Regression coverage for blocked execution, approval action-hash binding,
    covered secret non-leakage, and enterprise-off smoke behavior.
33. Cross-platform MVP-0 gate runner for enterprise compile checks, full
    enterprise tests, and targeted Hermes authority-seam regressions.
34. Downstream GitHub Actions workflow that runs the MVP-0 gate on PRs and
    pushes targeting `enterprise/main`.
35. MVP-0 readiness note that lists allowed claims, forbidden claims, release
    evidence, and the correct MVP-1 starting point.
36. Provider egress guard for Chat Completions, Codex Responses, Anthropic
    Messages, Bedrock Converse, and auxiliary model-call request payloads.
37. Memory Manager governance guard for governed memory read/write payloads.
38. Plugin and MCP admission contracts for plugin manifests, plugin tools, MCP
    servers, and MCP tools.
39. Plugin import and plugin tool-registration admission gates.
40. MCP server startup and MCP tool-registration admission gates.
41. Doctor check for strict Plugin/MCP admission probes.
42. Gateway identity binding and assignment policy for mapped platform users,
    channels, and subjects.
43. Cron governance wrapper for owner, intent, expiry, and policy-context
    metadata.
44. Access Broker grant lifecycle for staged approvals, expiry, revocation,
    approver identity, and exact action-hash binding.
45. Fake Secret Broker for grant-gated, short-lived opaque credential issuance.
46. Sensitive provider streaming denial for deterministic secret-bearing stream
    payloads; this is not a streamed response scanner.

Hermes authority seams patched so far:

1. `agent/tool_executor.py` preflight for sequential tool execution.
2. `agent/tool_executor.py` preflight for concurrent tool execution.
3. `agent/tool_dispatch_helpers.py` tool-result message construction.
4. `agent/transports/chat_completions.py` Chat Completions payload assembly.
5. `agent/memory_manager.py` memory provider orchestration.
6. `hermes_cli/plugins.py` plugin import and plugin tool registration.
7. `tools/mcp_tool.py` MCP server startup and tool registration.
8. `agent/transports/codex.py` Codex Responses payload assembly.
9. `agent/transports/anthropic.py` Anthropic Messages payload assembly.
10. `agent/transports/bedrock.py` Bedrock Converse payload assembly.
11. `agent/auxiliary_client.py` auxiliary model-call payload assembly.
12. `agent/chat_completion_helpers.py` Chat Completions streaming request
    denial for sensitive payloads.
13. `agent/codex_runtime.py` Codex Responses streaming request denial for
    sensitive payloads.
14. `gateway/run.py` gateway identity evaluation and subject binding before
    dispatch.
15. `cron/scheduler.py` cron owner, intent, expiry, and policy-context
    evaluation before scheduled execution.

## Current Hermes Authority Surfaces

The enterprise blueprint identifies these Hermes areas as important enforcement
surfaces:

| Surface | Current status | Enterprise action |
|---|---|---|
| Tool execution | Hermes owns model-proposed tool execution. | Add action firewall at the strongest runtime seam. |
| Tool results | Hermes feeds tool outputs back into model context. | Add result sanitizer and context labeling. |
| Provider egress | Chat Completions, Codex Responses, Anthropic Messages, Bedrock Converse, and auxiliary model-call payloads pass through the enterprise provider-egress guard when enterprise mode is enabled. Sensitive stream payloads with deterministic secret findings are denied. | Extend coverage to embeddings, image-generation provider plugins, remaining direct client factories, and buffered streamed response scanning. |
| Memory | Memory Manager payloads pass through the enterprise memory-governance guard when enterprise mode is enabled. | Extend to tenant-scoped memory isolation, provider-specific recall ACLs, semantic classification, and durable quarantine workflow. |
| Plugins | Enterprise mode checks plugin admission before enabled plugins import and before plugin tools register. | Extend to memory/model-provider plugin discovery, signature/provenance verification, and plugin runtime sandboxing. |
| MCP | Enterprise mode checks MCP server admission before startup and MCP tool admission before registration. | Add dynamic revocation for already-running servers, richer remote-server provenance, and per-tool risk manifests. |
| Gateway | Gateway events pass through enterprise identity binding and assignment policy before dispatch when enterprise mode is enabled. | Extend to SSO/SCIM lifecycle, role policy, admin assignment UI, and richer per-channel authorization. |
| Cron | Scheduled jobs pass through owner, intent, expiry, and policy-context governance before execution when enterprise mode is enabled. | Extend to admin-managed job approvals, recurrence policy, schedule drift review, and dashboard visibility. |
| Access grants | Staged approval-required actions can be approved into scoped, expiring grants bound to subject, tool, and action hash. | Add approval queue API/UI, multi-approver policy, and approved execution workflow. |
| Secrets | The fake Secret Broker issues opaque, short-lived credential references only after a valid secret-issue grant. | Replace fake provider with real vault/KMS adapters and rotation/revocation integration. |
| Artifacts | Enterprise artifact vault and hydration boundary exist as v0 modules. | Wire provider, memory, support bundle, and workflow paths through hydration in later slices. |

## Current Hermes Files Touched

| File | Reason | Runtime authority impact |
|---|---|---|
| `pyproject.toml` | Include the new `enterprise` package in setuptools discovery. | None. |
| `hermes_cli/config.py` | Add disabled-by-default enterprise config defaults and root-key validation. | None; enterprise mode remains off. |
| `enterprise/manifests/core_tools.yaml` | Define initial risk metadata for covered high-risk tool families. | None; metadata is not enforced yet. |
| `agent/tool_executor.py` | Add lazy enterprise preflight before sequential and concurrent tool execution. | Blocks covered tool calls before execution when enterprise mode is enabled. |
| `agent/tool_dispatch_helpers.py` | Route tool-result message construction through the enterprise result sanitizer. | Sanitizes covered tool output before model-visible context when enterprise mode is enabled. |
| `agent/transports/chat_completions.py` | Route OpenAI-compatible provider request payloads through the enterprise provider-egress guard. | Sanitizes Chat Completions provider payloads before provider submission when enterprise mode is enabled. |
| `agent/transports/codex.py` | Route Codex Responses request payloads through the enterprise provider-egress guard. | Sanitizes Responses API payloads before provider submission when enterprise mode is enabled. |
| `agent/transports/anthropic.py` | Route Anthropic Messages request payloads through the enterprise provider-egress guard. | Sanitizes Anthropic payloads before provider submission when enterprise mode is enabled. |
| `agent/transports/bedrock.py` | Route Bedrock Converse request payloads through the enterprise provider-egress guard. | Sanitizes Bedrock Converse payloads before provider submission when enterprise mode is enabled. |
| `agent/auxiliary_client.py` | Route auxiliary model-call kwargs through the enterprise provider-egress guard. | Sanitizes compression, vision, extraction, session-search, and other auxiliary LLM payloads when enterprise mode is enabled. |
| `agent/chat_completion_helpers.py` | Check Chat Completions stream payloads against enterprise egress policy before provider streaming. | Denies deterministic secret-bearing streaming requests when enterprise mode is enabled and `deny_sensitive_streaming` is configured. |
| `agent/codex_runtime.py` | Check Codex Responses stream payloads against enterprise egress policy before provider streaming. | Denies deterministic secret-bearing Responses streaming requests when enterprise mode is enabled and `deny_sensitive_streaming` is configured. |
| `agent/memory_manager.py` | Route memory write/read payloads through the enterprise memory-governance guard. | Sanitizes governed memory provider inputs and recalled memory outputs when enterprise mode is enabled. |
| `hermes_cli/plugins.py` | Route enabled plugin imports and plugin tool registrations through enterprise admission checks. | Quarantines unapproved plugins and unmanifested plugin-provided tools before they become active authority in enterprise mode. |
| `tools/mcp_tool.py` | Route MCP server startup and discovered tool registration through enterprise admission checks. | Quarantines unapproved MCP servers before connection and undeclared MCP tools before registry exposure in enterprise mode. |
| `gateway/run.py` | Route gateway source identity through enterprise subject assignment before event dispatch. | Denies unmapped gateway users/channels and binds mapped subjects to downstream action-firewall decisions in enterprise mode. |
| `cron/scheduler.py` | Route scheduled jobs through enterprise cron governance before agent execution. | Denies jobs missing owner, intent, expiry, or valid policy context and binds approved cron owner context to the agent in enterprise mode. |
| `enterprise/provider_egress.py` | Define deterministic provider request egress governance, route coverage, sensitive streaming denial, and audit emission. | Enforces covered provider payload boundaries when called by transports, auxiliary calls, or streaming request seams. |
| `enterprise/memory_governance.py` | Define deterministic memory payload governance and audit emission. | Enforces memory payload boundaries when called by Memory Manager. |
| `enterprise/admission.py` | Define deterministic plugin and MCP admission decisions and audit emission. | Enforces plugin/MCP admission when called by plugin and MCP runtime seams. |
| `enterprise/gateway_identity.py` | Define deterministic gateway subject binding and redacted identity audit events. | Enforces mapped platform-user/channel assignments when called by the gateway runtime seam. |
| `enterprise/cron_governance.py` | Define deterministic cron intent envelopes and redacted governance decisions. | Enforces owner, intent, expiry, and policy-context requirements when called by the scheduler seam. |
| `enterprise/access.py` | Store, approve, revoke, and look up scoped access grants for staged actions. | Allows exact approved action hashes through the action firewall and fails closed for changed, expired, or revoked grants. |
| `enterprise/secrets.py` | Define fake Secret Broker issuance behind secret-issue grants and opaque credential references. | Proves short-lived credential lifecycle without exposing raw secrets or claiming real vault/KMS integration. |
| `enterprise/sanitization.py` | Share deterministic secret and prompt-control sanitizers across result and provider boundaries. | No direct authority until called by a runtime boundary. |
| `enterprise/firewall/action.py` | Feed observed sandbox side effects into triage, apply developer local fast path, and emit sandbox/staging audit events. | Enforces manifest/profile mismatch checks and audited local fast-path decisions inside the existing action firewall path. |
| `enterprise/sandbox/*` | Define sandbox profiles and v0 observed-intent enforcement. | No direct runtime authority until called by the action firewall. |
| `enterprise/staging/*` | Store staged approval records and redacted previews for covered side-effecting actions. | No direct runtime authority until called by the action firewall. |
| `enterprise/artifacts/*` | Store artifact records and enforce explicit hydration views by route and data class. | No direct Hermes runtime authority until provider/memory/artifact consumers call the boundary. |
| `enterprise/fast_path.py` | Define owner-scoped developer fast-path eligibility for local workspace file actions. | No direct runtime authority until called by the action firewall. |
| `enterprise/doctor.py` | Produce machine-readable enterprise health checks. | Diagnostic only; does not enforce runtime authority. |
| `hermes_cli/doctor.py` | Render an Enterprise Security section from the enterprise doctor report. | Diagnostic only; no runtime enforcement change. |
| `tests/enterprise/conftest.py` | Provide shared fake provider, memory, secret, agent, and tool-output fixtures. | Test-only; no runtime authority. |
| `tests/enterprise/test_mvp0_release_gates.py` | Encode MVP-0 release-blocking regression gates. | Test-only; no runtime authority. |
| `scripts/enterprise_mvp0_gate.py` | Run the repeatable MVP-0 release gate locally and in CI. | Test/CI only; no runtime authority. |
| `.github/workflows/enterprise-mvp0-gate.yml` | Run the MVP-0 release gate for `enterprise/main`. | CI only; no runtime authority. |
| `ENTERPRISE_MVP0_READINESS.md` | State MVP-0 claim boundaries and release evidence. | Documentation only. |
| `ENTERPRISE_MVP1_READINESS.md` | State MVP-1 claim boundaries, closure evidence, and next milestone direction. | Documentation only. |

## Controls Not Yet Implemented

These are not real yet:

1. Approval queue, approval UI/API, and approved execution workflow for staged
   Action Firewall decisions.
2. Agentic WAF.
3. Provider egress coverage for embeddings, image-generation provider plugins,
   remaining direct client factories, and all streamed provider responses.
4. Real external secret broker integration with vault/KMS.
5. Full approval execution UI/API on top of staged records and access grants.
6. Plugin admission for memory-provider/model-provider discovery systems,
   plugin code-signature verification, and plugin runtime sandboxing.
7. Dynamic revocation of already-running MCP servers when enterprise policy is
   tightened during a live process.
8. Provider/runtime integration with the Artifact Vault and Context Hydration
   Boundary, plus deeper memory integration with artifact-backed quarantine.
9. Durable encrypted artifact storage and tenant-scoped artifact isolation.
10. Managed agent fleet controller.
11. Agent Builder.
12. SIEM export.
13. Tamper-evident audit storage.
14. Tenant/workspace isolation.
15. Full semantic DLP/prompt-injection classification beyond deterministic
    sanitizer patterns.
16. OS/container-level syscall, filesystem, and network sandbox enforcement.
17. Fully implemented provider streamed response scanner; current posture denies
    deterministic secret-bearing streaming requests instead of buffering and
    scanning response deltas.

## Current Enforcement Claims Allowed

MVP-0 and MVP-1 may claim only what is implemented and tested:

1. Enterprise mode exists and is disabled by default.
2. Covered local tool calls pass through an action firewall.
3. Covered tool outputs are sanitized before model context.
4. Covered decisions write local audit events.
5. Deterministic runtime triage exists for covered checks.
6. Enterprise-off compatibility is tested for touched paths.
7. Covered tool calls are checked against declared sandbox profiles and observed
   side effects before execution.
8. Covered approval-required side effects create staged records before
   execution is blocked pending approval.
9. Artifact records can be stored behind `artifact://...` URIs and hydrated only
   through explicit metadata, summary, redacted, or full views.
10. Full artifact hydration is denied for disallowed routes and secret-bearing
    data classes by default.
11. Owner-scoped local workspace file actions can be auto-allowed when the
    developer fast path is configured, audited, sandbox-only, and no-egress.
12. Enterprise Doctor can report implemented enterprise controls and flag
    missing critical controls before team rollout.
13. MVP-0 has release-gate regression tests for blocked execution, changed
    action arguments, fake secret handling, and enterprise-off compatibility.
14. MVP-0 has a repeatable local and CI gate command for enterprise release
    checks on the downstream `enterprise/main` branch.
15. Covered Memory Manager read/write paths pass through deterministic memory
    governance.
16. Unapproved plugins, unmanifested plugin tools, unapproved MCP servers, and
    undeclared MCP tools are quarantined before registry exposure in enterprise
    mode.
17. Gateway events can be bound to enterprise subjects through assignment
    policy, and unmapped gateway users/channels fail closed.
18. Cron jobs can be denied before execution when owner, intent, expiry, or
    policy context is missing or invalid.
19. Covered provider request payloads for Chat Completions, Codex Responses,
    Anthropic Messages, Bedrock Converse, and auxiliary model calls are
    sanitized before provider submission in enterprise mode.
20. Deterministic secret-bearing streaming provider requests are denied by
    policy instead of claiming streamed response scanning.
21. Access grants are scoped to staged action hashes and fail closed after
    action changes, expiry, or revocation.
22. Fake Secret Broker issues only opaque short-lived credential references
    after a valid access grant; real vault/KMS integration is not claimed.

## Bypass Classes To Track

Each implementation slice should test at least one bypass class where relevant:

1. Direct tool dispatch bypasses the firewall.
2. Special agent-loop tools bypass generic dispatch checks.
3. Tool output injects instructions into the next model turn.
4. Secret values leak into provider prompts, logs, memory, or audit previews.
5. Unmanifested plugin tools become available in enterprise mode.
6. Gateway user identity is not bound to an assignment.
7. Cron job executes without owner, intent, expiry, or policy context.
8. Approval is reused after action arguments change.
9. Artifact full content hydrates into an unauthorized route.
10. Enterprise disabled changes normal Hermes behavior.

## Audit Evidence Standard

For every security control, keep evidence of:

1. The enforcement point.
2. The policy decision.
3. The denied or allowed action hash.
4. Redacted previews only.
5. The test that proves the behavior.
6. The enterprise-off compatibility test.

## Latest Audit Evidence

Action Firewall v0 evidence:

1. Enforcement point: `agent/tool_executor.py` before sequential execution and
   before concurrent worker submission.
2. Policy decision: `enterprise.firewall.action.evaluate_tool_call(...)` using
   the deterministic triage engine and core capability manifest.
3. Denied/allowed action hash: included in blocked tool result and audit event
   `action_id`.
4. Redacted previews only: audit events store `terminal(command)` style
   previews and raw hashes, not raw arguments in previews.
5. Enterprise-off tests:
   `tests/enterprise/test_action_firewall.py::test_action_firewall_disabled_is_a_true_noop`
   and
   `tests/enterprise/test_action_firewall.py::test_enterprise_off_sequential_tool_execution_is_unchanged`.
6. Enterprise-on tests:
   `tests/enterprise/test_action_firewall.py::test_action_firewall_blocked_sequential_call_never_reaches_tool_runner`
   and
   `tests/enterprise/test_action_firewall.py::test_action_firewall_blocked_concurrent_call_is_not_submitted`.

Tool-Result Sanitizer v0 evidence:

1. Enforcement point: `agent/tool_dispatch_helpers.py::make_tool_result_message`
   before tool output is appended to conversation messages.
2. Policy decision: `enterprise.firewall.result.sanitize_tool_result(...)`
   using deterministic secret and prompt-injection pattern checks.
3. Raw hash: included in the sanitized model-visible label and audit
   `raw_sha256`.
4. Redacted previews only: `result_sanitized` audit events store sanitized
   previews without raw fake API keys.
5. Enterprise-off tests:
   `tests/enterprise/test_result_firewall.py::test_result_sanitizer_disabled_returns_content_unchanged`
   and `tests/run_agent/test_tool_name_db_persistence.py`.
6. Enterprise-on tests:
   `tests/enterprise/test_result_firewall.py::test_result_sanitizer_redacts_secret_and_neutralizes_prompt_bait`
   and
   `tests/enterprise/test_result_firewall.py::test_runtime_tool_result_is_sanitized_before_message_append`.

Sandbox Enforcement v0 evidence:

1. Enforcement point: `enterprise.firewall.action.evaluate_tool_call(...)`
   before the existing action-firewall policy decision is returned.
2. Policy decision: `enterprise.sandbox.evaluate_sandbox(...)` derives observed
   side effects from tool arguments and compares them to the tool manifest and
   sandbox profile.
3. Denied/allowed action hash: includes the observed requested side effects used
   by triage.
4. Redacted previews only: `sandbox_violation` audit events store counts,
   detectors, and side-effect labels, not raw environment values.
5. Enterprise-off tests:
   `tests/enterprise/test_sandbox_enforcement.py::test_action_firewall_disabled_skips_sandbox_enforcement`.
6. Enterprise-on tests:
   `tests/enterprise/test_sandbox_enforcement.py::test_action_firewall_denies_sandbox_violation_and_audits`
   and
   `tests/enterprise/test_sandbox_enforcement.py::test_action_firewall_sandbox_env_violation_does_not_leak_secret`.

Staged Execution v0 evidence:

1. Enforcement point: `enterprise.firewall.action.evaluate_tool_call(...)`
   after deterministic triage and before a blocked approval-required tool
   result is returned.
2. Policy decision: `enterprise.staging.should_stage_action(...)` stages only
   covered approval-required side effects.
3. Approval binding: `StagedExecutionRecord` stores the action hash, preview
   URI, idempotency key, subject, tool name, and status.
4. Redacted previews only: stage previews include safe argument keys and
   deterministic redaction, not full write content or raw fake API keys.
5. Enterprise-on tests:
   `tests/enterprise/test_staged_execution.py::test_action_firewall_stages_approval_required_tool_and_audits`
   and
   `tests/enterprise/test_staged_execution.py::test_stage_preview_redacts_secret_like_values`.
6. Explicit limitation: MVP-0 does not execute approved staged actions and does
   not claim rollback for irreversible side effects.

Context Hydration v0 evidence:

1. Enforcement point: `enterprise.artifacts.hydration.hydrate_context(...)`
   before artifact content is released from `ArtifactVault`.
2. Policy decision: route, requested view, data class, and byte budget decide
   whether metadata, summary, redacted, or full content can be returned.
3. Unauthorized full hydration: full content is denied for provider-style routes
   outside `enterprise.hydration.full_allowed_routes`.
4. Secret-bearing content: full hydration is denied for configured secret data
   classes by default; redacted hydration removes deterministic secret patterns.
5. Audit evidence: `hydration_decision` events record view, route, budget,
   data class, allow/deny status, and content hash without storing raw hydrated
   content.
6. Enterprise-on tests:
   `tests/enterprise/test_context_hydration.py::test_hydration_denies_full_content_to_provider_route_and_audits`,
   `tests/enterprise/test_context_hydration.py::test_hydration_allows_redacted_view_without_secret_leak`,
   and
   `tests/enterprise/test_context_hydration.py::test_hydration_denies_full_secret_content_even_on_allowed_route`.
7. Explicit limitation: MVP-0 does not yet force provider, memory, gateway,
   support-bundle, or workflow code paths through hydration.

Developer Local Fast Path v0 evidence:

1. Enforcement point: `enterprise.firewall.action.evaluate_tool_call(...)`
   after deterministic triage/sandbox checks and before staged approval.
2. Policy decision: `enterprise.fast_path.apply_developer_fast_path(...)`
   can convert eligible local file read/write decisions to allow only when the
   subject owns the configured workspace root.
3. Non-bypass rule: the fast path does not override deny/quarantine decisions,
   sandbox findings, network egress, explicit environment forwarding, process or
   code execution, secret-looking content, sensitive paths, denied roots, or
   paths outside the owner workspace.
4. Audit evidence: action proposal and policy decision events include
   `fast_path`, `fast_path_detectors`, workspace roots, side effects, and the
   reason without storing raw file content.
5. Enterprise-on tests:
   `tests/enterprise/test_developer_fast_path.py::test_developer_fast_path_allows_owner_workspace_write_and_audits`,
   `tests/enterprise/test_developer_fast_path.py::test_developer_fast_path_does_not_override_secret_content_denial`,
   and
   `tests/enterprise/test_developer_fast_path.py::test_developer_fast_path_does_not_cross_workspace_boundary`.
6. Explicit limitation: MVP-0 does not yet model full team assignments, SSO
   identity, project ownership lifecycle, or admin UI for fast-path policy.

Enterprise Doctor v0 evidence:

1. Enforcement point: none; this is diagnostic support, not a runtime gate.
2. Machine-readable report:
   `enterprise.doctor.run_enterprise_doctor(...).to_dict()` returns overall
   status, mode, enabled flag, and per-check status/detail/remediation.
3. Human CLI surface: `hermes_cli.doctor._check_enterprise_security(...)`
   renders the Enterprise Security section in `hermes doctor`.
4. Critical checks: enterprise mode config, audit store, action firewall hook,
   capability manifest loading, triage latency config, sandbox profile coverage,
   result sanitizer, provider egress guard, memory governance, Plugin/MCP
   admission, and streaming policy readiness.
5. Fail-closed posture: missing critical controls fail in team, enterprise, or
   regulated mode; Developer Secure can warn for incomplete future controls.
6. Tests:
   `tests/enterprise/test_enterprise_doctor.py::test_enterprise_doctor_team_fails_missing_streaming_policy`,
   `tests/enterprise/test_enterprise_doctor.py::test_enterprise_doctor_detects_manifest_loader_failure`,
   and
   `tests/enterprise/test_enterprise_doctor.py::test_hermes_cli_renders_enterprise_doctor_section`.
7. Explicit limitation: Doctor does not replace enforcement, SIEM export,
   tamper-evident storage, all-provider egress coverage, or admin dashboard
   health management.

MVP-0 Release-Gate Regression Suite evidence:

1. Enforcement point: none; this slice adds regression evidence for existing
   MVP-0 controls and does not add runtime authority.
2. Shared fixtures: `tests/enterprise/conftest.py` provides fake provider
   capture, fake memory sink, fake OpenAI-style secret, fake untrusted tool
   output, mock tool calls, and lightweight agent construction.
3. Blocked execution gate:
   `tests/enterprise/test_mvp0_release_gates.py::test_release_gate_blocked_tool_action_does_not_execute`
   proves a blocked pre-tool decision never reaches `handle_function_call`.
4. Approval binding gate:
   `tests/enterprise/test_mvp0_release_gates.py::test_release_gate_changed_action_args_invalidate_staged_approval`
   proves changed args produce a different action hash, stage id, and
   idempotency key.
5. Secret non-leakage gate:
   `tests/enterprise/test_mvp0_release_gates.py::test_release_gate_fake_secret_absent_from_provider_audit_session_and_memory`
   checks the fake secret is absent from provider payloads, audit events,
   session history, and memory session-end payloads on covered sanitized paths.
6. Enterprise-off gate:
   `tests/enterprise/test_mvp0_release_gates.py::test_release_gate_enterprise_off_smoke_preserves_normal_tool_path`
   proves disabled enterprise mode does not audit, stage, block, or sanitize
   the normal tool path.
7. Verification:
   `python -m pytest -o addopts="" --basetemp .pytest-tmp tests\enterprise`
   returned 70 passed.

MVP-0 Closure Gate evidence:

1. Enforcement point: none; this slice adds release assurance and does not add
   runtime authority.
2. Local gate: `scripts/enterprise_mvp0_gate.py` runs enterprise package
   compile checks, full `tests/enterprise`, and targeted Hermes seam
   regressions for tool-loop guardrails, tool-result persistence, and doctor
   diagnostics.
3. CI gate: `.github/workflows/enterprise-mvp0-gate.yml` runs the same gate for
   PRs and pushes targeting `enterprise/main` when enterprise code, patched
   seams, test files, or enterprise docs change.
4. Claim boundary: `ENTERPRISE_MVP0_READINESS.md` records allowed MVP-0 claims,
   forbidden claims, release evidence, and the MVP-1 starting point.
5. Verification:
   `python scripts\enterprise_mvp0_gate.py` passed locally with 70 enterprise
   tests and 15 targeted Hermes authority-seam tests.

MVP-1 Provider Egress v0 evidence:

1. Enforcement points: `agent/transports/chat_completions.py`,
   `agent/transports/codex.py`, `agent/transports/anthropic.py`,
   `agent/transports/bedrock.py`, `agent/auxiliary_client.py`,
   `agent/chat_completion_helpers.py`, and `agent/codex_runtime.py`.
2. Enterprise module: `enterprise/provider_egress.py` recursively sanitizes
   outbound provider payload strings, emits `provider_egress_sanitized`
   audit events only when the payload changes, and marks deterministic
   secret-bearing stream payloads as denied.
3. Shared sanitizer: `enterprise/sanitization.py` keeps result and provider
   boundary redaction behavior aligned.
4. Enterprise-off gate:
   `tests/enterprise/test_provider_egress.py::test_provider_egress_disabled_returns_payload_unchanged`
   and
   `tests/enterprise/test_provider_egress.py::test_chat_completions_provider_egress_disabled_preserves_transport_payload`
   prove disabled enterprise mode returns the original provider payload and
   preserves the Chat Completions transport payload.
5. Enterprise-on gates:
   `tests/enterprise/test_provider_egress.py::test_chat_completions_provider_egress_redacts_before_fake_provider`
   `tests/enterprise/test_provider_egress.py::test_chat_completions_profile_path_uses_provider_egress`,
   `tests/enterprise/test_provider_egress.py::test_codex_responses_transport_redacts_before_provider`,
   `tests/enterprise/test_provider_egress.py::test_anthropic_messages_transport_redacts_before_provider`,
   `tests/enterprise/test_provider_egress.py::test_bedrock_converse_transport_redacts_before_provider`,
   `tests/enterprise/test_provider_egress.py::test_auxiliary_kwargs_are_governed_before_call`, and
   `tests/enterprise/test_provider_egress.py::test_sensitive_streaming_payload_is_denied_by_policy`
   prove fake secrets are absent from covered provider payloads and sensitive
   stream payloads are denied by policy.
6. Doctor evidence:
   `tests/enterprise/test_enterprise_doctor.py` now includes the
   `provider_egress` diagnostic check.
7. Explicit limitation: streamed response scanning is not implemented. This
   slice uses `deny_sensitive_streaming`: deterministic secret-bearing stream
   requests are denied, but provider response tokens are not buffered or
   scanned.
8. Verification:
   `python scripts\enterprise_mvp0_gate.py` passed locally with 108 enterprise
   tests and 15 targeted Hermes authority-seam tests after this slice.

MVP-1 Memory Governance v0 evidence:

1. Enforcement point: `agent/memory_manager.py`, the common orchestrator for
   memory provider prefetch, queueing, sync, session-end extraction,
   pre-compression extraction, explicit memory-write mirroring, provider tool
   calls/results, and delegation observations.
2. Enterprise module: `enterprise/memory_governance.py` recursively sanitizes
   memory-bound payload strings and emits `memory_governance_sanitized` audit
   events only when the payload changes.
3. Enterprise-off gates:
   `tests/enterprise/test_memory_governance.py::test_memory_governance_disabled_returns_payload_unchanged`
   and
   `tests/enterprise/test_memory_governance.py::test_memory_manager_disabled_preserves_provider_payloads`
   prove disabled enterprise mode preserves payloads and does not audit.
4. Enterprise-on gates:
   `tests/enterprise/test_memory_governance.py::test_memory_manager_redacts_session_end_sync_and_recall_payloads`
   and
   `tests/enterprise/test_memory_governance.py::test_memory_manager_redacts_explicit_writes_tools_and_pre_compress`
   prove fake secrets do not reach fake memory provider payloads or recalled
   model-visible memory text on governed paths.
5. Upstream compatibility gate:
   `tests/agent/test_memory_provider.py` passed after the Memory Manager patch.
6. Doctor evidence:
   `tests/enterprise/test_enterprise_doctor.py` includes the
   `memory_governance` diagnostic check.
7. Explicit limitation: this is a deterministic redaction boundary. It does
   not yet provide tenant memory isolation, provider-specific recall ACLs,
   semantic classification, durable quarantine review, or memory deletion
   enforcement across third-party providers.

MVP-1 Plugin/MCP Admission v0 evidence:

1. Enforcement points:
   `hermes_cli/plugins.py::PluginManager.discover_and_load(...)`,
   `hermes_cli/plugins.py::PluginContext.register_tool(...)`,
   `tools/mcp_tool.py::register_mcp_servers(...)`, and
   `tools/mcp_tool.py::_register_server_tools(...)`.
2. Enterprise module: `enterprise/admission.py` decides admission for plugin
   manifests, plugin tools, MCP servers, and MCP tools, and emits
   `authority_admission_decision` audit events for quarantines.
3. Plugin import rule: bundled plugin sources are trusted by default; user,
   project, and entrypoint plugins require explicit enterprise trust or
   allow-list configuration before import in enterprise mode.
4. Tool rule: plugin-provided tools and MCP-discovered tools must be declared
   by manifest or trust metadata unless the enterprise admission config
   explicitly disables that requirement.
5. Enterprise-off gates:
   `tests/enterprise/test_plugin_mcp_admission.py::test_admission_disabled_allows_untrusted_plugin_without_audit`
   and
   `tests/enterprise/test_plugin_mcp_admission.py::test_enterprise_off_plugin_tool_registration_is_unchanged`
   prove disabled enterprise mode preserves ordinary plugin behavior.
6. Enterprise-on gates:
   `tests/enterprise/test_plugin_mcp_admission.py::test_untrusted_plugin_is_not_imported_in_enterprise_mode`,
   `tests/enterprise/test_plugin_mcp_admission.py::test_plugin_tool_admission_requires_admitted_plugin`,
   `tests/enterprise/test_plugin_mcp_admission.py::test_approved_plugin_can_only_register_declared_tools`,
   `tests/enterprise/test_plugin_mcp_admission.py::test_untrusted_mcp_server_is_not_started_in_enterprise_mode`,
   and
   `tests/enterprise/test_plugin_mcp_admission.py::test_mcp_tool_registration_requires_declared_tool`
   prove unapproved plugins/MCP servers and undeclared tools are quarantined
   before registry exposure.
7. Doctor evidence:
   `tests/enterprise/test_enterprise_doctor.py` includes the
   `plugin_mcp_admission` diagnostic check.
8. Explicit limitation: this is an admission boundary, not plugin code
   sandboxing, code-signature verification, runtime syscall/network sandboxing,
   dynamic revocation of already-running MCP servers, or governance for the
   separate memory/model-provider plugin discovery systems.
9. Verification:
   `python scripts\enterprise_mvp0_gate.py` passed locally with 86 enterprise
   tests and 15 targeted Hermes authority-seam tests after this slice.

MVP-1 Gateway Identity v0 evidence:

1. Enforcement point: `gateway/run.py` evaluates enterprise gateway identity
   before dispatch and binds the enterprise subject onto the event and source.
2. Enterprise module: `enterprise/gateway_identity.py` maps platform, user, and
   channel inputs to `GatewaySubjectBinding` records and emits
   `gateway_identity_decision` audit events without raw platform identifiers.
3. Enterprise-off gate:
   `tests/enterprise/test_gateway_identity.py::test_gateway_identity_disabled_is_noop`
   proves disabled enterprise mode allows normal gateway flow and does not
   audit.
4. Enterprise-on gates:
   `tests/enterprise/test_gateway_identity.py::test_gateway_identity_binds_assignment_and_audits_without_raw_ids`,
   `tests/enterprise/test_gateway_identity.py::test_gateway_identity_denies_unmapped_subject`,
   `tests/enterprise/test_gateway_identity.py::test_action_firewall_prefers_enterprise_gateway_subject`,
   and
   `tests/enterprise/test_gateway_identity.py::test_action_firewall_falls_back_to_private_gateway_user_id`
   prove mapped subjects bind correctly, unmapped subjects fail closed, and the
   action firewall prefers the enterprise subject over raw platform IDs.
5. Doctor evidence:
   `tests/enterprise/test_enterprise_doctor.py` includes the
   `gateway_identity` diagnostic check.
6. Explicit limitation: this is assignment binding, not full SSO, SCIM,
   organization lifecycle, RBAC, or admin UI.

MVP-1 Cron Governance v0 evidence:

1. Enforcement point: `cron/scheduler.py` evaluates enterprise cron governance
   before scheduled execution and binds approved owner context to the agent.
2. Enterprise module: `enterprise/cron_governance.py` validates owner, intent,
   expiry, and policy-context metadata and emits `cron_governance_decision`
   audit events with hashed intent data.
3. Enterprise-off gate:
   `tests/enterprise/test_cron_governance.py::test_cron_governance_disabled_is_noop`
   proves disabled enterprise mode preserves legacy cron behavior and does not
   audit.
4. Enterprise-on gates:
   `tests/enterprise/test_cron_governance.py::test_cron_governance_valid_envelope_allows_and_audits_without_raw_intent`,
   `tests/enterprise/test_cron_governance.py::test_cron_governance_missing_owner_fails_closed`,
   `tests/enterprise/test_cron_governance.py::test_cron_governance_expired_or_invalid_expiry_fails_closed`,
   and
   `tests/enterprise/test_cron_governance.py::test_cron_governance_binds_owner_to_agent_subject`
   prove valid jobs are allowed, malformed jobs fail closed, raw intent is not
   logged, and approved owner context reaches the agent.
5. Doctor evidence:
   `tests/enterprise/test_enterprise_doctor.py` includes the
   `cron_governance` diagnostic check.
6. Explicit limitation: this is a wrapper and subject-binding control, not an
   admin-managed scheduler UI, recurrence-risk engine, or SIEM event pipeline.

MVP-1 Access Broker v0 evidence:

1. Enforcement points: `enterprise.access.AccessGrantStore` approves and
   revokes staged grants, and `enterprise.firewall.action.evaluate_tool_call(...)`
   checks grants before allowing high-risk staged actions through.
2. Enterprise module: `enterprise/access.py` stores grants in local SQLite,
   binds them to subject, tool, action hash, approver, policy version, expiry,
   and revocation state, and emits `action_approved` and
   `access_grant_revoked` audit events.
3. Enterprise-on gates:
   `tests/enterprise/test_access_broker.py::test_access_broker_approves_stage_with_scoped_grant_and_audit`,
   `tests/enterprise/test_access_broker.py::test_access_grant_allows_exact_action_and_changed_args_stage_again`,
   and
   `tests/enterprise/test_access_broker.py::test_revoked_access_grant_fails_closed_for_same_action`
   prove approval creates a scoped grant, exact repeat execution is allowed,
   changed arguments stage again, and revoked grants deny the same action.
4. Explicit limitation: this is the grant lifecycle behind staged approvals,
   not a complete approval queue UI/API or approved side-effect execution
   workflow.

MVP-1 Secret Broker v0 evidence:

1. Enforcement point: `enterprise.secrets.FakeSecretBroker.issue_credential(...)`
   requires a valid secret-issue access grant before issuing a credential
   reference.
2. Enterprise module: `enterprise/secrets.py` validates subject, resource,
   scope action, expiry, and revocation; it returns
   `broker://credential/...` references and stores only credential metadata and
   secret hashes.
3. Denial gate:
   `tests/enterprise/test_secret_broker.py::test_fake_secret_broker_denies_without_policy_grant`
   proves broker access fails closed and audits request plus denial when no
   grant exists.
4. Issuance gates:
   `tests/enterprise/test_secret_broker.py::test_fake_secret_broker_issues_opaque_credential_after_valid_grant`
   and
   `tests/enterprise/test_secret_broker.py::test_secret_broker_rejects_unscoped_or_stale_grants`
   prove valid grants issue opaque credentials and mismatched, unscoped,
   expired, or revoked grants fail closed.
5. Non-leakage gate:
   `tests/enterprise/test_secret_broker.py::test_secret_broker_reference_does_not_leak_raw_secret_to_governed_boundaries`
   proves raw fake secrets are absent from credential references, model-visible
   tool messages, provider payloads, and audit event JSON on covered paths.
6. Doctor evidence:
   `tests/enterprise/test_enterprise_doctor.py` includes the `secret_broker`
   diagnostic check.
7. Explicit limitation: this is a fake in-memory broker for lifecycle proof. It
   does not claim real vault/KMS integration, provider runtime injection,
   cloud-secret rotation, or emergency revocation across live provider clients.

MVP-1 Closure evidence:

1. Closure note: `ENTERPRISE_MVP1_READINESS.md` records claim boundaries,
   completed issue/PR mapping, evidence matrix, and next milestone direction.
2. GitHub state at closure: all `enterprise-mvp1` issues are closed and no PRs
   are open against `enterprise/main`.
3. Release gate: `python scripts\enterprise_mvp0_gate.py` remains the required
   local and CI gate before merging runtime, policy, or claim-boundary changes.
4. Verification:
   `python scripts\enterprise_mvp0_gate.py` passed locally with 113 enterprise
   tests and 15 targeted Hermes authority-seam tests for this closure slice.
