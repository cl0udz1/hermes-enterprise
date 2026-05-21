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

Hermes authority seams patched so far:

1. `agent/tool_executor.py` preflight for sequential tool execution.
2. `agent/tool_executor.py` preflight for concurrent tool execution.
3. `agent/tool_dispatch_helpers.py` tool-result message construction.

## Current Hermes Authority Surfaces

The enterprise blueprint identifies these Hermes areas as important enforcement
surfaces:

| Surface | Current status | Enterprise action |
|---|---|---|
| Tool execution | Hermes owns model-proposed tool execution. | Add action firewall at the strongest runtime seam. |
| Tool results | Hermes feeds tool outputs back into model context. | Add result sanitizer and context labeling. |
| Provider egress | Hermes sends prompts/context to providers. | Add provider egress policy in later slice. |
| Memory | Hermes stores and retrieves durable context. | Add memory proposal/quarantine gates. |
| Plugins | Hermes can load third-party tools/hooks. | Add manifest and trust admission. |
| Gateway | Hermes exposes messaging/platform authority. | Add identity binding and assignment policy. |
| Cron | Hermes can run scheduled work. | Add owner, intent, expiry, and policy wrapper. |
| Artifacts | Planned enterprise evidence and data objects. | Add vault and hydration boundary. |

## Current Hermes Files Touched

| File | Reason | Runtime authority impact |
|---|---|---|
| `pyproject.toml` | Include the new `enterprise` package in setuptools discovery. | None. |
| `hermes_cli/config.py` | Add disabled-by-default enterprise config defaults and root-key validation. | None; enterprise mode remains off. |
| `enterprise/manifests/core_tools.yaml` | Define initial risk metadata for covered high-risk tool families. | None; metadata is not enforced yet. |
| `agent/tool_executor.py` | Add lazy enterprise preflight before sequential and concurrent tool execution. | Blocks covered tool calls before execution when enterprise mode is enabled. |
| `agent/tool_dispatch_helpers.py` | Route tool-result message construction through the enterprise result sanitizer. | Sanitizes covered tool output before model-visible context when enterprise mode is enabled. |
| `enterprise/firewall/action.py` | Feed observed sandbox side effects into triage and emit sandbox violation audit events. | Enforces manifest/profile mismatch checks inside the existing action firewall path. |
| `enterprise/sandbox/*` | Define sandbox profiles and v0 observed-intent enforcement. | No direct runtime authority until called by the action firewall. |
| `enterprise/staging/*` | Store staged approval records and redacted previews for covered side-effecting actions. | No direct runtime authority until called by the action firewall. |

## Controls Not Yet Implemented

These are not real yet:

1. Approval queue, approval UI/API, and approved execution workflow for staged
   Action Firewall decisions.
2. Agentic WAF.
3. Provider egress gateway.
4. Secret broker.
5. Access Broker.
6. Artifact Vault.
7. Context Hydration Boundary.
8. Managed agent fleet controller.
9. Agent Builder.
10. SIEM export.
11. Tamper-evident audit storage.
12. Tenant/workspace isolation.
13. Full semantic DLP/prompt-injection classification beyond deterministic
    sanitizer patterns.
14. OS/container-level syscall, filesystem, and network sandbox enforcement.

## First Enforcement Claims Allowed After MVP-0

MVP-0 may claim only what is implemented and tested:

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
