# Patch Boundary Ledger

This ledger records every enterprise fork change that touches mature Hermes core
runtime files.

The goal is simple: keep Hermes upstream-shaped. Add enterprise modules first,
use adapter hooks second, and patch core only where a real enforcement boundary
cannot be controlled any other way.

## Current Status

One enterprise runtime authority patch exists:

1. MVP-0 Action Firewall v0 patches the Hermes tool execution preflight in
   `agent/tool_executor.py`.

The patch is disabled by default through `enterprise.enabled: false`. It does
not patch provider egress, memory, gateway, plugin admission, or cron authority.

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
