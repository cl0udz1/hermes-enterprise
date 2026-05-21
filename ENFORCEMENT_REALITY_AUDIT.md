# Enforcement Reality Audit

This file separates current implementation truth from intended enterprise
architecture.

The rule: do not claim an enterprise security control exists until code and
tests prove it.

## Current Status

Enterprise package skeleton work has started, but no enterprise runtime
enforcement has been implemented yet.

Implemented so far:

1. Enterprise default config, disabled by default.
2. Enterprise mode resolver.
3. Runtime contract dataclasses with deterministic JSON/hashing.
4. Local SQLite audit store skeleton for structured events.
5. Enterprise tests for contracts, config defaults, import no-op behavior, and
   audit store append/list behavior.

No Hermes authority seam has been patched yet.

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

## Controls Not Yet Implemented

These are not real yet:

1. Action Firewall.
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

## First Enforcement Claims Allowed After MVP-0

MVP-0 may claim only what is implemented and tested:

1. Enterprise mode exists and is disabled by default.
2. Covered local tool calls pass through an action firewall.
3. Covered tool outputs are sanitized before model context.
4. Covered decisions write local audit events.
5. Deterministic runtime triage exists for covered checks.
6. Enterprise-off compatibility is tested for touched paths.

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

## Next Required Audit Update

Update this file during the first coding PR to record:

1. What `enterprise/` modules were added.
2. Whether any core Hermes files were touched.
3. Which tests prove enterprise disabled is a no-op.
4. Which controls are still planning-only.
