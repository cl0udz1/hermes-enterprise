# Enterprise MVP-1 Readiness

This document is the MVP-1 closure note for the downstream enterprise fork.
It records what is implemented, what can be claimed, what must not be claimed,
and what the next milestone should build.

MVP-1 is a governed authority-seam foundation. It is not yet a complete
enterprise product with a full admin dashboard, SSO lifecycle, real vault/KMS,
SIEM export, tenant isolation, or managed fleet operations.

## Baseline

| Item | Value |
|---|---|
| Downstream branch | `enterprise/main` |
| Closure commit | `45a7ffa7d35a6b7631e8cb64cc545c0b0bab108b` |
| GitHub milestone | `MVP-1 Enterprise Governance` |
| Open `enterprise-mvp1` issues at closure | none |
| Open PRs at closure | none |
| Release gate | `python scripts/enterprise_mvp0_gate.py` |
| Latest local gate result | 113 enterprise tests passed; 15 targeted Hermes authority-seam tests passed |

The gate name remains `enterprise_mvp0_gate.py` for continuity, but the suite
now includes the MVP-1 enterprise tests and patched Hermes authority-seam
regressions.

## Completed MVP-1 Slices

| Issue | PR | Control | Closure status |
|---|---|---|---|
| #14 | #22 | Initial provider egress guard | merged |
| #15 | #24 | Memory governance guard | merged |
| #16 | #25 | Plugin and MCP admission guard | merged |
| #17 | #26 | Gateway identity binding | merged |
| #18 | #27 | Cron governance wrapper | merged |
| #19 | #28 | Access Broker grant lifecycle | merged |
| #20 | #29 | Fake Secret Broker lifecycle | merged |
| #23 | #30 | Expanded provider egress coverage | merged |

## Claims Allowed

MVP-1 may claim only these implemented, tested behaviors:

1. Enterprise mode remains disabled by default.
2. Covered local tool calls pass through the Action Firewall before execution.
3. Covered tool results are sanitized before model-visible context.
4. Covered provider request payloads for Chat Completions, Codex Responses,
   Anthropic Messages, Bedrock Converse, and auxiliary model calls pass through
   deterministic provider-egress governance.
5. Deterministic secret-bearing streaming requests are denied under the
   `deny_sensitive_streaming` posture.
6. Memory Manager read/write payloads pass through deterministic memory
   governance.
7. Unapproved plugins, unmanifested plugin tools, unapproved MCP servers, and
   undeclared MCP tools are quarantined before becoming active authority in
   enterprise mode.
8. Gateway platform users and channels can be bound to enterprise subjects
   through assignment policy, and unmapped subjects fail closed.
9. Cron jobs can be evaluated for owner, intent, expiry, and policy context
   before execution, and approved cron context is bound to the agent subject.
10. Staged approval-required actions can be converted into scoped, expiring
    Access Broker grants bound to the original action hash.
11. Revoked, expired, changed, or mismatched access grants fail closed.
12. The fake Secret Broker issues opaque short-lived credential references only
    after a valid secret-issue grant.
13. Raw fake secrets are not emitted into governed provider payloads, tool
    messages, audit event JSON, or credential references on covered paths.
14. Enterprise Doctor can report the implemented controls and flag missing
    critical controls for team, enterprise, or regulated posture.
15. Enterprise-off compatibility is tested for touched paths.

## Claims Forbidden

MVP-1 must not claim:

1. Production enterprise readiness.
2. A complete managed multi-tenant SaaS platform.
3. Full SSO, SCIM, RBAC, org lifecycle, or admin dashboard behavior.
4. Full approved-action execution workflow or approval UI/API.
5. Real external vault, KMS, or cloud secret-manager integration.
6. SIEM export, tamper-evident audit storage, or long-term audit retention.
7. Tenant/workspace isolation across profiles, memory, artifacts, logs, and
   execution sandboxes.
8. OS/container-level syscall, filesystem, or network sandbox enforcement.
9. Complete semantic DLP, prompt-injection classification, or LLM-based WAF.
10. Streamed provider response scanning. MVP-1 denies deterministic
    secret-bearing streaming requests instead.
11. Provider egress coverage for embeddings, image-generation provider plugins,
    every direct provider client factory, or every future upstream provider
    path.
12. Plugin runtime sandboxing, code-signature verification, or dynamic
    revocation of already-running MCP servers.
13. Real enterprise secret retrieval by agents. MVP-1 proves the lifecycle with
    opaque fake-broker credentials only.

## Evidence Matrix

| Control | Runtime seam | Evidence |
|---|---|---|
| Action Firewall | `agent/tool_executor.py` | `tests/enterprise/test_action_firewall.py` |
| Tool-result sanitizer | `agent/tool_dispatch_helpers.py` | `tests/enterprise/test_result_firewall.py` |
| Provider egress | `agent/transports/*`, `agent/auxiliary_client.py`, streaming helpers | `tests/enterprise/test_provider_egress.py` |
| Memory governance | `agent/memory_manager.py` | `tests/enterprise/test_memory_governance.py` |
| Plugin/MCP admission | `hermes_cli/plugins.py`, `tools/mcp_tool.py` | `tests/enterprise/test_plugin_mcp_admission.py` |
| Gateway identity | `gateway/run.py` | `tests/enterprise/test_gateway_identity.py` |
| Cron governance | `cron/scheduler.py` | `tests/enterprise/test_cron_governance.py` |
| Access Broker | `enterprise/access.py`, `enterprise/firewall/action.py` | `tests/enterprise/test_access_broker.py` |
| Secret Broker | `enterprise/secrets.py` | `tests/enterprise/test_secret_broker.py` |
| Enterprise Doctor | `enterprise/doctor.py`, `hermes_cli/doctor.py` | `tests/enterprise/test_enterprise_doctor.py` |
| Release gate | `scripts/enterprise_mvp0_gate.py` | full enterprise suite plus targeted Hermes authority-seam tests |

Detailed control evidence and limitations live in
`ENFORCEMENT_REALITY_AUDIT.md`. Core Hermes patch boundaries live in
`PATCH_BOUNDARY_LEDGER.md`.

## Release Gate

Before merging runtime, policy, or claim-boundary changes into
`enterprise/main`, run:

```text
python scripts/enterprise_mvp0_gate.py
```

For local Windows runs in this workspace, use the same pytest posture the gate
uses internally:

```text
python -m pytest -o addopts="" --basetemp=.pytest-tmp-enterprise tests\enterprise
```

Latest local verification for this closure note:

```text
python scripts\enterprise_mvp0_gate.py
113 enterprise tests passed.
15 targeted Hermes authority-seam tests passed.
```

## MVP-1 Release Decision

MVP-1 is ready to be treated as an internal security-foundation checkpoint when
the release gate passes and the following files are kept current:

1. `ENTERPRISE_MVP1_READINESS.md`
2. `ENFORCEMENT_REALITY_AUDIT.md`
3. `PATCH_BOUNDARY_LEDGER.md`
4. `.github/workflows/enterprise-mvp0-gate.yml`
5. `.github/PULL_REQUEST_TEMPLATE.md`

It is not ready to be sold or described as a complete enterprise deployment
platform. The honest positioning is:

```text
Hermes Enterprise MVP-1 adds tested governance seams for tool execution,
tool results, provider egress, memory, plugins, MCP, gateway identity, cron,
access grants, and fake short-lived secret credentials. It remains a downstream
security foundation, not a full enterprise control plane.
```

## Next Milestone Direction

The next real milestone should be `MVP-2 Managed Enterprise Surface`. It should
avoid broad new security promises and turn the MVP-1 foundations into operator
workflows:

1. Approval queue API and UI for staged actions and Access Broker grants.
2. Admin assignment surface for employees, agents, profiles, gateway channels,
   cron jobs, and allowed tool scopes.
3. Real vault/KMS adapter behind the Secret Broker contracts.
4. Tamper-evident audit chain and SIEM export.
5. Tenant/workspace isolation model for profiles, memory, artifacts, logs, and
   execution roots.
6. Runtime sandbox enforcement beyond observed intent checks.
7. Policy-pack authoring and dry-run simulator for admins.
8. Upstream-sync discipline for keeping `main` close to NousResearch Hermes and
   `enterprise/main` as the downstream product branch.
