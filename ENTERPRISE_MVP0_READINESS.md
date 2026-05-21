# Enterprise MVP-0 Readiness

This document is the MVP-0 closure note for the downstream enterprise fork.
It is intentionally narrow: MVP-0 proves a local governance spine around
covered Hermes tool execution. It does not claim production enterprise
readiness.

## Gate Command

Run the release gate before merging MVP-0 runtime or policy changes:

```text
python scripts/enterprise_mvp0_gate.py
```

The gate runs:

1. `python -m compileall -q enterprise`
2. `python -m pytest -o addopts= --basetemp .pytest-tmp-enterprise tests/enterprise`
3. Targeted Hermes authority-seam regressions for tool-loop guardrails,
   tool-result persistence, and doctor diagnostics.

The matching GitHub Actions workflow is:

```text
.github/workflows/enterprise-mvp0-gate.yml
```

It runs on PRs and pushes targeting `enterprise/main` when enterprise code,
enterprise tests, patched Hermes authority seams, or enterprise planning docs
change.

## MVP-0 Claims Allowed

MVP-0 may claim only:

1. Enterprise mode exists and is disabled by default.
2. Covered local tool calls pass through an Action Firewall.
3. Covered tool outputs are sanitized before model-visible context.
4. Covered decisions write local audit events with redacted previews.
5. Deterministic runtime triage exists for covered checks.
6. Covered tools are checked against capability manifests and sandbox profiles.
7. Approval-required side effects are staged before execution is blocked.
8. Artifact records can be stored and hydrated only through explicit views.
9. Owner-scoped developer fast paths can allow low-risk local workspace file
   actions without network egress or sensitive-path bypass.
10. Enterprise Doctor reports missing critical MVP-0 controls.
11. Enterprise-off compatibility is regression-tested for touched paths.

## MVP-0 Claims Forbidden

MVP-0 must not claim:

1. Production enterprise readiness.
2. Full provider, memory, gateway, plugin, cron, or MCP governance.
3. Full tenant isolation or SaaS multi-tenancy.
4. Full Agentic WAF, SIEM, KMS, secret broker, or access broker behavior.
5. Full rollback for irreversible external side effects.
6. Complete semantic DLP or prompt-injection detection.
7. Secure streaming-provider egress.
8. Admin dashboard, fleet management, SSO, or assignment lifecycle.

## Release Evidence

| Evidence | Current artifact |
|---|---|
| Security truth ledger | `ENFORCEMENT_REALITY_AUDIT.md` |
| Core patch ledger | `PATCH_BOUNDARY_LEDGER.md` |
| Upstream compatibility notes | `UPSTREAM_COMPATIBILITY.md` |
| Gate runner | `scripts/enterprise_mvp0_gate.py` |
| CI gate | `.github/workflows/enterprise-mvp0-gate.yml` |
| Release-gate tests | `tests/enterprise/test_mvp0_release_gates.py` |
| Doctor diagnostics | `enterprise/doctor.py` and `hermes_cli/doctor.py` |

## MVP-1 Starting Point

The next phase should close bypass classes that MVP-0 deliberately leaves open:

1. Provider egress wrapper, including streaming policy.
2. Memory write/read governance.
3. Plugin and MCP admission policy.
4. Gateway identity binding and assignment policy.
5. Cron owner, intent, expiry, and policy context.
6. Access Broker and approval lifecycle.
7. Secret Broker and short-lived credential issuance.
