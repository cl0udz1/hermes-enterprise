---
title: "Hermes Enterprise Implementation Plan"
version: "0.2"
status: "Final sanity-swept fork and build plan"
date: "2026-05-20"
source_blueprint: "HERMES_ENTERPRISE_BLUEPRINT.md v0.9"
audience:
  - "Enterprise fork maintainers"
  - "Security/runtime engineers"
  - "Future coding agents"
---

# Hermes Enterprise Implementation Plan

This file translates `HERMES_ENTERPRISE_BLUEPRINT.md` into a buildable fork
plan. It is intentionally practical: branch shape, code ownership, patch points,
test gates, and the exact order of work.

The hardest requirement is not adding security code. The hardest requirement is
adding mandatory enterprise enforcement while keeping Hermes upstream-shaped and
mergeable.

## 0. Non-Negotiables

These rules override convenience:

1. Do not build enterprise code on upstream-tracking `main`.
2. Do not commit enterprise work directly to the upstream mirror branch.
3. Do not create a broad fork when a small adapter hook enforces the invariant.
4. Do not claim a control exists until a regression test proves it.
5. Do not add runtime dependencies casually; dependency policy applies from the
   first code slice.
6. Do not let enterprise mode affect normal Hermes behavior when disabled.
7. Do not turn Developer Local Fast Path into break-glass.
8. Do not describe rollback for irreversible external actions; use staged
   execution, idempotency, compensation, or explicit irreversible gates.
9. Do not trust capability manifests as enforcement truth.
10. Do not skip baseline evidence before the first runtime patch.

## 1. Current Repository Reality

Current checkout state observed on 2026-05-20:

1. `origin` points to `https://github.com/NousResearch/hermes-agent.git`.
2. The current branch is `main`, tracking `origin/main`.
3. Enterprise planning files are currently untracked.
4. Hermes already has real runtime seams for the enterprise fork:
   - `agent/tool_executor.py`
   - `agent/conversation_loop.py`
   - `agent/agent_init.py`
   - `model_tools.py`
   - `tools/registry.py`
   - `toolsets.py`
   - `agent/memory_manager.py`
   - `hermes_cli/plugins.py`
   - `gateway/run.py`
   - `cron/jobs.py`
   - `cron/scheduler.py`
   - `hermes_cli/config.py`
   - `hermes_cli/doctor.py`

Do not start enterprise implementation directly on upstream-tracking `main`.

Immediate safety note: the planning docs are currently untracked in this local
checkout. Preserve them on a planning branch before any remote surgery, branch
rebasing, or code implementation.

## 2. Forking Model

### 2.1 Safe First Move From This Checkout

Because this checkout is currently on `main` with untracked enterprise planning
docs, the first move is to preserve the docs without changing upstream history:

```bash
git checkout -b codex/enterprise-planning-docs
git status --short
```

Then add only the planning artifacts:

```bash
git add HERMES_ENTERPRISE_BLUEPRINT.md HERMES_ENTERPRISE_IMPLEMENTATION_PLAN.md ENTERPRISE_AGENTIC_SECURITY_FINDINGS.md
git add -- "Enterprise AI Workflows in Saudi Arabia  Adoption, Trust, and Future Direction (2023*2026).md"
```

Do not add generated caches, virtualenv files, logs, local config, or unrelated
workspace changes. If the long Saudi report filename has encoding differences
on Windows, use shell completion or `git add -- <actual path shown by git
status>`.

The planning branch can later be pushed to the enterprise fork after the remote
layout is corrected.

### 2.2 Recommended Git Remote Layout

After creating a real fork under the chosen GitHub org/user, use this layout:

```bash
git remote rename origin upstream
git remote add origin git@github.com:<enterprise-org>/hermes-enterprise.git
git fetch upstream --tags
git fetch origin --tags
```

Expected meaning:

| Remote | Meaning |
|---|---|
| `upstream` | Official NousResearch Hermes repository. Never push enterprise work here unless contributing a generic upstream PR. |
| `origin` | Enterprise fork repository. Clean mirror branches, product branches, and enterprise releases live here. |

If using HTTPS instead of SSH:

```bash
git remote add origin https://github.com/<enterprise-org>/hermes-enterprise.git
```

Validation:

```bash
git remote -v
git fetch upstream --tags
git fetch origin --tags
```

`upstream` must point to NousResearch. `origin` must point to the enterprise
fork. Stop if that is not true.

### 2.3 Branch Model

Use three branch classes:

| Branch | Purpose | Rule |
|---|---|---|
| `main` | Local clean upstream mirror. | Pulls from `upstream/main`; no enterprise commits. |
| `origin/main` | Fork-hosted clean mirror. | Push updated upstream mirror here; no enterprise commits. |
| `enterprise/main` | Stable enterprise product branch. | Equivalent to `product-main`; only merge reviewed enterprise slices. |
| `codex/enterprise-*` or `feature/enterprise-*` | Work branches. | One bounded slice per branch. |

Initial setup after the fork remote exists:

```bash
git checkout main
git pull --ff-only upstream main
git push origin main
git checkout -b enterprise/main
git push -u origin enterprise/main
```

If the planning docs were first committed on `codex/enterprise-planning-docs`,
merge that branch into `enterprise/main` after remote layout is correct:

```bash
git checkout enterprise/main
git merge --no-ff codex/enterprise-planning-docs
git push origin enterprise/main
```

Daily development should happen on topic branches:

```bash
git checkout enterprise/main
git checkout -b codex/enterprise-mvp0-contracts
```

### 2.4 Upstream Sync Rule

Rebaseability is a product requirement.

1. Sync `main` from `upstream/main` weekly during active development.
2. Push the clean mirror to `origin/main`.
3. Merge `main` into `enterprise/main` only after enterprise-off smoke tests
   pass. Prefer merge for the shared product branch after the project has more
   than one maintainer; rebase is acceptable only for private topic branches.
4. Every enterprise core patch must be listed in `PATCH_BOUNDARY_LEDGER.md`.
5. Any generic hook useful to upstream Hermes should be proposed upstream as a
   small, non-enterprise-specific PR.
6. Never rewrite the agent loop, TUI dashboard chat, provider system, gateway,
   or all tools unless a release-blocking invariant cannot be enforced through a
   smaller adapter.

### 2.5 Branch Protection

Protect `enterprise/main` before code implementation:

1. Require PR review.
2. Require enterprise-off smoke tests.
3. Require `tests/enterprise` once they exist.
4. Block force-push.
5. Block direct pushes except emergency maintainer actions.
6. Require the patch-boundary ledger to change when core Hermes files change.

### 2.6 Release Branches

Use release branches only after MVP-0 is real:

```text
enterprise/release/mvp0
enterprise/release/mvp1
enterprise/release/v1
```

Each release branch must record:

1. Upstream base commit.
2. Enterprise patch-boundary ledger hash.
3. Enterprise-off smoke result.
4. Enterprise-on regression result.
5. Known unsupported claims.

### 2.7 Branding, Account Ownership, and Attribution

The enterprise product may be branded under the maintainer's own name, account,
company, or future organization. That is compatible with a downstream product
distribution, but it must be handled deliberately.

Rules:

1. The public fork can live under the maintainer's GitHub account or company
   org. `origin` should point there.
2. Keep Hermes' MIT license text and original copyright notice intact in all
   copies or substantial portions of the software.
3. Add a product-level attribution file before public or commercial release:
   `ATTRIBUTION.md` or `NOTICE.md`.
4. Do not describe the product as official Hermes, official Nous Research
   software, or an endorsed distribution unless that permission exists.
5. Use the final product name for user-facing branding, package metadata,
   dashboard copy, docs, screenshots, release notes, and deployment templates.
6. Keep upstream references where they are factual: upstream repo URL, base
   commit, retained license, compatibility notes, and contribution boundaries.
7. Avoid renaming mature internal Hermes modules early just for branding. Start
   with skin/theme, docs, package metadata, release names, dashboard/admin
   surfaces, and deployment names.
8. Release notes must include the upstream Hermes base commit and a short
   downstream-changes summary.
9. If the product becomes commercial or public-facing, run a trademark/name
   review before launch.

Suggested positioning:

```text
<Product Name> is an enterprise security distribution built on the open-source
Hermes Agent project, with additional governance, audit, policy, sandboxing, and
managed-agent controls.
```

Avoid positioning like:

```text
Official Hermes Enterprise
```

unless there is explicit upstream permission.

## 3. Forking Discipline

The enterprise fork must be additive first, adapter-based second, and core-patch
only where authority actually crosses a boundary.

### 3.1 Allowed Change Types

| Change type | Preferred location | Example |
|---|---|---|
| New enterprise service | `enterprise/` package | Policy engine, audit store, contracts, triage, grants. |
| Manifest data | `enterprise/manifests/` | Tool risk tiers and default sandbox profiles. |
| Tests | `tests/enterprise/` | Action firewall, audit, secret scanner, policy cache. |
| Docs | repo root docs | Patch ledger, enforcement audit, implementation plan. |
| Small core adapter | Existing Hermes authority seam | Tool executor calls enterprise firewall when enabled. |
| Upstream candidate | Generic hook with no enterprise branding | Tool-result sanitizer hook, registry metadata. |

### 3.2 Forbidden Early Moves

Do not do these in MVP-0:

1. Do not rebuild the Hermes conversation loop.
2. Do not replace the TUI or dashboard chat surface.
3. Do not rewrite provider plugins.
4. Do not edit every tool one by one.
5. Do not start with SaaS multi-tenancy.
6. Do not make enterprise mode the default for normal Hermes users.
7. Do not depend on prompt instructions as a security control.
8. Do not depend on plugin hooks alone for mandatory enforcement.

### 3.3 Dependency Discipline

Hermes dependency policy applies to the enterprise fork.

1. Prefer the Python standard library and existing Hermes helpers for MVP-0.
2. Do not add a dependency for contracts, enums, simple validation, or SQLite
   storage unless the standard library is clearly insufficient.
3. New PyPI dependencies must have upper bounds.
4. CI-only pip dependencies should be exact-pinned.
5. Git dependencies must be pinned to commit SHA.
6. If `pyproject.toml` changes, regenerate `uv.lock` and include it in the same
   PR.
7. Security-sensitive detectors should start deterministic and local; no network
   service should become required for MVP-0 policy decisions.
8. If a dependency is proposed for sandboxing, classify platform support first:
   Windows, WSL/Linux, macOS, container, and server deployment.

### 3.4 Platform Discipline

This repo may be developed on Windows, but many hard sandboxing primitives are
Linux/container-specific.

MVP-0 must separate:

| Enforcement type | Windows local | Linux/WSL/container |
|---|---|---|
| Path policy | Required. | Required. |
| Env scrubbing | Required. | Required. |
| Resource ceilings | Required where practical. | Required where practical. |
| Network destination policy | Required for URL-aware tools first. | Required for URL-aware tools first; network namespace later. |
| Process isolation | Best-effort wrapper first. | Container/namespace profile later. |
| seccomp/AppArmor/SELinux | Not native. | Later hardening target. |

Do not block MVP-0 on perfect OS sandboxing. Do block enterprise claims that
require OS sandboxing until the target deployment can enforce it.

## 4. Target Code Layout

Add a new top-level package:

```text
enterprise/
  __init__.py
  mode.py
  config.py
  contracts.py
  errors.py
  audit/
    __init__.py
    store.py
    events.py
    replay.py
  policy/
    __init__.py
    engine.py
    decisions.py
    bundle.py
    cache.py
  triage/
    __init__.py
    engine.py
    detectors.py
    latency.py
  manifests/
    core_tools.yaml
    loader.py
    schema.py
  firewall/
    __init__.py
    action.py
    result.py
  sandbox/
    __init__.py
    profiles.py
    enforcement.py
    observed_behavior.py
  waf/
    __init__.py
    checkpoints.py
    decisions.py
  artifacts/
    __init__.py
    vault.py
    hydration.py
  staging/
    __init__.py
    records.py
    idempotency.py
  grants/
    __init__.py
    access_broker.py
    lifecycle.py
  resources/
    __init__.py
    guard.py
    budgets.py
  doctor.py
  compatibility.py
```

MVP-0 can implement only the modules it needs. The folder structure reserves
the architecture so later slices do not invent new names.

## 5. Enterprise Mode

Enterprise mode must be explicit and off by default.

Recommended config shape:

```yaml
enterprise:
  enabled: false
  edition: developer_secure
  fail_closed_high_risk: true
  audit:
    backend: sqlite
  policy:
    bundle_path: null
  triage:
    low_risk_latency_budget_ms: 150
    llm_evaluator_enabled: false
  sandbox:
    enforce_manifests: true
  developer_fast_path:
    enabled: true
    no_egress_default: true
```

Config entry points:

1. Add defaults in `hermes_cli/config.py`.
2. Add enterprise-mode runtime loader in `enterprise/config.py`.
3. Keep all secrets out of config; secrets stay in vault/broker paths later.
4. If enterprise mode is disabled, core adapter hooks must behave like no-ops.
5. Use profile-aware Hermes paths through existing helpers such as
   `get_hermes_home()` where available. Do not hardcode `~/.hermes` or
   `Path.home() / ".hermes"` in enterprise storage.

Edition behavior:

| Edition | Missing control behavior |
|---|---|
| `developer_secure` | Warn for incomplete non-critical controls; fail closed for high-risk covered actions. |
| `team` | Fail closed for missing action firewall, audit, manifest, policy, and identity controls. |
| `enterprise` | Fail closed for missing action, audit, manifest, policy, identity, plugin, memory, provider, and gateway controls. |
| `regulated` | Fail closed for missing regional routing, audit, secret, storage, and isolation controls. |

## 6. Core Patch Points

Each core patch must be small, named, and tested.

| Patch point | Why it exists | Patch shape | Enterprise-off behavior | First tests |
|---|---|---|---|---|
| `agent/tool_executor.py` | Strongest boundary before model tool calls become real actions. | Call `enterprise.firewall.action.evaluate_tool_call(...)` before special-case and generic dispatch. | No-op; existing flow unchanged. | Block destructive fake tool; approval hash binding; enterprise-off smoke. |
| `agent/tool_dispatch_helpers.py` | Builds tool result messages and helper paths. | Route covered tool results through `enterprise.firewall.result.sanitize_tool_result(...)`. | No-op. | Tool-result prompt injection does not trigger follow-up tool. |
| `tools/registry.py` | Tool registration and schema exposure. | Attach enterprise manifest/risk metadata and hide unmanifested high-risk tools in enterprise mode. | No-op. | High-risk tool without manifest is unavailable. |
| `model_tools.py` | Generic tool dispatch and registry bridge. | Preserve dispatch; add enterprise audit/manifest checks only where executor cannot see path. | No-op. | Registry dispatch still works with enterprise disabled. |
| `agent/conversation_loop.py` | Prompt/model/final-response path. | Add lightweight enterprise checkpoint calls for prompt, model egress, final response, and streaming policy. | No-op. | Sensitive streaming disabled or buffered; provider mock sees redacted payload. |
| `agent/agent_init.py` | Agent/session initialization. | Create intent envelope and enterprise context when enabled. | No-op. | Session gets intent envelope only in enterprise mode. |
| `agent/memory_manager.py` | Durable memory sync/prefetch/tool calls. | Add memory proposal/quarantine hooks. | No-op. | Memory poisoning write quarantined. |
| `hermes_cli/plugins.py` | Plugin admission and tool registration. | Require manifest/trust metadata in enterprise mode. | No-op. | Unmanifested plugin tool denied. |
| `toolsets.py` | Platform tool exposure. | Define enterprise toolset profiles/downgrades. | Normal toolsets unchanged. | Enterprise profile hides risky tools without manifests. |
| `hermes_cli/doctor.py` | Health and support checks. | Add enterprise doctor checks. | Existing doctor unchanged plus optional section. | Missing firewall/audit/manifests detected. |
| `gateway/run.py` | Multi-user platform authority. | Later: identity/channel/policy gate before runtime authority. | No-op until MVP-1. | Unmapped user cannot execute high-risk action. |
| `cron/jobs.py`, `cron/scheduler.py` | Persistent scheduled authority. | Later: owner/intent/expiry/policy wrapper. | No-op until MVP-1. | Job without owner/expiry refused. |

## 7. MVP-0 Build Order

MVP-0 proves local governance around tool execution without claiming full
enterprise readiness.

### Slice 00: Fork Baseline

Deliverables:

1. Preserve current planning docs on `codex/enterprise-planning-docs`.
2. Create fork remote layout.
3. Create `enterprise/main`.
4. Add this plan, blueprint, patch ledger, compatibility doc, and enforcement
   audit doc.
5. Run baseline tests before any code changes.
6. Record baseline evidence in `UPSTREAM_COMPATIBILITY.md`.

Acceptance:

1. `main` remains upstream-clean.
2. `origin/main` remains a clean fork mirror.
3. `enterprise/main` contains planning docs only.
4. `git remote -v` clearly separates `upstream` and `origin`.
5. `git status --short --branch` is recorded before the first code slice.
6. Baseline test failures, if any, are documented before enterprise changes.

Baseline evidence to record:

1. Upstream base commit.
2. Python executable and version.
3. Test command used.
4. Existing failures before enterprise code.
5. Current platform: Windows, WSL, Linux, macOS, or container.
6. Whether `.venv`, `venv`, or shared Hermes venv was used.

### Slice 01: Enterprise Package Skeleton

Deliverables:

1. Add `enterprise/` package.
2. Add `enterprise/mode.py`.
3. Add `enterprise/config.py`.
4. Add no-op helpers so core adapters can call enterprise safely.

Acceptance:

1. Importing `enterprise` has no side effects.
2. Enterprise disabled returns no-op decisions.
3. Existing Hermes tests still pass for touched paths.

### Slice 02: Contracts

Deliverables:

1. Add dataclasses or pydantic-style lightweight models for:
   - Intent Envelope
   - Action Manifest
   - Audit Event
   - Policy Decision
   - Runtime Triage Decision
   - Access Request
   - Access Grant
   - Artifact Vault Record
   - Context Hydration Request
   - Staged Execution Record
   - Governance Change Record
   - Evaluation Run Record
2. Add JSON serialization helpers.
3. Add schema tests.

Acceptance:

1. Contracts round-trip to JSON.
2. Hash fields are stable.
3. Invalid enum values fail in enterprise tests.

### Slice 03: Local Audit Store

Deliverables:

1. Add `enterprise/audit/store.py`.
2. Use SQLite under profile-aware Hermes home.
3. Store structured events with redacted previews and hashes.
4. Add append-only behavior for MVP-0.

Acceptance:

1. Tool proposal, policy decision, denial, approval, execution, and sanitizer
   events can be replayed.
2. Fake secret is not stored raw.
3. Audit write failure fails closed for high-risk enterprise actions.

### Slice 04: Capability Manifests

Deliverables:

1. Add `enterprise/manifests/core_tools.yaml`.
2. Add loader and schema checks.
3. Cover first high-risk set:
   - terminal execution
   - file write/edit
   - code execution
   - browser/web fetch
   - provider/model egress
   - memory write
   - outbound send/message
4. Add registry admission helper.

Acceptance:

1. Manifest loader catches missing risk tier, sandbox profile, and side effects.
2. Enterprise mode can hide or deny high-risk tools without manifests.
3. Enterprise disabled does not change tool exposure.

### Slice 05: Fast-Path Runtime Triage

Deliverables:

1. Add deterministic detectors:
   - obvious secret patterns
   - path allow/deny
   - network destination allow/deny
   - revoked/expired grant check
   - manifest mismatch check
2. Add policy cache keyed by policy version, action hash, subject, tool, data
   class, and expiry.
3. Add latency measurement.
4. Do not add LLM evaluator in MVP-0.

Acceptance:

1. Low-risk local action decision does not call an LLM.
2. Triage emits decision path and latency.
3. High-risk timeout fails closed.

### Slice 06: Action Firewall Hook

Deliverables:

1. Patch `agent/tool_executor.py`.
2. Convert covered tool calls into Action Manifest.
3. Call policy/triage before execution.
4. Return a standard denied tool result when blocked.
5. Emit audit events.

Acceptance:

1. Blocked action does not execute.
2. Denied tool result is safe for model context.
3. Enterprise disabled keeps existing behavior.

### Slice 07: Tool-Result Sanitizer

Deliverables:

1. Add `enterprise/firewall/result.py`.
2. Sanitize secrets, role-like injection markers, tool-call bait, and hostile
   instruction framing from covered tool outputs.
3. Preserve hashes and redacted previews.

Acceptance:

1. Tool-result prompt injection does not become authority.
2. Fake API key is absent from session history and audit preview.
3. Raw output hash is available without storing raw sensitive content.

### Slice 08: Sandbox Enforcement v0

Deliverables:

1. Add sandbox profile definitions.
2. Enforce what can be enforced around existing tool paths first:
   - environment variable scrubbing
   - path allow/deny
   - network destination policy where tool path exposes URL/host
   - process/tool family risk tier
3. Record observed behavior versus manifest.

Acceptance:

1. Tool claiming no file/network access is blocked on covered attempted access.
2. Sandbox violation emits audit event.
3. Enterprise disabled keeps existing tool behavior.

### Slice 09: Staged Execution v0

Deliverables:

1. Add `enterprise/staging/records.py`.
2. Add dry-run/preview semantics for covered local file/code actions.
3. Add idempotency key generation for side-effecting actions.
4. Do not claim full rollback.

Acceptance:

1. High-risk covered side effect creates staged record before execution.
2. Approval binds to staged artifact/action hash.
3. Irreversible action without staging is denied or approval-required.

### Slice 10: Context Hydration v0

Deliverables:

1. Add Context Hydration Request contract usage.
2. Add Artifact Vault stub for report/diff/evidence records.
3. Hydrate only metadata/summary/redacted/full based on policy.
4. Prevent full content hydration to disallowed provider route.

Acceptance:

1. Unauthorized full hydration is denied.
2. Hydration decision records view, route, budget, and data class.
3. Hydrated secret-bearing content does not enter memory/compaction/logs raw.

### Slice 11: Developer Local Fast Path

Deliverables:

1. Add policy for owner-scoped, sandbox-only, no-egress local actions.
2. Auto-allow low-risk file read/write in assigned local workspace where policy
   permits.
3. Keep secrets, external sends, production mutations, regulated exports, and
   cross-workspace hydration outside the fast path.

Acceptance:

1. Local owner-scoped sandbox action is fast and audited.
2. External send or secret access is denied outside normal gate.
3. Admin can disable fast path via config.

### Slice 12: Enterprise Doctor v0

Deliverables:

1. Add enterprise section to `hermes_cli/doctor.py`.
2. Check:
   - enterprise mode config
   - audit store
   - action firewall hook
   - manifest loader
   - triage latency config
   - sandbox profile availability
   - result sanitizer
   - streaming policy
3. Add machine-readable doctor output for tests.

Acceptance:

1. Missing enforcement components are detected.
2. Developer Secure can warn.
3. Team/Enterprise modes fail closed for missing critical components.

### Slice 13: Regression Suite

Deliverables:

1. Add `tests/enterprise/`.
2. Add fixtures for fake tools, fake provider, fake secrets, fake tool outputs.
3. Cover release-blocking gates for MVP-0.

Acceptance:

1. Blocked tool action does not execute.
2. Changed action args invalidate approval.
3. Fake secret absent from provider mock, audit preview, session history, and
   memory payload for covered paths.
4. Enterprise-off smoke tests pass.

## 8. MVP-1 Build Order

MVP-1 closes bypass classes after MVP-0 proves the spine.

1. Provider egress wrapper across `agent/transports/`, provider profiles, retry
   helpers, streaming, summaries, and auxiliary model calls.
2. Memory firewall at `agent/memory_manager.py`.
3. Plugin trust registry at `hermes_cli/plugins.py`.
4. Gateway identity binding in `gateway/run.py`, `gateway/session.py`, and
   `gateway/slash_access.py`.
5. Cron owner/intent/expiry wrapper in `cron/jobs.py` and `cron/scheduler.py`.
6. Access Broker v0 and Access Grant lifecycle.
7. Artifact Vault v0 and Context Hydration Boundary.
8. Developer Local Fast Path hardening.
9. Buffered streaming scanner for sensitive provider routes.
10. Connector registry v0.

MVP-1 acceptance:

1. Direct provider bypass is detected or blocked.
2. Memory poisoning cannot influence tools.
3. Unmanifested plugin tool is unavailable in enterprise mode.
4. Unmapped gateway user cannot execute high-risk action.
5. Expired grant cannot authorize runtime behavior.
6. Context hydration denies unauthorized full content.

## 9. V1 Build Order

V1 makes this credible for a team deployment.

1. Admin API and minimal dashboard.
2. SSO/OIDC identity binding.
3. Workspace/team policy model.
4. Managed agent fleet controller.
5. Agent Builder v1.
6. Agent Security Operations dashboard.
7. SIEM/OTEL export.
8. Tamper-evident audit storage.
9. Governance change-control workflow.
10. Workspace isolation proofs across memory, artifacts, audit, session search,
    support bundles, and hydration.
11. Connector scope drift detection.
12. Workflow-level staged execution.

V1 acceptance:

1. Employee can use assigned agents without raw infrastructure authority.
2. Admin can pause, quarantine, revoke, and reassign agents.
3. Security can inspect WAF, policy, grant, hydration, staged execution, and
   incident evidence.
4. Cross-workspace access tests fail closed.

## 10. First Files To Create

Create these before touching core runtime files:

1. `PATCH_BOUNDARY_LEDGER.md`
2. `UPSTREAM_COMPATIBILITY.md`
3. `ENFORCEMENT_REALITY_AUDIT.md`
4. `ATTRIBUTION.md` or `NOTICE.md`
5. `enterprise/__init__.py`
6. `enterprise/mode.py`
7. `enterprise/config.py`
8. `enterprise/contracts.py`
9. `enterprise/audit/store.py`
10. `enterprise/policy/engine.py`
11. `enterprise/triage/engine.py`
12. `enterprise/manifests/core_tools.yaml`
13. `tests/enterprise/test_contracts.py`
14. `tests/enterprise/test_enterprise_mode_noop.py`

Only after those pass should the first core adapter patch land.

Do not create all reserved modules from the target layout at once. Empty package
directories are acceptable only when needed by imports/tests. A slice should add
the smallest set of files required for that slice plus its tests.

## 11. Patch Boundary Ledger Format

Every core patch must have one ledger entry:

```markdown
Patch: agent/tool_executor.py action firewall hook

Invariant:
- Tool calls are never executed directly from raw model output.

Why plugin/sidecar cannot enforce it:
- Special agent-loop tools and generic dispatch become authority inside the
  executor before external hooks can fail closed.

Patch shape:
- One enterprise-mode check before special-case and generic dispatch.
- No-op when enterprise mode disabled.

Files touched:
- agent/tool_executor.py
- enterprise/firewall/action.py
- tests/enterprise/test_action_firewall.py

Enterprise-off compatibility:
- Existing tool execution tests pass.

Release gate:
- Blocked tool action does not execute.
```

## 12. Testing Commands

Use repo-native tests first. The project guide says `scripts/run_tests.sh`
probes `.venv`, `venv`, and shared Hermes venv locations.

Linux/macOS/WSL:

```bash
scripts/run_tests.sh
python -m pytest tests/enterprise
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\enterprise
```

Fallback when venv layout differs:

```powershell
python -m pytest tests\enterprise
```

Minimum per-slice verification:

1. `python -m pytest tests/enterprise`
2. Targeted existing tests around touched Hermes files.
3. Enterprise-off smoke test.
4. `python -m compileall enterprise`

Windows note: prefer the active venv Python directly. If using npm/pnpm later
for TUI/dashboard work, prefer `npm.cmd` on this machine.

Do not treat a green enterprise test subset as enough when a core Hermes file is
touched. Add at least one existing upstream-style regression or smoke test for
that path.

## 12.1 CI Gate Plan

Before MVP-0 can be called complete, CI should run:

1. Enterprise contracts and unit tests.
2. Enterprise-off smoke tests.
3. Targeted Hermes tests for touched files.
4. Static import/compile check for `enterprise/`.
5. Manifest schema validation.
6. Dependency policy check when `pyproject.toml` or `uv.lock` changes.
7. Patch-boundary ledger check when core Hermes files change.

CI may be staged. The first PR can start with local tests plus documented manual
verification, but no runtime patch should merge without automated coverage.

MVP-0 downstream gate:

```text
python scripts/enterprise_mvp0_gate.py
```

The matching workflow is `.github/workflows/enterprise-mvp0-gate.yml`. It runs
for PRs and pushes targeting `enterprise/main` when enterprise code, enterprise
tests, patched Hermes authority seams, or enterprise planning docs change.

## 13. Enterprise-Off Smoke Contract

Every branch that touches core Hermes files must prove enterprise disabled does
not change normal Hermes behavior.

Smoke contract:

1. Existing tool schemas still load.
2. Existing CLI config still loads.
3. Existing tool dispatch works without enterprise config.
4. Existing provider setup path is not forced through enterprise policy.
5. Existing memory manager path works without enterprise hooks.
6. Existing plugin loading works without enterprise manifests.
7. Existing gateway path is not gated unless enterprise mode is enabled.

If enterprise-off behavior changes, the patch is too invasive.

## 14. Initial High-Risk Tool Set

MVP-0 should not try to classify every tool perfectly. Start with a small set:

| Tool family | Why high risk | MVP-0 handling |
|---|---|---|
| Terminal/process | Shell, filesystem, secrets, network, destructive commands. | Manifest, action firewall, sandbox profile, approval. |
| File write/edit | Can alter code, configs, secrets, or persistence. | Path policy, staged preview, diff artifact. |
| Code execution | Can read env, spawn process, write files, use network. | Sandbox profile, env scrub, resource guard. |
| Browser/web | Prompt injection, SSRF-ish behavior, data exfil. | URL policy, tool-result sanitizer, context labels. |
| Model/provider egress | Data leaves runtime. | MVP-0 skeleton, MVP-1 full wrapper. |
| Memory write | Hidden future authority. | MVP-0 contract, MVP-1 firewall. |
| Outbound send/message | External disclosure. | Draft-only in MVP-0; send gates later. |

## 15. Product Claim Boundaries

MVP-0 may claim:

1. Local enterprise mode exists.
2. Covered local tool calls pass through action firewall.
3. Covered tool outputs are sanitized before model context.
4. Local audit events exist for covered paths.
5. Deterministic fast-path triage exists for covered checks.
6. Enterprise-off compatibility is tested for touched paths.

MVP-0 may not claim:

1. Full provider governance.
2. Full gateway governance.
3. Full plugin governance.
4. Full memory-provider governance.
5. Full cron governance.
6. Full tenant isolation.
7. Full Agentic WAF coverage.
8. Full rollback of external side effects.
9. Production enterprise readiness.

## 16. Implementation Rules For Coding Agents

Any future coding agent must follow these rules:

1. Read `HERMES_ENTERPRISE_BLUEPRINT.md` and this file first.
2. Work one slice at a time.
3. Never merge MVP-1 work into MVP-0 to look more complete.
4. Add tests in the same slice as code.
5. Keep enterprise mode disabled by default.
6. Keep enterprise hooks no-op when disabled.
7. Update `PATCH_BOUNDARY_LEDGER.md` for every core patch.
8. Do not edit mature Hermes subsystems broadly.
9. Do not claim coverage without a test.
10. Preserve user/unrelated changes in the worktree.
11. Stop and update the implementation plan if repo reality contradicts it.
12. Prefer additive enterprise modules over core edits until a ledger entry
    proves the core edit is mandatory.
13. Use existing Hermes helpers and profile-aware paths.
14. Keep user-facing denial messages useful: explain what was blocked, why, and
    the next safe action, without exposing sensitive content.
15. Do not introduce an LLM evaluator into a hot path in MVP-0.

## 16.1 Slice Handoff Template

Every completed slice should leave a short handoff note:

```markdown
Slice NN handoff

Branch:
Upstream base:
Files changed:
Core Hermes files touched:
Patch-boundary ledger entries:
Enterprise-off tests:
Enterprise-on tests:
Known gaps:
Next slice:
```

If a slice touches a core Hermes file and has no ledger entry, it is incomplete.

## 17. First Coding PR

The first coding PR should be boring:

Title:

```text
enterprise: add mode, contracts, audit skeleton, and no-op compatibility tests
```

Files:

1. `enterprise/__init__.py`
2. `enterprise/mode.py`
3. `enterprise/config.py`
4. `enterprise/contracts.py`
5. `enterprise/audit/__init__.py`
6. `enterprise/audit/store.py`
7. `tests/enterprise/test_contracts.py`
8. `tests/enterprise/test_enterprise_mode_noop.py`
9. `PATCH_BOUNDARY_LEDGER.md`
10. `UPSTREAM_COMPATIBILITY.md`

No core Hermes runtime patch in the first PR unless the no-op package and tests
are already green.

Definition of done:

1. Contracts serialize and validate.
2. Enterprise mode defaults disabled.
3. Audit store can append redacted metadata events.
4. No core behavior changes.
5. Tests pass.

## 18. Final Readiness Checklist

Do not start runtime implementation until these are true:

1. Planning docs are committed on a non-upstream branch.
2. `main`, `origin/main`, `upstream`, `origin`, and `enterprise/main` have the
   meanings defined in this plan.
3. `enterprise/main` is protected before runtime patches begin.
4. Baseline test evidence is recorded before enterprise code changes.
5. `PATCH_BOUNDARY_LEDGER.md`, `UPSTREAM_COMPATIBILITY.md`, and
   `ENFORCEMENT_REALITY_AUDIT.md` exist.
6. The first coding PR is additive and keeps core Hermes behavior unchanged.
7. Any PR touching a core Hermes file includes a ledger entry, enterprise-off
   smoke coverage, and targeted upstream-style regression coverage.
8. Any new dependency follows Hermes dependency pinning policy.
9. Enterprise mode remains disabled by default.
10. Product claims match implemented and tested enforcement, not roadmap intent.
11. Branding, license preservation, upstream attribution, and "not official
    Hermes" positioning are documented before public release.

If any item is false, the next step is to fix the plan/repo state before adding
runtime enforcement.

## 19. The Fork Strategy In One Sentence

Keep Hermes upstream as the engine, add `enterprise/` as the control plane, and
patch only the authority chokepoints where the engine turns model proposals into
real effects.
