# Upstream Compatibility Record

This file records the fork state before enterprise runtime implementation begins.

The enterprise product is a downstream distribution of Hermes, not a random
copy. Compatibility with upstream Hermes is a product requirement.

## Baseline Snapshot

Date:

```text
2026-05-20
```

Current upstream base:

```text
43c7a1b2621bdf7bf024f296c5d00e990c85e9de
```

Upstream commit date:

```text
2026-05-19T20:11:37-07:00
```

Current branch:

```text
codex/enterprise-planning-docs
```

Current remotes:

```text
origin  https://github.com/NousResearch/hermes-agent.git
```

Planned remotes after the GitHub fork exists:

```text
upstream  https://github.com/NousResearch/hermes-agent.git
origin    <maintainer or company fork URL>
```

## Current Local Planning Files

The following planning files exist before runtime implementation:

1. `HERMES_ENTERPRISE_BLUEPRINT.md`
2. `HERMES_ENTERPRISE_IMPLEMENTATION_PLAN.md`
3. `ENTERPRISE_AGENTIC_SECURITY_FINDINGS.md`
4. Saudi/GCC enterprise AI workflow research report.
5. `PATCH_BOUNDARY_LEDGER.md`
6. `UPSTREAM_COMPATIBILITY.md`
7. `ENFORCEMENT_REALITY_AUDIT.md`
8. `NOTICE.md`

## Baseline Test Evidence

Baseline tests have not been run yet in this record.

Before the first runtime patch, record:

1. Python executable and version.
2. Virtual environment used: `.venv`, `venv`, shared Hermes venv, or system
   Python.
3. Test command used.
4. Existing failures before enterprise code changes.
5. Current platform: Windows, WSL, Linux, macOS, or container.
6. Whether the failure is environment-related or repository-related.

## Enterprise-Off Compatibility Contract

When enterprise mode is disabled:

1. Existing Hermes tool schemas should load unchanged.
2. Existing CLI config should load unchanged.
3. Existing tool dispatch should work without enterprise policy.
4. Existing provider setup should not require enterprise configuration.
5. Existing memory paths should work without enterprise hooks.
6. Existing plugin loading should work without enterprise manifests.
7. Existing gateway paths should not be gated by enterprise policy.

## Upstream Sync Policy

1. Keep local `main` as a clean upstream mirror.
2. Keep `origin/main` as the fork-hosted clean mirror after the fork is added.
3. Keep enterprise work on `enterprise/main` and topic branches.
4. Merge upstream mirror changes into `enterprise/main` only after
   enterprise-off smoke tests pass.
5. Prefer merge for shared product branches.
6. Use rebase only for private topic branches.

## Current Compatibility Risk

Risk is low at this stage because only planning documents are being added.

The first meaningful compatibility risk appears when a core adapter hook is
added around tool execution, provider egress, memory, plugin admission, gateway
identity, or cron authority.
