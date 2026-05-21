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
ca192cfb773915c9d8113352b8646d3ce9329424
```

Upstream commit date:

```text
2026-05-20T09:22:28-07:00
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

Targeted MVP-0 skeleton verification:

```text
python -m pytest -o addopts="" --basetemp .pytest-tmp tests\enterprise
```

Result:

```text
9 passed
```

Environment notes:

1. Platform: Windows.
2. Python: system `python`, observed as Python 3.14.4 during pytest output.
3. No `.venv`, `venv`, or shared Hermes venv was present in this checkout.
4. The repo's default pytest addopts require plugins that were not installed in
   the system Python environment, so the targeted run disabled addopts.
5. The default pytest temp root under AppData was inaccessible on this machine,
   so the targeted run used workspace-local `--basetemp .pytest-tmp`.

Before the first runtime authority patch, also record:

1. Python executable path.
2. Full targeted tests around the touched Hermes authority seam.
3. Enterprise-off smoke result for that authority seam.
4. Existing failures before the runtime patch, if any.
5. Whether the failure is environment-related or repository-related.

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

The current compatibility risk is limited to package discovery and config
default loading. The first meaningful runtime compatibility risk appears when a
core adapter hook is added around tool execution, provider egress, memory,
plugin admission, gateway identity, or cron authority.
