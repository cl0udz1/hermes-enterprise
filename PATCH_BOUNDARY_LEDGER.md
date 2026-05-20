# Patch Boundary Ledger

This ledger records every enterprise fork change that touches mature Hermes core
runtime files.

The goal is simple: keep Hermes upstream-shaped. Add enterprise modules first,
use adapter hooks second, and patch core only where a real enforcement boundary
cannot be controlled any other way.

## Current Status

No enterprise runtime authority patches have been made yet.

The MVP-0 skeleton branch adds enterprise package discovery, default config, and
new enterprise modules/tests. It does not patch tool execution, provider egress,
memory, gateway, plugin admission, or cron authority.

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

None yet.

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
