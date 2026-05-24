# Enterprise MVP-1 Prep

This note prepares the repository for MVP-1 and records the first runtime slice
once it starts.

## GitHub Operating Model

Use GitHub as the coordination layer:

1. Open work as issues first.
2. Attach every MVP-1 issue to the `MVP-1 Enterprise Governance` milestone.
3. Use labels to show the security boundary being touched.
4. Open PRs against `enterprise/main`.
5. Keep `main` clean as the upstream mirror branch.
6. Run `python scripts/enterprise_mvp0_gate.py` before merging.

## Labels To Use

| Label | Meaning |
|---|---|
| `enterprise-mvp1` | MVP-1 implementation work. |
| `security-boundary` | A control that enforces or protects an authority boundary. |
| `upstream-compat` | Work related to staying compatible with upstream Hermes. |
| `release-gate` | Tests, CI, or readiness checks that block release. |
| `provider-egress` | Provider/model request governance. |
| `memory-governance` | Memory read/write policy and quarantine. |
| `plugin-mcp` | Plugin and MCP admission controls. |
| `gateway-identity` | Gateway user/channel identity binding. |
| `cron-governance` | Scheduled work owner, intent, expiry, and policy context. |
| `access-broker` | Grants, approvals, expiry, and revocation. |
| `secret-broker` | Credential issuance and secret access controls. |

## Recommended MVP-1 Order

1. Provider egress wrapper, including streaming policy.
2. Memory write/read governance.
3. Plugin and MCP admission policy.
4. Gateway identity binding and assignment policy.
5. Cron owner, intent, expiry, and policy context.
6. Access Broker and approval lifecycle.
7. Secret Broker and short-lived credential issuance.

## First MVP-1 Issue

Start with provider egress governance because it is the highest leverage gap:
tool outputs, hydrated artifacts, memory context, and user prompts all converge
before external model calls.

The first MVP-1 PR should still be small:

1. Add provider-egress contracts and fake-provider tests.
2. Do not wrap every provider path yet.
3. Prove synthetic secrets do not reach a fake non-streaming provider payload.
4. Document streaming as blocked, buffered, or not yet supported.

## First MVP-1 Slice

The first implementation slice is the Chat Completions provider-egress guard:

1. `agent/transports/chat_completions.py` applies the enterprise provider egress
   guard after both provider-profile and legacy payload assembly.
2. `enterprise/provider_egress.py` recursively sanitizes outbound provider
   payload strings with deterministic secret and prompt-control detectors.
3. Enterprise-off mode returns the original provider payload unchanged.
4. Enterprise-on mode emits a local audit event only when the provider payload
   changes.
5. Streaming posture is `request_payload_only`: prompt/request payloads are
   sanitized before Chat Completions streaming is enabled, but streamed provider
   responses are not buffered or scanned in this slice.

## Second MVP-1 Slice

The second implementation slice is Memory Manager governance:

1. `agent/memory_manager.py` applies the enterprise memory-governance guard to
   prefetch queries, recall results, queued prefetches, completed-turn sync,
   session-end extraction, pre-compression extraction, explicit memory writes,
   memory-provider tool calls/results, and delegation observations.
2. `enterprise/memory_governance.py` recursively sanitizes memory-bound payloads
   with deterministic secret and prompt-control detectors.
3. Enterprise-off mode returns memory payloads unchanged and does not audit.
4. Enterprise-on mode emits a local audit event only when a memory-bound payload
   changes.
5. This is a redaction boundary, not full tenant-scoped memory isolation,
   provider-specific ACLs, durable quarantine workflow, or semantic memory
   classification.

## Third MVP-1 Slice

The third implementation slice is Plugin and MCP admission:

1. `hermes_cli/plugins.py` checks enterprise admission before importing an
   enabled plugin and before accepting plugin-provided tool registrations.
2. `tools/mcp_tool.py` checks enterprise admission before starting new MCP
   servers and before registering each discovered MCP tool or MCP utility tool.
3. `enterprise/admission.py` defines deterministic decisions for plugin
   manifests, plugin tools, MCP servers, and MCP tools, with bundled plugins
   trusted by source and user/project/entrypoint plugins requiring explicit
   trust or allow-list configuration in enterprise mode.
4. Enterprise-off mode preserves normal Hermes plugin and MCP behavior.
5. Enterprise-on mode quarantines unapproved plugin imports, unmanifested
   plugin tools, unapproved MCP servers, and undeclared MCP tools before they
   become model-visible tools.
6. This is an admission boundary, not full plugin sandboxing, code-signature
   verification, dynamic revocation of already-running MCP servers, or
   provider-specific memory/model plugin governance.
