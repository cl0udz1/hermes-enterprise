"""Enterprise admission checks for plugins and MCP tool surfaces."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import (
    AuditEvent,
    AuditEventType,
    AuthorityAdmissionDecision,
    DecisionOutcome,
    stable_hash,
)
from enterprise.mode import EnterpriseMode


SURFACE_PLUGIN = "plugin"
SURFACE_PLUGIN_TOOL = "plugin_tool"
SURFACE_MCP_SERVER = "mcp_server"
SURFACE_MCP_TOOL = "mcp_tool"


def evaluate_plugin_manifest(
    manifest: Any,
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> AuthorityAdmissionDecision:
    """Decide whether a plugin manifest may be imported."""

    resolved_config = _resolve_root_config(root_config)
    if not _admission_enforcing(resolved_config):
        return _decision(
            surface=SURFACE_PLUGIN,
            resource=_plugin_resource(manifest),
            outcome=DecisionOutcome.ALLOW,
            reason="enterprise admission disabled",
        )

    admission_cfg = _admission_config(resolved_config)
    key = str(getattr(manifest, "key", "") or getattr(manifest, "name", ""))
    name = str(getattr(manifest, "name", "") or key)
    source = str(getattr(manifest, "source", "") or "")
    trusted_sources = _as_set(admission_cfg.get("trusted_plugin_sources"))
    allowed_plugins = _as_set(admission_cfg.get("allowed_plugins"))
    trust_entry = _plugin_trust_entry(admission_cfg, key, name)

    if source in trusted_sources:
        return _decision(
            surface=SURFACE_PLUGIN,
            resource=_plugin_resource(manifest),
            outcome=DecisionOutcome.ALLOW,
            reason=f"trusted plugin source: {source}",
            trust_source=f"source:{source}",
            metadata={"plugin_key": key, "plugin_name": name, "source": source},
            root_config=resolved_config,
            audit_store=audit_store,
        )
    if key in allowed_plugins or name in allowed_plugins:
        return _decision(
            surface=SURFACE_PLUGIN,
            resource=_plugin_resource(manifest),
            outcome=DecisionOutcome.ALLOW,
            reason="plugin allowed by enterprise.plugin_mcp_admission.allowed_plugins",
            trust_source="enterprise.allowed_plugins",
            metadata={"plugin_key": key, "plugin_name": name, "source": source},
            root_config=resolved_config,
            audit_store=audit_store,
        )
    if _trust_approved(trust_entry):
        return _decision(
            surface=SURFACE_PLUGIN,
            resource=_plugin_resource(manifest),
            outcome=DecisionOutcome.ALLOW,
            reason="plugin approved by enterprise trust metadata",
            trust_source="enterprise.plugin_trust",
            metadata={"plugin_key": key, "plugin_name": name, "source": source},
            root_config=resolved_config,
            audit_store=audit_store,
        )

    return _decision(
        surface=SURFACE_PLUGIN,
        resource=_plugin_resource(manifest),
        outcome=DecisionOutcome.QUARANTINE,
        reason="plugin is not approved for enterprise mode",
        trust_source="missing",
        metadata={"plugin_key": key, "plugin_name": name, "source": source},
        root_config=resolved_config,
        audit_store=audit_store,
    )


def evaluate_plugin_tool(
    manifest: Any,
    tool_name: str,
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> AuthorityAdmissionDecision:
    """Decide whether a plugin may register one tool."""

    resolved_config = _resolve_root_config(root_config)
    if not _admission_enforcing(resolved_config):
        return _decision(
            surface=SURFACE_PLUGIN_TOOL,
            resource=f"{_plugin_resource(manifest)}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="enterprise admission disabled",
        )

    plugin_decision = evaluate_plugin_manifest(
        manifest,
        root_config=resolved_config,
        audit_store=audit_store,
    )
    if plugin_decision.outcome is not DecisionOutcome.ALLOW:
        return _decision(
            surface=SURFACE_PLUGIN_TOOL,
            resource=f"{_plugin_resource(manifest)}:{tool_name}",
            outcome=DecisionOutcome.QUARANTINE,
            reason="plugin manifest is not admitted",
            trust_source=plugin_decision.trust_source,
            metadata={
                "plugin_key": str(getattr(manifest, "key", "") or getattr(manifest, "name", "")),
                "plugin_name": str(getattr(manifest, "name", "") or ""),
                "tool_name": tool_name,
            },
            root_config=resolved_config,
            audit_store=audit_store,
        )

    admission_cfg = _admission_config(resolved_config)
    if not bool(admission_cfg.get("require_declared_plugin_tools", True)):
        return _decision(
            surface=SURFACE_PLUGIN_TOOL,
            resource=f"{_plugin_resource(manifest)}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="declared plugin tool requirement disabled",
            root_config=resolved_config,
            audit_store=audit_store,
        )

    key = str(getattr(manifest, "key", "") or getattr(manifest, "name", ""))
    name = str(getattr(manifest, "name", "") or key)
    trust_entry = _plugin_trust_entry(admission_cfg, key, name)
    if _trust_allow_all_tools(trust_entry):
        return _decision(
            surface=SURFACE_PLUGIN_TOOL,
            resource=f"{_plugin_resource(manifest)}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="plugin trust metadata allows all tools",
            trust_source="enterprise.plugin_trust",
            metadata={"plugin_key": key, "plugin_name": name, "tool_name": tool_name},
            root_config=resolved_config,
            audit_store=audit_store,
        )

    declared_tools = _as_set(getattr(manifest, "provides_tools", []))
    declared_tools.update(_trust_declared_tools(trust_entry))
    if tool_name in declared_tools:
        return _decision(
            surface=SURFACE_PLUGIN_TOOL,
            resource=f"{_plugin_resource(manifest)}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="plugin tool declared in manifest or trust metadata",
            trust_source="manifest.provides_tools",
            metadata={"plugin_key": key, "plugin_name": name, "tool_name": tool_name},
            root_config=resolved_config,
            audit_store=audit_store,
        )

    return _decision(
        surface=SURFACE_PLUGIN_TOOL,
        resource=f"{_plugin_resource(manifest)}:{tool_name}",
        outcome=DecisionOutcome.QUARANTINE,
        reason="plugin tool is not declared in enterprise mode",
        trust_source="missing",
        metadata={
            "plugin_key": key,
            "plugin_name": name,
            "tool_name": tool_name,
            "declared_tools": sorted(declared_tools),
        },
        root_config=resolved_config,
        audit_store=audit_store,
    )


def evaluate_mcp_server(
    server_name: str,
    server_config: Mapping[str, Any] | None,
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> AuthorityAdmissionDecision:
    """Decide whether an MCP server may be started."""

    resolved_config = _resolve_root_config(root_config)
    if not _admission_enforcing(resolved_config):
        return _decision(
            surface=SURFACE_MCP_SERVER,
            resource=str(server_name),
            outcome=DecisionOutcome.ALLOW,
            reason="enterprise admission disabled",
        )

    admission_cfg = _admission_config(resolved_config)
    allowed_servers = _as_set(admission_cfg.get("allowed_mcp_servers"))
    trust_entry = _mcp_trust_entry(admission_cfg, str(server_name), server_config)
    if str(server_name) in allowed_servers:
        return _decision(
            surface=SURFACE_MCP_SERVER,
            resource=str(server_name),
            outcome=DecisionOutcome.ALLOW,
            reason="MCP server allowed by enterprise.plugin_mcp_admission.allowed_mcp_servers",
            trust_source="enterprise.allowed_mcp_servers",
            metadata={"server_name": str(server_name)},
            root_config=resolved_config,
            audit_store=audit_store,
        )
    if _trust_approved(trust_entry):
        return _decision(
            surface=SURFACE_MCP_SERVER,
            resource=str(server_name),
            outcome=DecisionOutcome.ALLOW,
            reason="MCP server approved by enterprise trust metadata",
            trust_source="enterprise.mcp_server_trust",
            metadata={"server_name": str(server_name)},
            root_config=resolved_config,
            audit_store=audit_store,
        )

    return _decision(
        surface=SURFACE_MCP_SERVER,
        resource=str(server_name),
        outcome=DecisionOutcome.QUARANTINE,
        reason="MCP server is not approved for enterprise mode",
        trust_source="missing",
        metadata={"server_name": str(server_name)},
        root_config=resolved_config,
        audit_store=audit_store,
    )


def evaluate_mcp_tool(
    server_name: str,
    tool_name: str,
    server_config: Mapping[str, Any] | None,
    *,
    prefixed_tool_name: str = "",
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> AuthorityAdmissionDecision:
    """Decide whether one discovered MCP tool may be registered."""

    resolved_config = _resolve_root_config(root_config)
    if not _admission_enforcing(resolved_config):
        return _decision(
            surface=SURFACE_MCP_TOOL,
            resource=f"{server_name}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="enterprise admission disabled",
        )

    admission_cfg = _admission_config(resolved_config)
    server_decision = evaluate_mcp_server(
        server_name,
        server_config,
        root_config=resolved_config,
        audit_store=audit_store,
    )
    if server_decision.outcome is not DecisionOutcome.ALLOW:
        return _decision(
            surface=SURFACE_MCP_TOOL,
            resource=f"{server_name}:{tool_name}",
            outcome=DecisionOutcome.QUARANTINE,
            reason="MCP server is not admitted",
            trust_source=server_decision.trust_source,
            metadata={"server_name": str(server_name), "tool_name": str(tool_name)},
            root_config=resolved_config,
            audit_store=audit_store,
        )

    if not bool(admission_cfg.get("require_declared_mcp_tools", True)):
        return _decision(
            surface=SURFACE_MCP_TOOL,
            resource=f"{server_name}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="declared MCP tool requirement disabled",
            root_config=resolved_config,
            audit_store=audit_store,
        )

    trust_entry = _mcp_trust_entry(admission_cfg, str(server_name), server_config)
    if _trust_allow_all_tools(trust_entry):
        return _decision(
            surface=SURFACE_MCP_TOOL,
            resource=f"{server_name}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="MCP trust metadata allows all tools",
            trust_source="enterprise.mcp_server_trust",
            metadata={"server_name": str(server_name), "tool_name": str(tool_name)},
            root_config=resolved_config,
            audit_store=audit_store,
        )

    declared_tools = _trust_declared_tools(trust_entry)
    if bool(admission_cfg.get("allow_mcp_tools_include_as_manifest", True)):
        declared_tools.update(
            _as_set(
                _mapping(server_config)
                .get("tools", {})
                .get("include", [])
                if isinstance(_mapping(server_config).get("tools", {}), Mapping)
                else []
            )
        )

    candidates = {str(tool_name)}
    if prefixed_tool_name:
        candidates.add(str(prefixed_tool_name))
    if candidates & declared_tools:
        return _decision(
            surface=SURFACE_MCP_TOOL,
            resource=f"{server_name}:{tool_name}",
            outcome=DecisionOutcome.ALLOW,
            reason="MCP tool declared in trust metadata",
            trust_source="enterprise.mcp_server_trust",
            metadata={
                "server_name": str(server_name),
                "tool_name": str(tool_name),
                "prefixed_tool_name": str(prefixed_tool_name),
            },
            root_config=resolved_config,
            audit_store=audit_store,
        )

    return _decision(
        surface=SURFACE_MCP_TOOL,
        resource=f"{server_name}:{tool_name}",
        outcome=DecisionOutcome.QUARANTINE,
        reason="MCP tool is not declared in enterprise mode",
        trust_source="missing",
        metadata={
            "server_name": str(server_name),
            "tool_name": str(tool_name),
            "prefixed_tool_name": str(prefixed_tool_name),
            "declared_tools": sorted(declared_tools),
        },
        root_config=resolved_config,
        audit_store=audit_store,
    )


def _resolve_root_config(root_config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if root_config is not None:
        return root_config
    from hermes_cli.config import load_config

    return load_config()


def _admission_enforcing(root_config: Mapping[str, Any]) -> bool:
    if not EnterpriseMode.from_config(root_config).is_enforcing:
        return False
    admission_cfg = _admission_config(root_config)
    return admission_cfg.get("enabled") is not False


def _admission_config(root_config: Mapping[str, Any]) -> Mapping[str, Any]:
    enterprise_cfg = enterprise_config_from_root(root_config)
    admission_cfg = enterprise_cfg.get("plugin_mcp_admission", {})
    if isinstance(admission_cfg, Mapping):
        return admission_cfg
    return {}


def _decision(
    *,
    surface: str,
    resource: str,
    outcome: DecisionOutcome,
    reason: str,
    trust_source: str = "",
    metadata: Mapping[str, Any] | None = None,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> AuthorityAdmissionDecision:
    metadata_dict = {str(key): _json_safe(value) for key, value in (metadata or {}).items()}
    decision_id = stable_hash(
        {
            "surface": surface,
            "resource": resource,
            "outcome": outcome.value,
            "reason": reason,
            "trust_source": trust_source,
            "metadata": metadata_dict,
        }
    )[:32]
    audit_event_ids: list[str] = []
    if root_config is not None and _should_audit(root_config, outcome):
        try:
            audit_event_ids = list(
                _append_admission_event(
                    audit_store or AuditStore(),
                    decision_id=decision_id,
                    surface=surface,
                    resource=resource,
                    outcome=outcome,
                    reason=reason,
                    trust_source=trust_source,
                    metadata=metadata_dict,
                )
            )
        except Exception:
            audit_event_ids = []
    return AuthorityAdmissionDecision(
        decision_id=decision_id,
        surface=surface,
        resource=resource,
        outcome=outcome,
        reason=reason,
        trust_source=trust_source,
        metadata=metadata_dict,
        audit_event_ids=audit_event_ids,
    )


def _should_audit(root_config: Mapping[str, Any], outcome: DecisionOutcome) -> bool:
    admission_cfg = _admission_config(root_config)
    return outcome is not DecisionOutcome.ALLOW or bool(admission_cfg.get("audit_all_decisions", False))


def _append_admission_event(
    audit_store: AuditStore,
    *,
    decision_id: str,
    surface: str,
    resource: str,
    outcome: DecisionOutcome,
    reason: str,
    trust_source: str,
    metadata: dict[str, Any],
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    raw_sha256 = stable_hash(
        {
            "surface": surface,
            "resource": resource,
            "outcome": outcome.value,
            "reason": reason,
            "metadata": metadata,
        }
    )
    event_id = stable_hash(
        {
            "event_type": AuditEventType.AUTHORITY_ADMISSION_DECISION.value,
            "decision_id": decision_id,
            "surface": surface,
            "resource": resource,
            "created_at": created_at,
        }
    )[:32]
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.AUTHORITY_ADMISSION_DECISION,
            subject_id="plugin-mcp-admission",
            action_id=f"{surface}:{resource}",
            decision_id=decision_id,
            redacted_preview=f"{outcome.value} {surface} {resource}: {reason}",
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata={
                "surface": surface,
                "resource": resource,
                "outcome": outcome.value,
                "reason": reason,
                "trust_source": trust_source,
                **metadata,
            },
        )
    )
    return (event_id,)


def _plugin_resource(manifest: Any) -> str:
    key = str(getattr(manifest, "key", "") or "")
    name = str(getattr(manifest, "name", "") or "")
    return key or name or "unknown-plugin"


def _plugin_trust_entry(admission_cfg: Mapping[str, Any], key: str, name: str) -> Mapping[str, Any]:
    trust = admission_cfg.get("plugin_trust", {})
    if not isinstance(trust, Mapping):
        return {}
    value = trust.get(key)
    if value is None:
        value = trust.get(name)
    return value if isinstance(value, Mapping) else {}


def _mcp_trust_entry(
    admission_cfg: Mapping[str, Any],
    server_name: str,
    server_config: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    server_mapping = _mapping(server_config)
    local_entry = server_mapping.get("enterprise_trust", {})
    if isinstance(local_entry, Mapping) and local_entry:
        return local_entry
    trust = admission_cfg.get("mcp_server_trust", {})
    if isinstance(trust, Mapping):
        entry = trust.get(server_name)
        if isinstance(entry, Mapping):
            return entry
    return {}


def _trust_approved(entry: Mapping[str, Any]) -> bool:
    return bool(entry.get("approved", False))


def _trust_allow_all_tools(entry: Mapping[str, Any]) -> bool:
    return bool(entry.get("allow_all_tools", False))


def _trust_declared_tools(entry: Mapping[str, Any]) -> set[str]:
    return _as_set(entry.get("tools", []))


def _mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return {str(item) for item in value}
    return set()


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return [_json_safe(item) for item in value]
    return str(value)
