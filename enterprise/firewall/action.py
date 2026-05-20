"""Pre-execution action firewall for enterprise tool calls."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import (
    AuditEvent,
    AuditEventType,
    DecisionOutcome,
    RiskTier,
    RuntimeTriageDecision,
    stable_hash,
)
from enterprise.manifests import load_core_tool_manifest
from enterprise.mode import EnterpriseMode
from enterprise.sandbox import SandboxDecision, evaluate_sandbox
from enterprise.triage import RuntimeTriageEngine, TriageRequest


@dataclass(frozen=True)
class ActionFirewallDecision:
    """Result of pre-execution enterprise action evaluation."""

    allows_execution: bool
    tool_result: str = ""
    triage_decision: RuntimeTriageDecision | None = None
    action_hash: str = ""
    audit_event_ids: tuple[str, ...] = ()

    @classmethod
    def allow(
        cls,
        *,
        triage_decision: RuntimeTriageDecision | None = None,
        action_hash: str = "",
        audit_event_ids: tuple[str, ...] = (),
    ) -> "ActionFirewallDecision":
        return cls(
            allows_execution=True,
            triage_decision=triage_decision,
            action_hash=action_hash,
            audit_event_ids=audit_event_ids,
        )

    @classmethod
    def block(
        cls,
        tool_result: str,
        *,
        triage_decision: RuntimeTriageDecision | None = None,
        action_hash: str = "",
        audit_event_ids: tuple[str, ...] = (),
    ) -> "ActionFirewallDecision":
        return cls(
            allows_execution=False,
            tool_result=tool_result,
            triage_decision=triage_decision,
            action_hash=action_hash,
            audit_event_ids=audit_event_ids,
        )


def evaluate_tool_call(
    tool_name: str,
    tool_args: Mapping[str, Any] | None,
    *,
    agent: Any = None,
    task_id: str = "",
    tool_call_id: str = "",
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> ActionFirewallDecision:
    """Evaluate a proposed tool call before any side effect can run.

    Enterprise mode is disabled by default. In that mode this function returns
    immediately and does not touch audit storage, manifests, or the filesystem.
    """

    resolved_config = _resolve_root_config(root_config, agent)
    mode = EnterpriseMode.from_config(resolved_config)
    if not mode.is_enforcing:
        return ActionFirewallDecision.allow()

    args = _json_safe(dict(tool_args or {}))
    subject_id = _subject_id(agent)
    manifest_index = load_core_tool_manifest()
    capability = manifest_index.get(tool_name)
    enterprise_cfg = enterprise_config_from_root(resolved_config)
    runtime_cfg = enterprise_cfg.get("runtime", {})
    if not isinstance(runtime_cfg, Mapping):
        runtime_cfg = {}
    sandbox_cfg = enterprise_cfg.get("sandbox", {})
    if not isinstance(sandbox_cfg, Mapping):
        sandbox_cfg = {}
    sandbox_decision = evaluate_sandbox(
        tool_name,
        args,
        capability,
        enforce_manifests=bool(sandbox_cfg.get("enforce_manifests", True)),
    )
    requested_side_effects = (
        sandbox_decision.observation.observed_side_effects
        or tuple(capability.side_effects) if capability else ()
    )
    action_hash = stable_hash(
        {
            "subject_id": subject_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "tool_args": args,
            "requested_side_effects": list(requested_side_effects),
        }
    )

    triage = RuntimeTriageEngine(
        manifest_index=manifest_index,
        allowed_roots=_as_tuple(runtime_cfg.get("allowed_roots")),
        denied_roots=_as_tuple(runtime_cfg.get("denied_roots")),
        allowed_hosts=_as_tuple(runtime_cfg.get("allowed_hosts")),
        denied_hosts=_as_tuple(runtime_cfg.get("denied_hosts")),
        allow_private_network=bool(runtime_cfg.get("allow_private_network", False)),
    )
    triage_decision = triage.evaluate(
        TriageRequest(
            subject_id=subject_id,
            tool_name=tool_name,
            tool_args=args,
            action_hash=action_hash,
            requested_side_effects=requested_side_effects,
            resource_paths=sandbox_decision.observation.resource_paths,
            network_destinations=sandbox_decision.observation.network_destinations,
            data_classes=tuple(capability.data_classes) if capability else (),
            extra_findings=sandbox_decision.findings,
        )
    )

    try:
        audit_event_ids = _append_audit_events(
            audit_store or AuditStore(),
            subject_id=subject_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            tool_args=args,
            action_hash=action_hash,
            triage_decision=triage_decision,
            sandbox_decision=sandbox_decision,
        )
    except Exception as exc:
        if mode.fail_closed_high_risk and triage_decision.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}:
            return ActionFirewallDecision.block(
                _blocked_tool_result(
                    tool_name=tool_name,
                    action_hash=action_hash,
                    triage_decision=triage_decision,
                    audit_error=str(exc),
                ),
                triage_decision=triage_decision,
                action_hash=action_hash,
            )
        audit_event_ids = ()

    if triage_decision.outcome is DecisionOutcome.ALLOW:
        return ActionFirewallDecision.allow(
            triage_decision=triage_decision,
            action_hash=action_hash,
            audit_event_ids=audit_event_ids,
        )

    return ActionFirewallDecision.block(
        _blocked_tool_result(
            tool_name=tool_name,
            action_hash=action_hash,
            triage_decision=triage_decision,
        ),
        triage_decision=triage_decision,
        action_hash=action_hash,
        audit_event_ids=audit_event_ids,
    )


def _resolve_root_config(root_config: Mapping[str, Any] | None, agent: Any) -> Mapping[str, Any]:
    if root_config is not None:
        return root_config
    agent_config = _root_config_from_agent(agent)
    if agent_config is not None:
        return agent_config
    return _cached_root_config()


@lru_cache(maxsize=1)
def _cached_root_config() -> Mapping[str, Any]:
    # Keep the enterprise-disabled hot path from re-reading config for every tool.
    from hermes_cli.config import load_config

    return load_config()


def _root_config_from_agent(agent: Any) -> Mapping[str, Any] | None:
    if agent is None:
        return None
    for attr in (
        "enterprise_root_config",
        "_enterprise_root_config",
        "root_config",
        "_root_config",
        "config",
        "_config",
    ):
        value = getattr(agent, attr, None)
        if isinstance(value, Mapping):
            return value
    return None


def _subject_id(agent: Any) -> str:
    if agent is None:
        return "local-agent"
    for attr in ("user_id", "subject_id", "session_id"):
        value = getattr(agent, attr, None)
        if value:
            return str(value)
    return "local-agent"


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        return tuple(str(item) for item in value if str(item))
    return ()


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return [_json_safe(item) for item in value]
    return str(value)


def _append_audit_events(
    audit_store: AuditStore,
    *,
    subject_id: str,
    task_id: str,
    tool_call_id: str,
    tool_name: str,
    tool_args: Mapping[str, Any],
    action_hash: str,
    triage_decision: RuntimeTriageDecision,
    sandbox_decision: SandboxDecision,
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    raw_sha256 = stable_hash({"tool_name": tool_name, "tool_args": tool_args})
    preview = _redacted_preview(tool_name, tool_args)
    event_ids = []
    for event_type in (AuditEventType.ACTION_PROPOSED, AuditEventType.POLICY_DECISION):
        event_id = stable_hash(
            {
                "event_type": event_type.value,
                "action_hash": action_hash,
                "decision_id": triage_decision.decision_id,
                "created_at": created_at,
            }
        )[:32]
        audit_store.append_event(
            AuditEvent(
                event_id=event_id,
                event_type=event_type,
                subject_id=subject_id,
                action_id=action_hash,
                decision_id=triage_decision.decision_id,
                redacted_preview=preview,
                raw_sha256=raw_sha256,
                created_at=created_at,
                metadata={
                    "tool_name": tool_name,
                    "task_id": task_id,
                    "tool_call_id": tool_call_id,
                    "outcome": triage_decision.outcome.value,
                    "risk_tier": triage_decision.risk_tier.value,
                    "detectors": list(triage_decision.detectors),
                    "latency_ms": triage_decision.latency_ms,
                },
            )
        )
        event_ids.append(event_id)
    if sandbox_decision.findings:
        event_id = stable_hash(
            {
                "event_type": AuditEventType.SANDBOX_VIOLATION.value,
                "action_hash": action_hash,
                "decision_id": triage_decision.decision_id,
                "created_at": created_at,
            }
        )[:32]
        audit_store.append_event(
            AuditEvent(
                event_id=event_id,
                event_type=AuditEventType.SANDBOX_VIOLATION,
                subject_id=subject_id,
                action_id=action_hash,
                decision_id=triage_decision.decision_id,
                redacted_preview=preview,
                raw_sha256=raw_sha256,
                created_at=created_at,
                metadata={
                    "tool_name": tool_name,
                    "task_id": task_id,
                    "tool_call_id": tool_call_id,
                    "outcome": triage_decision.outcome.value,
                    "sandbox_profile": sandbox_decision.observation.sandbox_profile,
                    "observed_side_effects": list(sandbox_decision.observation.observed_side_effects),
                    "resource_path_count": len(sandbox_decision.observation.resource_paths),
                    "network_destination_count": len(sandbox_decision.observation.network_destinations),
                    "env_key_count": sandbox_decision.observation.env_key_count,
                    "env_secret_like": sandbox_decision.observation.env_secret_like,
                    "detectors": [finding.detector for finding in sandbox_decision.findings],
                },
            )
        )
        event_ids.append(event_id)
    return tuple(event_ids)


def _redacted_preview(tool_name: str, tool_args: Mapping[str, Any]) -> str:
    keys = sorted(str(key) for key in tool_args.keys())
    if not keys:
        return f"{tool_name}()"
    return f"{tool_name}({', '.join(keys[:12])})"


def _blocked_tool_result(
    *,
    tool_name: str,
    action_hash: str,
    triage_decision: RuntimeTriageDecision,
    audit_error: str = "",
) -> str:
    if triage_decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
        error = "Enterprise action firewall requires approval before executing this tool."
    else:
        error = "Enterprise action firewall blocked tool execution."

    payload = {
        "error": error,
        "enterprise": {
            "tool_name": tool_name,
            "action_hash": action_hash,
            "decision_id": triage_decision.decision_id,
            "outcome": triage_decision.outcome.value,
            "risk_tier": triage_decision.risk_tier.value,
            "detectors": list(triage_decision.detectors),
            "reason": triage_decision.reason,
            "escalated": triage_decision.escalated,
            "latency_ms": triage_decision.latency_ms,
        },
    }
    if audit_error:
        payload["enterprise"]["audit_error"] = audit_error
    return json.dumps(payload, ensure_ascii=False)
