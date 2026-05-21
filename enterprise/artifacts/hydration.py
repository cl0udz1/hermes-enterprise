"""Context hydration boundary for enterprise artifacts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from enterprise.artifacts.vault import ArtifactVault
from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import (
    ArtifactVaultRecord,
    AuditEvent,
    AuditEventType,
    ContextHydrationRequest,
    HydrationView,
    stable_hash,
)
from enterprise.mode import EnterpriseMode
from enterprise.triage.detectors import SECRET_PATTERNS


@dataclass(frozen=True)
class HydrationResult:
    """Decision and payload returned by the hydration boundary."""

    allowed: bool
    request: ContextHydrationRequest
    artifact: ArtifactVaultRecord | None = None
    content: str = ""
    hydrated_view: HydrationView | None = None
    budget_bytes: int = 0
    content_truncated: bool = False
    audit_event_id: str = ""
    reason: str = ""


def hydrate_context(
    request: ContextHydrationRequest,
    *,
    vault: ArtifactVault | None = None,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> HydrationResult:
    """Hydrate one permitted view of a vault artifact."""
    resolved_vault = vault or ArtifactVault()
    record = resolved_vault.get_record(request.artifact_id)
    enterprise_cfg = enterprise_config_from_root(root_config)
    mode = EnterpriseMode.from_config(root_config)
    hydration_cfg = enterprise_cfg.get("hydration", {})
    if not isinstance(hydration_cfg, Mapping):
        hydration_cfg = {}

    if record is None:
        result = HydrationResult(
            allowed=False,
            request=request,
            hydrated_view=request.view,
            budget_bytes=_budget_for(request.view, hydration_cfg),
            reason="Artifact is not present in the vault.",
        )
        return _with_audit(result, audit_store, mode)

    if not mode.is_enforcing or not bool(hydration_cfg.get("enabled", True)):
        content = _content_for_disabled_mode(request.view, record, resolved_vault)
        return HydrationResult(
            allowed=True,
            request=request,
            artifact=record,
            content=content,
            hydrated_view=request.view,
            budget_bytes=len(content.encode("utf-8")),
            reason="Enterprise hydration policy is disabled.",
        )

    budget = _budget_for(request.view, hydration_cfg)
    denied_reason = _deny_reason(request, record, hydration_cfg, budget)
    if denied_reason:
        result = HydrationResult(
            allowed=False,
            request=request,
            artifact=record,
            hydrated_view=request.view,
            budget_bytes=budget,
            reason=denied_reason,
        )
        return _with_audit(result, audit_store, mode)

    content, truncated = _hydrate_allowed_content(
        request.view,
        record,
        resolved_vault,
        budget,
    )
    result = HydrationResult(
        allowed=True,
        request=request,
        artifact=record,
        content=content,
        hydrated_view=request.view,
        budget_bytes=budget,
        content_truncated=truncated,
        reason="Hydration view allowed by route and data-class policy.",
    )
    return _with_audit(result, audit_store, mode)


def _deny_reason(
    request: ContextHydrationRequest,
    record: ArtifactVaultRecord,
    hydration_cfg: Mapping[str, Any],
    budget: int,
) -> str:
    route = request.route.strip()
    denied_routes = set(_as_tuple(hydration_cfg.get("denied_routes")))
    if route in denied_routes:
        return f"Hydration route is denied: {route}"
    if request.view is not HydrationView.FULL:
        return ""
    allowed_full_routes = set(_as_tuple(hydration_cfg.get("full_allowed_routes")))
    if route not in allowed_full_routes:
        return f"Full hydration is not allowed for route: {route}"
    secret_classes = set(_as_tuple(hydration_cfg.get("secret_data_classes")))
    if record.data_class in secret_classes and not bool(hydration_cfg.get("allow_secret_full", False)):
        return f"Full hydration is not allowed for secret-bearing data class: {record.data_class}"
    size = int(record.metadata.get("content_size_bytes", 0) or 0)
    if size and size > budget:
        return f"Full hydration exceeds route budget: {size} bytes > {budget} bytes"
    return ""


def _hydrate_allowed_content(
    view: HydrationView,
    record: ArtifactVaultRecord,
    vault: ArtifactVault,
    budget: int,
) -> tuple[str, bool]:
    if view is HydrationView.METADATA:
        return "", False
    if view is HydrationView.SUMMARY:
        summary = str(record.metadata.get("summary") or record.redacted_preview)
        return _truncate_bytes(_redact(summary), budget)
    content = vault.read_content(record.artifact_id) or ""
    if view is HydrationView.REDACTED:
        return _truncate_bytes(_redact(content), budget)
    if view is HydrationView.FULL:
        return _truncate_bytes(content, budget)
    return "", False


def _content_for_disabled_mode(
    view: HydrationView,
    record: ArtifactVaultRecord,
    vault: ArtifactVault,
) -> str:
    if view is HydrationView.METADATA:
        return ""
    if view is HydrationView.SUMMARY:
        return str(record.metadata.get("summary") or record.redacted_preview)
    if view is HydrationView.REDACTED:
        return _redact(vault.read_content(record.artifact_id) or "")
    return vault.read_content(record.artifact_id) or ""


def _with_audit(
    result: HydrationResult,
    audit_store: AuditStore | None,
    mode: EnterpriseMode,
) -> HydrationResult:
    if not mode.is_enforcing:
        return result
    store = audit_store or AuditStore()
    event = _audit_event_for(result)
    sequence = store.append_event(event)
    return HydrationResult(
        allowed=result.allowed,
        request=result.request,
        artifact=result.artifact,
        content=result.content,
        hydrated_view=result.hydrated_view,
        budget_bytes=result.budget_bytes,
        content_truncated=result.content_truncated,
        audit_event_id=event.event_id if sequence else "",
        reason=result.reason,
    )


def _audit_event_for(result: HydrationResult) -> AuditEvent:
    created_at = datetime.now(timezone.utc).isoformat()
    artifact = result.artifact
    artifact_id = result.request.artifact_id
    data_class = artifact.data_class if artifact else ""
    content_sha256 = artifact.content_sha256 if artifact else ""
    event_id = stable_hash(
        {
            "event_type": AuditEventType.HYDRATION_DECISION.value,
            "request_id": result.request.request_id,
            "artifact_id": artifact_id,
            "route": result.request.route,
            "view": result.request.view.value,
            "allowed": result.allowed,
            "created_at": created_at,
        }
    )[:32]
    preview = artifact.redacted_preview if artifact else f"missing artifact {artifact_id}"
    return AuditEvent(
        event_id=event_id,
        event_type=AuditEventType.HYDRATION_DECISION,
        subject_id=result.request.subject_id,
        action_id=artifact_id,
        decision_id=result.request.request_id,
        redacted_preview=preview,
        raw_sha256=content_sha256,
        created_at=created_at,
        metadata={
            "request_id": result.request.request_id,
            "artifact_id": artifact_id,
            "route": result.request.route,
            "requested_view": result.request.view.value,
            "hydrated_view": result.hydrated_view.value if result.hydrated_view else "",
            "budget_bytes": result.budget_bytes,
            "data_class": data_class,
            "allowed": result.allowed,
            "reason": result.reason,
            "content_sha256": content_sha256,
            "content_truncated": result.content_truncated,
        },
    )


def _budget_for(view: HydrationView, hydration_cfg: Mapping[str, Any]) -> int:
    budgets = hydration_cfg.get("view_budgets", {})
    if not isinstance(budgets, Mapping):
        budgets = {}
    default = int(hydration_cfg.get("default_budget_bytes", 4096) or 4096)
    value = budgets.get(view.value, default)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        return tuple(str(item) for item in value if str(item))
    return ()


def _redact(value: str) -> str:
    redacted = value
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted


def _truncate_bytes(value: str, budget: int) -> tuple[str, bool]:
    if budget <= 0:
        return "", bool(value)
    encoded = value.encode("utf-8")
    if len(encoded) <= budget:
        return value, False
    truncated = encoded[:budget].decode("utf-8", errors="ignore")
    return f"{truncated}...", True
