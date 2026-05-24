"""Memory read/write governance for enterprise model boundaries."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import (
    AuditEvent,
    AuditEventType,
    MemoryGovernanceDecision,
    stable_hash,
)
from enterprise.mode import EnterpriseMode
from enterprise.sanitization import sanitize_text_for_model_boundary


DEFAULT_ACTION = "redact"


def govern_memory_payload(
    payload: Any,
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
    route: str = "memory",
) -> tuple[Any, MemoryGovernanceDecision]:
    """Sanitize memory-bound payloads when enterprise mode is enforcing.

    Enterprise mode is disabled by default. In that mode the original payload
    object is returned unchanged and no audit storage is touched.
    """

    resolved_config = _resolve_root_config(root_config)
    mode = EnterpriseMode.from_config(resolved_config)
    enterprise_cfg = enterprise_config_from_root(resolved_config)
    memory_cfg = enterprise_cfg.get("memory_governance", {})
    if not isinstance(memory_cfg, Mapping):
        memory_cfg = {}
    action = str(memory_cfg.get("action") or DEFAULT_ACTION)

    if not mode.is_enforcing or memory_cfg.get("enabled") is False:
        return (
            payload,
            MemoryGovernanceDecision(
                decision_id="",
                route=route,
                changed=False,
                findings=[],
                raw_sha256="",
                sanitized_sha256="",
                action=action,
            ),
        )

    covered_routes = _as_set(memory_cfg.get("covered_routes"))
    route_key = route.split(":", 1)[0]
    if covered_routes and route_key not in covered_routes:
        return (
            payload,
            MemoryGovernanceDecision(
                decision_id="",
                route=route,
                changed=False,
                findings=[],
                raw_sha256="",
                sanitized_sha256="",
                action=action,
            ),
        )

    raw_sha256 = stable_hash(_json_safe(payload))
    sanitized, findings = _sanitize_payload(payload)
    unique_findings = list(dict.fromkeys(findings))
    sanitized_sha256 = stable_hash(_json_safe(sanitized))
    changed = sanitized != payload
    decision_id = stable_hash(
        {
            "route": route,
            "raw_sha256": raw_sha256,
            "sanitized_sha256": sanitized_sha256,
            "findings": unique_findings,
            "action": action,
        }
    )[:32]
    audit_event_ids: list[str] = []

    if changed:
        try:
            audit_event_ids = list(
                _append_memory_governance_event(
                    audit_store or AuditStore(),
                    decision_id=decision_id,
                    route=route,
                    raw_sha256=raw_sha256,
                    sanitized_sha256=sanitized_sha256,
                    findings=tuple(unique_findings),
                    redacted_preview=_redacted_preview(sanitized),
                    action=action,
                )
            )
        except Exception:
            audit_event_ids = []

    return (
        sanitized,
        MemoryGovernanceDecision(
            decision_id=decision_id,
            route=route,
            changed=changed,
            findings=unique_findings,
            raw_sha256=raw_sha256,
            sanitized_sha256=sanitized_sha256,
            action=action,
            audit_event_ids=audit_event_ids,
        ),
    )


def _resolve_root_config(root_config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if root_config is not None:
        return root_config
    return _cached_root_config()


@lru_cache(maxsize=1)
def _cached_root_config() -> Mapping[str, Any]:
    from hermes_cli.config import load_config

    return load_config()


def _sanitize_payload(value: Any) -> tuple[Any, list[str]]:
    if isinstance(value, str):
        return sanitize_text_for_model_boundary(value)

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        findings: list[str] = []
        for key, item in value.items():
            sanitized_item, item_findings = _sanitize_payload(item)
            sanitized[str(key)] = sanitized_item
            findings.extend(item_findings)
        return sanitized, findings

    if isinstance(value, list):
        sanitized_items: list[Any] = []
        findings: list[str] = []
        for item in value:
            sanitized_item, item_findings = _sanitize_payload(item)
            sanitized_items.append(sanitized_item)
            findings.extend(item_findings)
        return sanitized_items, findings

    if isinstance(value, tuple):
        sanitized_items: list[Any] = []
        findings: list[str] = []
        for item in value:
            sanitized_item, item_findings = _sanitize_payload(item)
            sanitized_items.append(sanitized_item)
            findings.extend(item_findings)
        return tuple(sanitized_items), findings

    return value, []


def _append_memory_governance_event(
    audit_store: AuditStore,
    *,
    decision_id: str,
    route: str,
    raw_sha256: str,
    sanitized_sha256: str,
    findings: tuple[str, ...],
    redacted_preview: str,
    action: str,
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": AuditEventType.MEMORY_GOVERNANCE_SANITIZED.value,
            "decision_id": decision_id,
            "route": route,
            "raw_sha256": raw_sha256,
            "created_at": created_at,
        }
    )[:32]
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.MEMORY_GOVERNANCE_SANITIZED,
            subject_id="memory-governance",
            action_id=route,
            decision_id=decision_id,
            redacted_preview=redacted_preview,
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata={
                "route": route,
                "findings": list(findings),
                "sanitized_sha256": sanitized_sha256,
                "action": action,
            },
        )
    )
    return (event_id,)


def _redacted_preview(content: Any, max_len: int = 240) -> str:
    text = _plain_text(content)
    text = " ".join(text.split())
    if len(text) > max_len:
        return text[: max_len - 1] + "..."
    return text


def _plain_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return " ".join(_plain_text(item) for item in value.values())
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return " ".join(_plain_text(item) for item in value)
    return str(value)


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


def _as_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return {str(item) for item in value}
    return set()
