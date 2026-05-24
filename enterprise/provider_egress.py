"""Provider request egress guard for enterprise model boundaries."""

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
    ProviderEgressDecision,
    stable_hash,
)
from enterprise.mode import EnterpriseMode
from enterprise.sanitization import sanitize_text_for_model_boundary


DEFAULT_STREAMING_POSTURE = "request_payload_only"


def govern_provider_payload(
    payload: Mapping[str, Any],
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
    route: str = "chat_completions",
) -> tuple[dict[str, Any], ProviderEgressDecision]:
    """Sanitize outbound provider payloads when enterprise mode is enforcing.

    Enterprise mode is disabled by default. In that mode the original payload
    object is returned unchanged and no audit storage is touched.
    """

    resolved_config = _resolve_root_config(root_config)
    mode = EnterpriseMode.from_config(resolved_config)
    enterprise_cfg = enterprise_config_from_root(resolved_config)
    egress_cfg = enterprise_cfg.get("provider_egress", {})
    if not isinstance(egress_cfg, Mapping):
        egress_cfg = {}
    streaming_posture = str(egress_cfg.get("streaming_posture") or DEFAULT_STREAMING_POSTURE)

    if not mode.is_enforcing or egress_cfg.get("enabled") is False:
        return (
            payload,  # type: ignore[return-value]
            ProviderEgressDecision(
                decision_id="",
                route=route,
                changed=False,
                findings=[],
                raw_sha256="",
                sanitized_sha256="",
                streaming_posture=streaming_posture,
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
        }
    )[:32]
    audit_event_ids: list[str] = []

    if changed:
        try:
            audit_event_ids = list(
                _append_provider_egress_event(
                    audit_store or AuditStore(),
                    decision_id=decision_id,
                    route=route,
                    raw_sha256=raw_sha256,
                    sanitized_sha256=sanitized_sha256,
                    findings=tuple(unique_findings),
                    redacted_preview=_redacted_preview(sanitized),
                    streaming_posture=streaming_posture,
                )
            )
        except Exception:
            audit_event_ids = []

    return (
        sanitized,
        ProviderEgressDecision(
            decision_id=decision_id,
            route=route,
            changed=changed,
            findings=unique_findings,
            raw_sha256=raw_sha256,
            sanitized_sha256=sanitized_sha256,
            streaming_posture=streaming_posture,
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


def _append_provider_egress_event(
    audit_store: AuditStore,
    *,
    decision_id: str,
    route: str,
    raw_sha256: str,
    sanitized_sha256: str,
    findings: tuple[str, ...],
    redacted_preview: str,
    streaming_posture: str,
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": AuditEventType.PROVIDER_EGRESS_SANITIZED.value,
            "decision_id": decision_id,
            "route": route,
            "raw_sha256": raw_sha256,
            "created_at": created_at,
        }
    )[:32]
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.PROVIDER_EGRESS_SANITIZED,
            subject_id="provider-egress",
            action_id=route,
            decision_id=decision_id,
            redacted_preview=redacted_preview,
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata={
                "route": route,
                "findings": list(findings),
                "sanitized_sha256": sanitized_sha256,
                "streaming_posture": streaming_posture,
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
