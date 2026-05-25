"""Operator console helpers for enterprise governance state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from enterprise.access import AccessGrantStore
from enterprise.assignments import AgentAssignmentStore, assignment_counts, assignment_to_summary
from enterprise.audit import AuditStore
from enterprise.contracts import AuditEvent, AuditEventType, StageStatus, stable_hash
from enterprise.doctor import run_enterprise_doctor
from enterprise.staging import StageStore
from enterprise.triage.detectors import SECRET_PATTERNS


MAX_OPERATOR_REASON = 500


def build_enterprise_console_snapshot(
    *,
    root_config: dict[str, Any] | None = None,
    audit_store: AuditStore | None = None,
    stage_store: StageStore | None = None,
    access_grant_store: AccessGrantStore | None = None,
    assignment_store: AgentAssignmentStore | None = None,
    recent_limit: int = 25,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a redacted snapshot for the dashboard enterprise console."""

    audit = audit_store or AuditStore()
    stages = stage_store or StageStore()
    grants = access_grant_store or AccessGrantStore()
    assignments = assignment_store or AgentAssignmentStore()
    current_time = now or datetime.now(timezone.utc)
    config = root_config or {}
    enterprise_cfg = config.get("enterprise", {}) if isinstance(config, dict) else {}
    enterprise_enabled = bool(enterprise_cfg.get("enabled")) if isinstance(enterprise_cfg, dict) else False
    mode = str(enterprise_cfg.get("mode", "off")) if isinstance(enterprise_cfg, dict) else "off"

    records = stages.list_records()
    grant_rows = grants.list_grants()
    assignment_rows = assignments.list()
    events = audit.list_events()
    doctor = run_enterprise_doctor(root_config=config)

    status_counts = _stage_counts(records)
    grant_counts = _grant_counts(grant_rows, now=current_time)
    assignment_status_counts = assignment_counts(assignment_rows, now=current_time)
    controls = doctor.to_dict()
    check_rows = list(controls.get("checks", [])) if isinstance(controls.get("checks"), list) else []

    return {
        "enabled": enterprise_enabled,
        "mode": mode,
        "doctor": {
            "overall": controls.get("status", "unknown"),
            "enabled": controls.get("enabled", enterprise_enabled),
            "mode": controls.get("mode", mode),
            "checks": [_check_summary(item) for item in check_rows],
        },
        "counts": {
            "staged_total": len(records),
            "approvals_pending": status_counts.get(StageStatus.STAGED.value, 0),
            "approvals_approved": status_counts.get(StageStatus.APPROVED.value, 0),
            "approvals_denied": status_counts.get(StageStatus.DENIED.value, 0),
            "grants_total": len(grant_rows),
            "grants_active": grant_counts["active"],
            "grants_revoked": grant_counts["revoked"],
            "grants_expired": grant_counts["expired"],
            "assignments_total": assignment_status_counts["total"],
            "assignments_active": assignment_status_counts["active"],
            "assignments_paused": assignment_status_counts["paused"],
            "assignments_revoked": assignment_status_counts["revoked"],
            "assignments_expired": assignment_status_counts["expired"],
            "audit_total": len(events),
            "doctor_pass": sum(1 for item in check_rows if item.get("status") == "pass"),
            "doctor_warn": sum(1 for item in check_rows if item.get("status") == "warn"),
            "doctor_fail": sum(1 for item in check_rows if item.get("status") == "fail"),
        },
        "pending_approvals": [
            _stage_summary(record, stages.get_preview(record.stage_id))
            for record in reversed(records)
            if record.status is StageStatus.STAGED
        ][:recent_limit],
        "recent_grants": [_grant_summary(grant, now=current_time) for grant in reversed(grant_rows)][
            :recent_limit
        ],
        "recent_assignments": [
            assignment_to_summary(record, now=current_time)
            for record in reversed(assignment_rows)
        ][:recent_limit],
        "recent_events": [_event_summary(event) for event in reversed(events)][
            :recent_limit
        ],
    }


def approve_console_stage(
    stage_id: str,
    *,
    approved_by: str,
    ttl_minutes: int = 30,
    policy_version: str = "dashboard",
    reason: str = "",
    audit_store: AuditStore | None = None,
    stage_store: StageStore | None = None,
    access_grant_store: AccessGrantStore | None = None,
) -> dict[str, Any]:
    """Approve one staged action and return its scoped grant summary."""

    audit = audit_store or AuditStore()
    stages = stage_store or StageStore()
    grants = access_grant_store or AccessGrantStore()
    grant = grants.approve_stage(
        stage_id,
        stage_store=stages,
        approved_by=approved_by.strip() or "dashboard-operator",
        ttl_minutes=max(1, int(ttl_minutes)),
        policy_version=policy_version.strip() or "dashboard",
        reason=_safe_operator_text(reason),
        audit_store=audit,
    )
    return {"ok": True, "grant": _grant_summary(grant)}


def deny_console_stage(
    stage_id: str,
    *,
    denied_by: str,
    reason: str = "",
    audit_store: AuditStore | None = None,
    stage_store: StageStore | None = None,
) -> dict[str, Any]:
    """Deny one staged action and append a redacted audit event."""

    audit = audit_store or AuditStore()
    stages = stage_store or StageStore()
    record = stages.set_status(
        stage_id,
        StageStatus.DENIED,
        approved_by=denied_by.strip() or "dashboard-operator",
    )
    if record is None:
        raise KeyError(stage_id)
    _append_stage_denied_event(audit, record, reason=_safe_operator_text(reason))
    return {"ok": True, "stage": _stage_summary(record, stages.get_preview(stage_id))}


def build_enterprise_evidence_bundle(
    *,
    stage_id: str | None = None,
    root_config: dict[str, Any] | None = None,
    audit_store: AuditStore | None = None,
    stage_store: StageStore | None = None,
    access_grant_store: AccessGrantStore | None = None,
    assignment_store: AgentAssignmentStore | None = None,
    recent_limit: int = 100,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a redacted evidence export for operator review and audit handoff."""

    audit = audit_store or AuditStore()
    stages = stage_store or StageStore()
    grants = access_grant_store or AccessGrantStore()
    assignments = assignment_store or AgentAssignmentStore()
    current_time = now or datetime.now(timezone.utc)
    events = audit.list_events()
    grant_rows = grants.list_grants()
    exported_at = current_time.isoformat()

    if stage_id:
        record = stages.get_record(stage_id)
        if record is None:
            raise KeyError(stage_id)
        stage = _stage_summary(record, stages.get_preview(stage_id))
        related_events = [
            _event_summary(event)
            for event in events
            if _event_matches_stage(event, stage_id=record.stage_id, action_hash=record.action_hash)
        ]
        related_grants = [
            _grant_summary(grant, now=current_time)
            for grant in grant_rows
            if grant.stage_id == record.stage_id or grant.action_hash == record.action_hash
        ]
        return _with_evidence_hash(
            {
                "schema_version": 1,
                "scope": "stage",
                "exported_at": exported_at,
                "redaction": {
                    "raw_payloads_excluded": True,
                    "operator_text_redacted": True,
                    "raw_hashes_retained": True,
                },
                "stage": stage,
                "grants": related_grants[:recent_limit],
                "events": related_events[:recent_limit],
                "doctor": build_enterprise_console_snapshot(
                    root_config=root_config,
                    audit_store=audit,
                    stage_store=stages,
                    access_grant_store=grants,
                    assignment_store=assignments,
                    recent_limit=1,
                    now=current_time,
                )["doctor"],
            }
        )

    snapshot = build_enterprise_console_snapshot(
        root_config=root_config,
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        assignment_store=assignments,
        recent_limit=recent_limit,
        now=current_time,
    )
    return _with_evidence_hash(
        {
            "schema_version": 1,
            "scope": "console",
            "exported_at": exported_at,
            "redaction": {
                "raw_payloads_excluded": True,
                "operator_text_redacted": True,
                "raw_hashes_retained": True,
            },
            "snapshot": snapshot,
        }
    )


def _stage_counts(records: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.status.value] = counts.get(record.status.value, 0) + 1
    return counts


def _grant_counts(grants: list[Any], *, now: datetime) -> dict[str, int]:
    counts = {"active": 0, "revoked": 0, "expired": 0}
    for grant in grants:
        if grant.revoked_at:
            counts["revoked"] += 1
        elif _parse_time(grant.expires_at) <= now:
            counts["expired"] += 1
        else:
            counts["active"] += 1
    return counts


def _stage_summary(record: Any, preview: dict[str, Any] | None) -> dict[str, Any]:
    safe_preview = dict(preview or {})
    return {
        "stage_id": record.stage_id,
        "action_hash": record.action_hash,
        "subject_id": record.subject_id,
        "tool_name": record.tool_name,
        "preview_uri": record.preview_uri,
        "idempotency_key": record.idempotency_key,
        "status": record.status.value,
        "created_at": record.created_at,
        "approved_by": record.approved_by,
        "risk_tier": str(safe_preview.get("risk_tier", "")),
        "outcome": str(safe_preview.get("outcome", "")),
        "detectors": list(safe_preview.get("detectors", []) or []),
        "requested_side_effects": list(safe_preview.get("requested_side_effects", []) or []),
        "safe_args": dict(safe_preview.get("safe_args", {}) or {}),
        "arg_keys": list(safe_preview.get("arg_keys", []) or []),
    }


def _grant_summary(grant: Any, *, now: datetime | None = None) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    expired = _parse_time(grant.expires_at) <= current_time
    if grant.revoked_at:
        status = "revoked"
    elif expired:
        status = "expired"
    else:
        status = "active"
    return {
        "grant_id": grant.grant_id,
        "request_id": grant.request_id,
        "subject_id": grant.subject_id,
        "resource": grant.resource,
        "actions": list(grant.actions),
        "expires_at": grant.expires_at,
        "policy_version": grant.policy_version,
        "created_at": grant.created_at,
        "revoked_at": grant.revoked_at,
        "approved_by": grant.approved_by,
        "stage_id": grant.stage_id,
        "action_hash": grant.action_hash,
        "tool_name": grant.tool_name,
        "status": status,
    }


def _event_summary(event: AuditEvent) -> dict[str, Any]:
    metadata = event.metadata if isinstance(event.metadata, dict) else {}
    return {
        "event_id": event.event_id,
        "event_type": event.event_type.value,
        "subject_id": event.subject_id,
        "action_id": event.action_id,
        "decision_id": event.decision_id,
        "redacted_preview": event.redacted_preview,
        "raw_sha256": event.raw_sha256,
        "created_at": event.created_at,
        "stage_id": str(metadata.get("stage_id", "")),
        "grant_id": str(metadata.get("grant_id", "")),
        "tool_name": str(metadata.get("tool_name", "")),
        "operator_id": str(
            metadata.get("approved_by")
            or metadata.get("actor_id")
            or metadata.get("operator_id")
            or ""
        ),
        "operator_reason": _safe_operator_text(str(metadata.get("operator_reason", ""))),
        "policy_version": str(metadata.get("policy_version", "")),
        "expires_at": str(metadata.get("expires_at", "")),
    }


def _check_summary(item: dict[str, Any]) -> dict[str, str]:
    return {
        "name": str(item.get("name", "")),
        "label": str(item.get("label", item.get("name", ""))),
        "status": str(item.get("status", "unknown")),
        "detail": str(item.get("detail", "")),
        "remediation": str(item.get("remediation", "")),
    }


def _append_stage_denied_event(audit_store: AuditStore, record: Any, *, reason: str = "") -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": AuditEventType.ACTION_DENIED.value,
            "stage_id": record.stage_id,
            "created_at": created_at,
        }
    )[:32]
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.ACTION_DENIED,
            subject_id=record.subject_id,
            action_id=record.action_hash,
            decision_id=record.stage_id,
            redacted_preview=f"action_denied stage={record.stage_id} tool={record.tool_name}",
            raw_sha256=stable_hash(record.to_dict()),
            created_at=created_at,
            metadata={
                "stage_id": record.stage_id,
                "tool_name": record.tool_name,
                "approved_by": record.approved_by,
                "operator_reason": reason,
                "status": record.status.value,
            },
        )
    )


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc) - timedelta(days=3650)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _event_matches_stage(event: AuditEvent, *, stage_id: str, action_hash: str) -> bool:
    metadata = event.metadata if isinstance(event.metadata, dict) else {}
    return (
        event.decision_id == stage_id
        or event.action_id == action_hash
        or str(metadata.get("stage_id", "")) == stage_id
        or str(metadata.get("request_id", "")) == stage_id
    )


def _with_evidence_hash(bundle: dict[str, Any]) -> dict[str, Any]:
    evidence_hash = stable_hash(bundle)
    return {
        **bundle,
        "integrity": {
            "hash_algorithm": "sha256:stable_json",
            "evidence_sha256": evidence_hash,
        },
    }


def _safe_operator_text(value: str, *, limit: int = MAX_OPERATOR_REASON) -> str:
    redacted = " ".join(str(value).split())
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    if len(redacted) > limit:
        return f"{redacted[:limit]}..."
    return redacted
