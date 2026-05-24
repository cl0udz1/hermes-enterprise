"""Enterprise governance for scheduled cron execution."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import (
    AuditEvent,
    AuditEventType,
    CronGovernanceDecision,
    CronIntentEnvelope,
    DecisionOutcome,
    stable_hash,
)
from enterprise.mode import EnterpriseMode


_UNOWNED_CRON_SUBJECT = "unowned-cron-job"
_POLICY_CONTEXT_KEYS = {
    "policy_id",
    "policy_version",
    "bundle_hash",
    "bundle_version",
    "approval_id",
    "decision_id",
    "assignment_id",
    "risk_tier",
}


def evaluate_cron_job(
    job: Mapping[str, Any],
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
    now: datetime | None = None,
) -> CronGovernanceDecision:
    """Evaluate whether a scheduled job has a valid enterprise intent envelope.

    Enterprise mode is disabled by default. In that mode cron execution remains
    unchanged and no audit event is written.
    """

    enterprise_cfg = enterprise_config_from_root(root_config)
    mode = EnterpriseMode.from_config(root_config)
    cron_cfg = enterprise_cfg.get("cron_governance", {})
    if not isinstance(cron_cfg, Mapping):
        cron_cfg = {}

    job_id = _field_text(job.get("id")) or "unknown"
    owner_id = _field_text(job.get("owner_id") or job.get("enterprise_owner_id"))
    intent = _field_text(job.get("intent") or job.get("enterprise_intent"))
    expires_at = _field_text(job.get("expires_at") or job.get("enterprise_expires_at"))
    policy_context = job.get("policy_context")
    schedule_hash = stable_hash(_json_safe(job.get("schedule", {}))) if job.get("schedule") else ""

    if not mode.is_enforcing or cron_cfg.get("enabled") is False:
        return _decision(
            job_id=job_id,
            owner_id=owner_id,
            outcome=DecisionOutcome.ALLOW,
            reason="enterprise_cron_governance_disabled",
            intent_hash=_hash_text(intent),
            expires_at=expires_at,
            policy_context_hash=_hash_policy_context(policy_context),
            schedule_hash=schedule_hash,
        )

    reason = ""
    if bool(cron_cfg.get("require_owner", True)) and not owner_id:
        reason = "missing_owner"
    elif bool(cron_cfg.get("require_intent", True)) and not intent:
        reason = "missing_intent"
    elif bool(cron_cfg.get("require_expiry", True)) and not expires_at:
        reason = "missing_expiry"
    elif bool(cron_cfg.get("require_policy_context", True)) and not _valid_policy_context(policy_context):
        reason = "missing_or_invalid_policy_context"
    else:
        reason = _expiry_reason(
            expires_at,
            max_ttl_days=_positive_int(cron_cfg.get("max_ttl_days")),
            now=now,
        )

    outcome = DecisionOutcome.DENY if reason else DecisionOutcome.ALLOW
    decision = _decision(
        job_id=job_id,
        owner_id=owner_id,
        outcome=outcome,
        reason=reason or "cron_intent_envelope_valid",
        intent_hash=_hash_text(intent),
        expires_at=expires_at,
        policy_context_hash=_hash_policy_context(policy_context),
        schedule_hash=schedule_hash,
    )

    if bool(cron_cfg.get("audit_all_decisions", True)) or decision.outcome is not DecisionOutcome.ALLOW:
        event_ids = _append_audit_event(
            audit_store or AuditStore(),
            decision=decision,
            envelope=CronIntentEnvelope(
                job_id=job_id,
                owner_id=owner_id or _UNOWNED_CRON_SUBJECT,
                intent_hash=decision.intent_hash,
                expires_at=decision.expires_at,
                policy_context_hash=decision.policy_context_hash,
                schedule_hash=decision.schedule_hash,
                created_at=_utc_now().isoformat(),
            ),
        )
        if event_ids:
            decision = CronGovernanceDecision(
                decision_id=decision.decision_id,
                outcome=decision.outcome,
                reason=decision.reason,
                job_id=decision.job_id,
                owner_id=decision.owner_id,
                intent_hash=decision.intent_hash,
                expires_at=decision.expires_at,
                policy_context_hash=decision.policy_context_hash,
                schedule_hash=decision.schedule_hash,
                audit_event_ids=list(event_ids),
            )

    return decision


def cron_governance_allows_execution(decision: CronGovernanceDecision) -> bool:
    """Return whether a governed cron decision permits execution."""

    return decision.outcome is DecisionOutcome.ALLOW


def bind_cron_governance(target: Any, decision: CronGovernanceDecision) -> None:
    """Attach cron governance identity to a mutable agent/runtime object."""

    if target is None or not decision.owner_id:
        return
    try:
        setattr(target, "enterprise_subject_id", decision.owner_id)
        setattr(target, "_enterprise_subject_id", decision.owner_id)
        setattr(target, "enterprise_cron_job_id", decision.job_id)
        setattr(target, "_enterprise_cron_job_id", decision.job_id)
        setattr(target, "enterprise_cron_governance_decision_id", decision.decision_id)
        setattr(target, "_enterprise_cron_governance_decision_id", decision.decision_id)
        setattr(
            target,
            "enterprise_cron_governance",
            {
                "decision_id": decision.decision_id,
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "job_id": decision.job_id,
                "owner_id": decision.owner_id,
                "intent_hash": decision.intent_hash,
                "expires_at": decision.expires_at,
                "policy_context_hash": decision.policy_context_hash,
                "schedule_hash": decision.schedule_hash,
            },
        )
    except Exception:
        return


def _decision(
    *,
    job_id: str,
    owner_id: str,
    outcome: DecisionOutcome,
    reason: str,
    intent_hash: str,
    expires_at: str,
    policy_context_hash: str,
    schedule_hash: str,
) -> CronGovernanceDecision:
    decision_id = stable_hash(
        {
            "job_id": job_id,
            "owner_id": owner_id,
            "outcome": outcome.value,
            "reason": reason,
            "intent_hash": intent_hash,
            "expires_at": expires_at,
            "policy_context_hash": policy_context_hash,
            "schedule_hash": schedule_hash,
        }
    )[:32]
    return CronGovernanceDecision(
        decision_id=decision_id,
        outcome=outcome,
        reason=reason,
        job_id=job_id,
        owner_id=owner_id,
        intent_hash=intent_hash,
        expires_at=expires_at,
        policy_context_hash=policy_context_hash,
        schedule_hash=schedule_hash,
    )


def _append_audit_event(
    audit_store: AuditStore,
    *,
    decision: CronGovernanceDecision,
    envelope: CronIntentEnvelope,
) -> tuple[str, ...]:
    created_at = _utc_now().isoformat()
    event_id = stable_hash(
        {
            "event_type": AuditEventType.CRON_GOVERNANCE_DECISION.value,
            "decision_id": decision.decision_id,
            "created_at": created_at,
        }
    )[:32]
    raw_sha256 = stable_hash(envelope.to_dict())
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.CRON_GOVERNANCE_DECISION,
            subject_id=decision.owner_id or _UNOWNED_CRON_SUBJECT,
            decision_id=decision.decision_id,
            redacted_preview=(
                "cron governance "
                f"{decision.outcome.value} job={decision.job_id} "
                f"owner={decision.owner_id or _UNOWNED_CRON_SUBJECT}"
            ),
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata={
                "job_id": decision.job_id,
                "owner_id": decision.owner_id,
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "intent_hash": decision.intent_hash,
                "expires_at": decision.expires_at,
                "policy_context_hash": decision.policy_context_hash,
                "schedule_hash": decision.schedule_hash,
            },
        )
    )
    return (event_id,)


def _expiry_reason(
    expires_at: str,
    *,
    max_ttl_days: int | None,
    now: datetime | None,
) -> str:
    if not expires_at:
        return ""
    current = _as_utc(now or _utc_now())
    try:
        expiry = _parse_iso_datetime(expires_at)
    except ValueError:
        return "invalid_expiry"
    if expiry <= current:
        return "expired"
    if max_ttl_days and expiry - current > timedelta(days=max_ttl_days):
        return "expiry_exceeds_max_ttl"
    return ""


def _parse_iso_datetime(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty datetime")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return _as_utc(parsed)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _field_text(value: Any) -> str:
    return str(value or "").strip()


def _hash_text(value: str) -> str:
    return stable_hash(value) if value else ""


def _hash_policy_context(value: Any) -> str:
    return stable_hash(_json_safe(value)) if value not in (None, "", {}, []) else ""


def _valid_policy_context(value: Any) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    return any(key in value and value.get(key) not in (None, "", [], {}) for key in _POLICY_CONTEXT_KEYS)


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)
