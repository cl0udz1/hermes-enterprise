"""Gateway subject binding for enterprise mode.

This module maps platform users/channels to enterprise subjects before gateway
messages reach the agent runtime. It stores only stable hashes of raw platform
identifiers in audit records.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import (
    AuditEvent,
    AuditEventType,
    DecisionOutcome,
    GatewayIdentityDecision,
    GatewaySubjectBinding,
    stable_hash,
)
from enterprise.mode import EnterpriseMode


_UNMAPPED_SUBJECT_ID = "unmapped-gateway-subject"


def evaluate_gateway_identity(
    source: Any,
    *,
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> GatewayIdentityDecision:
    """Evaluate whether a gateway source is bound to an enterprise subject."""

    enterprise_cfg = enterprise_config_from_root(root_config)
    mode = EnterpriseMode.from_config(root_config)
    gateway_cfg = enterprise_cfg.get("gateway_identity", {})
    if not isinstance(gateway_cfg, Mapping):
        gateway_cfg = {}

    platform = _platform_value(getattr(source, "platform", ""))
    user_id_hash = _hash_optional(getattr(source, "user_id", None))
    channel_hash = _hash_optional(getattr(source, "chat_id", None))
    thread_id_hash = _hash_optional(getattr(source, "thread_id", None))
    chat_type = str(getattr(source, "chat_type", "") or "")

    if not mode.is_enforcing or not bool(gateway_cfg.get("enabled", True)):
        return GatewayIdentityDecision(
            decision_id=_decision_id(
                platform=platform,
                outcome=DecisionOutcome.ALLOW,
                assignment_id="",
                subject_id="",
                user_id_hash=user_id_hash,
                channel_hash=channel_hash,
                thread_id_hash=thread_id_hash,
            ),
            outcome=DecisionOutcome.ALLOW,
            reason="enterprise_gateway_identity_disabled",
            platform=platform,
            user_id_hash=user_id_hash,
            channel_hash=channel_hash,
            thread_id_hash=thread_id_hash,
            chat_type=chat_type,
        )

    binding = _find_assignment(source, gateway_cfg.get("assignments", {}))
    if binding is not None:
        decision = GatewayIdentityDecision(
            decision_id=_decision_id(
                platform=platform,
                outcome=DecisionOutcome.ALLOW,
                assignment_id=binding.assignment_id,
                subject_id=binding.subject_id,
                user_id_hash=user_id_hash,
                channel_hash=channel_hash,
                thread_id_hash=thread_id_hash,
            ),
            outcome=DecisionOutcome.ALLOW,
            reason="assignment_matched",
            platform=platform,
            subject_id=binding.subject_id,
            assignment_id=binding.assignment_id,
            user_id_hash=user_id_hash,
            channel_hash=channel_hash,
            thread_id_hash=thread_id_hash,
            chat_type=chat_type,
        )
    else:
        outcome = _unmapped_outcome(str(gateway_cfg.get("unmapped_action", "deny")))
        decision = GatewayIdentityDecision(
            decision_id=_decision_id(
                platform=platform,
                outcome=outcome,
                assignment_id="",
                subject_id=_UNMAPPED_SUBJECT_ID,
                user_id_hash=user_id_hash,
                channel_hash=channel_hash,
                thread_id_hash=thread_id_hash,
            ),
            outcome=outcome,
            reason="no_gateway_assignment",
            platform=platform,
            subject_id=_UNMAPPED_SUBJECT_ID,
            user_id_hash=user_id_hash,
            channel_hash=channel_hash,
            thread_id_hash=thread_id_hash,
            chat_type=chat_type,
        )

    if bool(gateway_cfg.get("audit_all_decisions", True)) or decision.outcome is not DecisionOutcome.ALLOW:
        event_ids = _append_audit_event(audit_store or AuditStore(), decision)
        if event_ids:
            decision = GatewayIdentityDecision(
                decision_id=decision.decision_id,
                outcome=decision.outcome,
                reason=decision.reason,
                platform=decision.platform,
                subject_id=decision.subject_id,
                assignment_id=decision.assignment_id,
                user_id_hash=decision.user_id_hash,
                channel_hash=decision.channel_hash,
                thread_id_hash=decision.thread_id_hash,
                chat_type=decision.chat_type,
                audit_event_ids=list(event_ids),
            )
    return decision


def gateway_identity_allows_dispatch(decision: GatewayIdentityDecision) -> bool:
    """Return whether a gateway message may proceed into agent dispatch."""

    return decision.outcome is DecisionOutcome.ALLOW


def bind_gateway_identity(target: Any, decision: GatewayIdentityDecision) -> None:
    """Attach enterprise gateway identity metadata to a mutable object."""

    if target is None or not decision.subject_id:
        return
    try:
        setattr(target, "enterprise_subject_id", decision.subject_id)
        setattr(target, "_enterprise_subject_id", decision.subject_id)
        setattr(target, "enterprise_assignment_id", decision.assignment_id)
        setattr(target, "_enterprise_assignment_id", decision.assignment_id)
        setattr(target, "enterprise_gateway_identity_decision_id", decision.decision_id)
        setattr(target, "_enterprise_gateway_identity_decision_id", decision.decision_id)
        setattr(
            target,
            "enterprise_gateway_identity",
            {
                "decision_id": decision.decision_id,
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "platform": decision.platform,
                "subject_id": decision.subject_id,
                "assignment_id": decision.assignment_id,
                "user_id_hash": decision.user_id_hash,
                "channel_hash": decision.channel_hash,
                "thread_id_hash": decision.thread_id_hash,
                "chat_type": decision.chat_type,
            },
        )
    except Exception:
        return


def _find_assignment(source: Any, raw_assignments: Any) -> GatewaySubjectBinding | None:
    assignments = _assignment_items(raw_assignments)
    for assignment_id, assignment in assignments:
        subject_id = str(assignment.get("subject_id") or "").strip()
        if not assignment_id or not subject_id:
            continue
        if not _assignment_has_selector(assignment):
            continue
        if not _assignment_matches(source, assignment):
            continue
        return GatewaySubjectBinding(
            assignment_id=assignment_id,
            subject_id=subject_id,
            platform=_platform_value(assignment.get("platform") or getattr(source, "platform", "")),
            user_id_hash=_hash_optional(getattr(source, "user_id", None)),
            channel_hash=_hash_optional(getattr(source, "chat_id", None)),
            thread_id_hash=_hash_optional(getattr(source, "thread_id", None)),
            chat_type=str(getattr(source, "chat_type", "") or ""),
        )
    return None


def _assignment_items(raw_assignments: Any) -> list[tuple[str, Mapping[str, Any]]]:
    if isinstance(raw_assignments, Mapping):
        items: list[tuple[str, Mapping[str, Any]]] = []
        for raw_id, raw_assignment in raw_assignments.items():
            if not isinstance(raw_assignment, Mapping):
                continue
            assignment_id = str(raw_assignment.get("assignment_id") or raw_id or "").strip()
            items.append((assignment_id, raw_assignment))
        return items
    if isinstance(raw_assignments, Iterable) and not isinstance(raw_assignments, (str, bytes, bytearray)):
        items = []
        for index, raw_assignment in enumerate(raw_assignments):
            if not isinstance(raw_assignment, Mapping):
                continue
            assignment_id = str(raw_assignment.get("assignment_id") or f"assignment-{index}" or "").strip()
            items.append((assignment_id, raw_assignment))
        return items
    return []


def _assignment_has_selector(assignment: Mapping[str, Any]) -> bool:
    if assignment.get("platform") in (None, ""):
        return False
    for key in (
        "user_id",
        "user_id_alt",
        "chat_id",
        "channel_id",
        "thread_id",
        "guild_id",
        "parent_chat_id",
    ):
        value = assignment.get(key)
        if value not in (None, "", [], ()):
            return True
    return False


def _assignment_matches(source: Any, assignment: Mapping[str, Any]) -> bool:
    checks = {
        "platform": _platform_value(getattr(source, "platform", "")),
        "user_id": getattr(source, "user_id", None),
        "user_id_alt": getattr(source, "user_id_alt", None),
        "chat_id": getattr(source, "chat_id", None),
        "channel_id": getattr(source, "chat_id", None),
        "thread_id": getattr(source, "thread_id", None),
        "chat_type": getattr(source, "chat_type", None),
        "guild_id": getattr(source, "guild_id", None),
        "parent_chat_id": getattr(source, "parent_chat_id", None),
    }
    for key, actual in checks.items():
        if key not in assignment:
            continue
        if key == "platform":
            expected = assignment.get(key)
            if expected in (None, ""):
                continue
            if not _value_matches(expected, actual, normalize=_platform_value):
                return False
            continue
        if not _value_matches(assignment.get(key), actual):
            return False
    return True


def _value_matches(expected: Any, actual: Any, *, normalize=None) -> bool:
    if expected in (None, ""):
        return True
    if isinstance(expected, Iterable) and not isinstance(expected, (str, bytes, bytearray, Mapping)):
        return any(_value_matches(item, actual, normalize=normalize) for item in expected)
    expected_str = str(expected).strip()
    if expected_str == "*":
        return True
    actual_str = str(actual or "").strip()
    if normalize:
        expected_str = normalize(expected_str)
        actual_str = normalize(actual_str)
    return expected_str == actual_str


def _unmapped_outcome(action: str) -> DecisionOutcome:
    normalized = action.strip().lower().replace("-", "_")
    if normalized in {"allow", "log_only", "audit_only"}:
        return DecisionOutcome.ALLOW
    if normalized in {"quarantine", "downgrade"}:
        return DecisionOutcome.QUARANTINE
    return DecisionOutcome.DENY


def _append_audit_event(
    audit_store: AuditStore,
    decision: GatewayIdentityDecision,
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": AuditEventType.GATEWAY_IDENTITY_DECISION.value,
            "decision_id": decision.decision_id,
            "created_at": created_at,
        }
    )[:32]
    raw_sha256 = stable_hash(
        {
            "platform": decision.platform,
            "user_id_hash": decision.user_id_hash,
            "channel_hash": decision.channel_hash,
            "thread_id_hash": decision.thread_id_hash,
        }
    )
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.GATEWAY_IDENTITY_DECISION,
            subject_id=decision.subject_id or _UNMAPPED_SUBJECT_ID,
            decision_id=decision.decision_id,
            redacted_preview=(
                "gateway identity "
                f"{decision.outcome.value} platform={decision.platform or 'unknown'} "
                f"assignment={decision.assignment_id or 'unmapped'}"
            ),
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata={
                "platform": decision.platform,
                "chat_type": decision.chat_type,
                "subject_id": decision.subject_id,
                "assignment_id": decision.assignment_id,
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "user_id_hash": decision.user_id_hash,
                "channel_hash": decision.channel_hash,
                "thread_id_hash": decision.thread_id_hash,
            },
        )
    )
    return (event_id,)


def _decision_id(
    *,
    platform: str,
    outcome: DecisionOutcome,
    assignment_id: str,
    subject_id: str,
    user_id_hash: str,
    channel_hash: str,
    thread_id_hash: str,
) -> str:
    return stable_hash(
        {
            "platform": platform,
            "outcome": outcome.value,
            "assignment_id": assignment_id,
            "subject_id": subject_id,
            "user_id_hash": user_id_hash,
            "channel_hash": channel_hash,
            "thread_id_hash": thread_id_hash,
        }
    )[:32]


def _platform_value(platform: Any) -> str:
    return str(getattr(platform, "value", platform) or "").strip().lower()


def _hash_optional(value: Any) -> str:
    if value in (None, ""):
        return ""
    return stable_hash(str(value))
