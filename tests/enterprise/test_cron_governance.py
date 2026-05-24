"""Tests for enterprise cron governance."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from enterprise.audit import AuditStore
from enterprise.contracts import AuditEventType, DecisionOutcome
from enterprise.cron_governance import (
    bind_cron_governance,
    cron_governance_allows_execution,
    evaluate_cron_job,
)


def _job(**overrides):
    now = datetime.now(timezone.utc)
    job = {
        "id": "job-secure-1",
        "owner_id": "employee-researcher",
        "intent": "daily regulated research digest",
        "expires_at": (now + timedelta(days=7)).isoformat(),
        "policy_context": {"policy_id": "cron-research", "policy_version": "2026.05"},
        "schedule": {"kind": "interval", "minutes": 60},
    }
    job.update(overrides)
    return job


def _enterprise_enabled(**cron_overrides):
    cron_cfg = {"max_ttl_days": 90}
    cron_cfg.update(cron_overrides)
    return {"enterprise": {"enabled": True, "cron_governance": cron_cfg}}


def _serialized(value) -> str:
    return json.dumps(
        value,
        default=lambda item: item.to_dict() if hasattr(item, "to_dict") else str(item),
        sort_keys=True,
    )


def test_cron_governance_disabled_is_noop(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_cron_job(
        {"id": "legacy-job", "prompt": "run"},
        root_config={"enterprise": {"enabled": False}},
        audit_store=audit,
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.reason == "enterprise_cron_governance_disabled"
    assert audit.count() == 0


def test_cron_governance_valid_envelope_allows_and_audits_without_raw_intent(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    job = _job(intent="summarize customer-sensitive renewal notes")

    decision = evaluate_cron_job(
        job,
        root_config=_enterprise_enabled(),
        audit_store=audit,
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert cron_governance_allows_execution(decision) is True
    assert decision.owner_id == "employee-researcher"
    assert decision.intent_hash
    event = audit.list_events()[0]
    rendered = event.to_json()
    assert event.event_type is AuditEventType.CRON_GOVERNANCE_DECISION
    assert event.subject_id == "employee-researcher"
    assert event.metadata["job_id"] == "job-secure-1"
    assert event.metadata["outcome"] == "allow"
    assert "summarize customer-sensitive renewal notes" not in rendered
    assert "cron-research" not in rendered


def test_cron_governance_missing_owner_fails_closed(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_cron_job(
        _job(owner_id=""),
        root_config=_enterprise_enabled(),
        audit_store=audit,
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason == "missing_owner"
    assert cron_governance_allows_execution(decision) is False
    assert audit.count() == 1


def test_cron_governance_expired_or_invalid_expiry_fails_closed(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    now = datetime.now(timezone.utc)

    expired = evaluate_cron_job(
        _job(expires_at=(now - timedelta(minutes=1)).isoformat()),
        root_config=_enterprise_enabled(),
        audit_store=audit,
        now=now,
    )
    invalid = evaluate_cron_job(
        _job(id="job-invalid-expiry", expires_at="not-a-date"),
        root_config=_enterprise_enabled(),
        audit_store=audit,
        now=now,
    )

    assert expired.outcome is DecisionOutcome.DENY
    assert expired.reason == "expired"
    assert invalid.outcome is DecisionOutcome.DENY
    assert invalid.reason == "invalid_expiry"


def test_cron_governance_binds_owner_to_agent_subject():
    class Agent:
        pass

    agent = Agent()
    decision = evaluate_cron_job(_job(), root_config=_enterprise_enabled(audit_all_decisions=False))

    bind_cron_governance(agent, decision)

    assert agent.enterprise_subject_id == "employee-researcher"
    assert agent.enterprise_cron_job_id == "job-secure-1"
    assert agent.enterprise_cron_governance["intent_hash"] == decision.intent_hash
    assert "daily regulated research digest" not in _serialized(agent.enterprise_cron_governance)
