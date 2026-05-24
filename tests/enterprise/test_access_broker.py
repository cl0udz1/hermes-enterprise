"""Tests for enterprise access broker grant lifecycle."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from enterprise.access import AccessGrantStore
from enterprise.audit import AuditStore
from enterprise.contracts import AuditEventType, DecisionOutcome, StageStatus
from enterprise.firewall.action import evaluate_tool_call
from enterprise.staging import StageStore


def _future(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def test_access_broker_approves_stage_with_scoped_grant_and_audit(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")

    decision = evaluate_tool_call(
        "terminal",
        {"command": "echo hello"},
        root_config={"enterprise": {"enabled": True}},
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-1",
        tool_call_id="call-1",
    )
    assert decision.staged_record is not None

    grant = grants.approve_stage(
        decision.staged_record.stage_id,
        stage_store=stages,
        approved_by="manager-1",
        expires_at=_future(),
        policy_version="policy-1",
        audit_store=audit,
    )

    assert grant.subject_id == "local-agent"
    assert grant.approved_by == "manager-1"
    assert grant.action_hash == decision.action_hash
    assert grant.tool_name == "terminal"
    assert grant.resource == decision.action_hash
    stored_stage = stages.get_record(decision.staged_record.stage_id)
    assert stored_stage is not None
    assert stored_stage.status is StageStatus.APPROVED
    assert stored_stage.approved_by == "manager-1"
    assert grants.count() == 1
    assert audit.list_events()[-1].event_type is AuditEventType.ACTION_APPROVED
    assert audit.list_events()[-1].metadata["grant_id"] == grant.grant_id


def test_access_grant_allows_exact_action_and_changed_args_stage_again(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    root_config = {"enterprise": {"enabled": True}}

    staged = evaluate_tool_call(
        "terminal",
        {"command": "echo original"},
        root_config=root_config,
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-1",
        tool_call_id="call-1",
    )
    assert staged.staged_record is not None
    grant = grants.approve_stage(
        staged.staged_record.stage_id,
        stage_store=stages,
        approved_by="manager-1",
        expires_at=_future(),
        audit_store=audit,
    )

    allowed = evaluate_tool_call(
        "terminal",
        {"command": "echo original"},
        root_config=root_config,
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-1",
        tool_call_id="call-1",
    )
    changed = evaluate_tool_call(
        "terminal",
        {"command": "echo changed"},
        root_config=root_config,
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-1",
        tool_call_id="call-1",
    )

    assert allowed.allows_execution is True
    assert allowed.triage_decision is not None
    assert allowed.triage_decision.outcome is DecisionOutcome.ALLOW
    assert "grant_status:valid" in allowed.triage_decision.detectors
    assert allowed.audit_event_ids
    grant_event = audit.get_event(allowed.audit_event_ids[0])
    assert grant_event is not None
    assert grant.grant_id in grant_event.metadata["grant_ids"]
    assert changed.allows_execution is False
    assert changed.staged_record is not None
    assert changed.action_hash != staged.action_hash


def test_revoked_access_grant_fails_closed_for_same_action(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    root_config = {"enterprise": {"enabled": True}}

    staged = evaluate_tool_call(
        "terminal",
        {"command": "echo original"},
        root_config=root_config,
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-1",
        tool_call_id="call-1",
    )
    assert staged.staged_record is not None
    grant = grants.approve_stage(
        staged.staged_record.stage_id,
        stage_store=stages,
        approved_by="manager-1",
        expires_at=_future(),
        audit_store=audit,
    )
    revoked = grants.revoke_grant(grant.grant_id, revoked_by="manager-2", audit_store=audit)
    assert revoked is not None
    assert revoked.revoked_at

    denied = evaluate_tool_call(
        "terminal",
        {"command": "echo original"},
        root_config=root_config,
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-1",
        tool_call_id="call-1",
    )

    assert denied.allows_execution is False
    assert denied.triage_decision is not None
    assert denied.triage_decision.outcome is DecisionOutcome.DENY
    assert "grant_status:revoked" in denied.triage_decision.detectors
    payload = json.loads(denied.tool_result)
    assert payload["enterprise"]["outcome"] == "deny"
    revoke_events = [
        event
        for event in audit.list_events()
        if event.event_type is AuditEventType.ACCESS_GRANT_REVOKED
    ]
    assert len(revoke_events) == 1
    assert revoke_events[0].metadata["grant_id"] == grant.grant_id
