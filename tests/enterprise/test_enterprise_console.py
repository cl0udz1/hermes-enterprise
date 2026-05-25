from __future__ import annotations

from enterprise.access import AccessGrantStore
from enterprise.audit import AuditStore
from enterprise.console import (
    approve_console_stage,
    build_enterprise_evidence_bundle,
    build_enterprise_console_snapshot,
    deny_console_stage,
)
from enterprise.contracts import AuditEventType, StageStatus
from enterprise.firewall.action import evaluate_tool_call
from enterprise.staging import StageStore


def _enterprise_config() -> dict:
    return {"enterprise": {"enabled": True, "mode": "team"}}


def _stage_terminal_action(
    *,
    audit: AuditStore,
    stages: StageStore,
    grants: AccessGrantStore,
    command: str = "echo hello",
):
    decision = evaluate_tool_call(
        "terminal",
        {"command": command},
        root_config=_enterprise_config(),
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
        task_id="task-console",
        tool_call_id="call-console",
    )
    assert decision.staged_record is not None
    return decision.staged_record


def test_enterprise_console_lists_pending_approvals(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    record = _stage_terminal_action(audit=audit, stages=stages, grants=grants)

    snapshot = build_enterprise_console_snapshot(
        root_config=_enterprise_config(),
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
    )

    assert snapshot["counts"]["approvals_pending"] == 1
    assert snapshot["counts"]["staged_total"] == 1
    assert snapshot["pending_approvals"][0]["stage_id"] == record.stage_id
    assert snapshot["pending_approvals"][0]["safe_args"]["command"] == "echo hello"
    assert snapshot["pending_approvals"][0]["status"] == StageStatus.STAGED.value


def test_enterprise_console_approves_stage_into_active_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    record = _stage_terminal_action(audit=audit, stages=stages, grants=grants)

    approved = approve_console_stage(
        record.stage_id,
        approved_by="manager-1",
        ttl_minutes=30,
        policy_version="policy-dashboard",
        reason="ticket SEC-42 confirms this command is scoped",
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
    )
    snapshot = build_enterprise_console_snapshot(
        root_config=_enterprise_config(),
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
    )

    assert approved["ok"] is True
    assert approved["grant"]["status"] == "active"
    assert approved["grant"]["stage_id"] == record.stage_id
    assert snapshot["counts"]["approvals_pending"] == 0
    assert snapshot["counts"]["approvals_approved"] == 1
    assert snapshot["counts"]["grants_active"] == 1
    assert stages.get_record(record.stage_id).status is StageStatus.APPROVED
    approval_event = next(event for event in audit.list_events() if event.event_type is AuditEventType.ACTION_APPROVED)
    assert approval_event.metadata["operator_reason"] == "ticket SEC-42 confirms this command is scoped"
    assert any(
        event["operator_reason"] == "ticket SEC-42 confirms this command is scoped"
        for event in snapshot["recent_events"]
    )


def test_enterprise_console_denies_stage_and_audits(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    record = _stage_terminal_action(audit=audit, stages=stages, grants=grants)

    denied = deny_console_stage(
        record.stage_id,
        denied_by="manager-1",
        reason="requested command no longer matches the change ticket",
        audit_store=audit,
        stage_store=stages,
    )
    snapshot = build_enterprise_console_snapshot(
        root_config=_enterprise_config(),
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
    )

    assert denied["ok"] is True
    assert denied["stage"]["status"] == StageStatus.DENIED.value
    assert snapshot["counts"]["approvals_pending"] == 0
    assert snapshot["counts"]["approvals_denied"] == 1
    assert stages.get_record(record.stage_id).status is StageStatus.DENIED
    assert any(
        event.event_type is AuditEventType.ACTION_DENIED
        and event.decision_id == record.stage_id
        and event.metadata["operator_reason"] == "requested command no longer matches the change ticket"
        for event in audit.list_events()
    )


def test_enterprise_evidence_bundle_exports_redacted_stage_context(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    record = _stage_terminal_action(audit=audit, stages=stages, grants=grants)
    approve_console_stage(
        record.stage_id,
        approved_by="manager-1",
        reason="approved through dashboard for incident INC-7",
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
    )

    bundle = build_enterprise_evidence_bundle(
        stage_id=record.stage_id,
        root_config=_enterprise_config(),
        audit_store=audit,
        stage_store=stages,
        access_grant_store=grants,
    )

    assert bundle["scope"] == "stage"
    assert bundle["stage"]["stage_id"] == record.stage_id
    assert bundle["stage"]["safe_args"]["command"] == "echo hello"
    assert bundle["redaction"]["raw_payloads_excluded"] is True
    assert bundle["integrity"]["evidence_sha256"]
    assert bundle["grants"][0]["stage_id"] == record.stage_id
    assert any(
        event["operator_reason"] == "approved through dashboard for incident INC-7"
        for event in bundle["events"]
    )
