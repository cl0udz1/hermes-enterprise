from __future__ import annotations

from enterprise.access import AccessGrantStore
from enterprise.audit import AuditStore
from enterprise.console import (
    approve_console_stage,
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


def test_enterprise_console_denies_stage_and_audits(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    grants = AccessGrantStore(tmp_path / "grants.sqlite3")
    record = _stage_terminal_action(audit=audit, stages=stages, grants=grants)

    denied = deny_console_stage(
        record.stage_id,
        denied_by="manager-1",
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
        for event in audit.list_events()
    )
