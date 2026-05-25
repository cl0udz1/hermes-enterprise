from __future__ import annotations

from datetime import datetime, timedelta, timezone

from enterprise.assignments import AgentAssignmentStore, assignment_counts, assignment_to_summary
from enterprise.control_center import evaluate_control_center_access


def test_agent_assignment_store_tracks_active_and_revoked_records(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    store = AgentAssignmentStore(tmp_path / "assignments.sqlite3")

    record = store.create(
        subject_id="employee:jane",
        agent_id="repo-coder",
        profile_id="coder",
        role="employee",
        assigned_by="manager-1",
        assignment_reason="ticket SEC-42",
        allowed_surfaces=["dashboard", "gateway"],
        workspace_scope=["repo:billing-api"],
    )

    active = store.active_for_subject("employee:jane", surface="dashboard")
    assert [item.assignment_id for item in active] == [record.assignment_id]
    assert assignment_to_summary(record)["workspace_scope"] == ["repo:billing-api"]

    revoked = store.revoke(record.assignment_id, revoked_by="manager-1")

    assert revoked is not None
    assert store.active_for_subject("employee:jane", surface="dashboard") == []
    counts = assignment_counts(store.list())
    assert counts["total"] == 1
    assert counts["revoked"] == 1


def test_agent_assignment_counts_expired_records(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    store = AgentAssignmentStore(tmp_path / "assignments.sqlite3")
    now = datetime.now(timezone.utc)

    record = store.create(
        subject_id="employee:jane",
        agent_id="researcher",
        profile_id="default",
        role="employee",
        assigned_by="manager-1",
        assignment_reason="time boxed research",
        expires_at=(now - timedelta(minutes=1)).isoformat(),
    )

    assert store.active_for_subject("employee:jane", now=now) == []
    assert assignment_to_summary(record, now=now)["status"] == "expired"
    assert assignment_counts(store.list(), now=now)["expired"] == 1


def test_control_center_denies_employee_and_requires_proxy_identity_when_configured():
    root_config = {
        "enterprise": {
            "enabled": True,
            "mode": "team",
            "control_center": {
                "enabled": True,
                "require_proxy_identity": True,
            },
        }
    }

    missing = evaluate_control_center_access({}, root_config=root_config, capability="view")
    employee = evaluate_control_center_access(
        {
            "x-hermes-subject": "employee:jane",
            "x-hermes-roles": "employee",
        },
        root_config=root_config,
        capability="view",
    )
    manager = evaluate_control_center_access(
        {
            "x-hermes-subject": "manager:ali",
            "x-hermes-roles": "manager",
        },
        root_config=root_config,
        capability="assign",
    )

    assert missing.allowed is False
    assert missing.reason == "proxy_identity_required"
    assert employee.allowed is False
    assert employee.reason == "role_denied"
    assert manager.allowed is True
