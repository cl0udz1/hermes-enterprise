"""Tests for enterprise developer local fast path."""

from __future__ import annotations

from types import SimpleNamespace

from enterprise.audit import AuditStore
from enterprise.contracts import DecisionOutcome
from enterprise.firewall.action import evaluate_tool_call
from enterprise.staging import StageStore


FAKE_OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"


def _config_for_workspace(workspace: str, *, enabled: bool = True) -> dict:
    return {
        "enterprise": {
            "enabled": True,
            "runtime": {
                "allowed_roots": [workspace],
            },
            "developer_fast_path": {
                "enabled": enabled,
                "owner_workspace_roots": {
                    "alice": [workspace],
                },
            },
        }
    }


def test_developer_fast_path_allows_owner_workspace_write_and_audits(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    agent = SimpleNamespace(user_id="alice")

    decision = evaluate_tool_call(
        "write_file",
        {"path": str(workspace / "notes.md"), "content": "hello local workspace"},
        agent=agent,
        root_config=_config_for_workspace(str(workspace)),
        audit_store=audit,
        stage_store=stages,
        task_id="task-fast",
        tool_call_id="call-fast",
    )

    assert decision.allows_execution is True
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.ALLOW
    assert "developer_fast_path:owner_workspace" in decision.triage_decision.detectors
    assert stages.count() == 0
    assert audit.count() == 2

    events = audit.list_events()
    assert all(event.metadata["fast_path"] is True for event in events)
    assert events[-1].metadata["observed_side_effects"] == ["filesystem_write"]
    assert "hello local workspace" not in "\n".join(event.to_json() for event in events)


def test_developer_fast_path_disabled_keeps_staged_approval(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    agent = SimpleNamespace(user_id="alice")

    decision = evaluate_tool_call(
        "write_file",
        {"path": str(workspace / "notes.md"), "content": "hello"},
        agent=agent,
        root_config=_config_for_workspace(str(workspace), enabled=False),
        audit_store=audit,
        stage_store=stages,
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
    assert decision.staged_record is not None
    assert stages.count() == 1
    assert audit.count() == 3
    assert "developer_fast_path:owner_workspace" not in decision.triage_decision.detectors


def test_developer_fast_path_does_not_override_secret_content_denial(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    agent = SimpleNamespace(user_id="alice")

    decision = evaluate_tool_call(
        "write_file",
        {"path": str(workspace / "notes.md"), "content": f"OPENAI_API_KEY={FAKE_OPENAI_KEY}"},
        agent=agent,
        root_config=_config_for_workspace(str(workspace)),
        audit_store=audit,
        stage_store=stages,
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.DENY
    assert "secret_pattern:openai_key" in decision.triage_decision.detectors
    assert "developer_fast_path:owner_workspace" not in decision.triage_decision.detectors
    assert stages.count() == 0
    assert FAKE_OPENAI_KEY not in "\n".join(event.to_json() for event in audit.list_events())


def test_developer_fast_path_does_not_cross_workspace_boundary(tmp_path):
    workspace = tmp_path / "repo"
    other_workspace = tmp_path / "other"
    workspace.mkdir()
    other_workspace.mkdir()
    audit = AuditStore(tmp_path / "audit.sqlite3")
    agent = SimpleNamespace(user_id="alice")

    decision = evaluate_tool_call(
        "write_file",
        {"path": str(other_workspace / "notes.md"), "content": "cross workspace"},
        agent=agent,
        root_config=_config_for_workspace(str(workspace)),
        audit_store=audit,
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.DENY
    assert "path_policy:outside_allowed_roots" in decision.triage_decision.detectors
    assert "developer_fast_path:owner_workspace" not in decision.triage_decision.detectors


def test_developer_fast_path_keeps_network_tools_outside_fast_path(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    agent = SimpleNamespace(user_id="alice")

    decision = evaluate_tool_call(
        "browser_navigate",
        {"url": "https://example.com"},
        agent=agent,
        root_config=_config_for_workspace(str(workspace)),
        audit_store=audit,
        stage_store=stages,
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert "developer_fast_path:owner_workspace" not in decision.triage_decision.detectors
    assert stages.count() == 0


def test_developer_fast_path_blocks_sensitive_path_from_fast_path(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    agent = SimpleNamespace(user_id="alice")

    decision = evaluate_tool_call(
        "write_file",
        {"path": str(workspace / ".env"), "content": "LOCAL_ONLY=1"},
        agent=agent,
        root_config=_config_for_workspace(str(workspace)),
        audit_store=audit,
        stage_store=stages,
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
    assert "developer_fast_path:owner_workspace" not in decision.triage_decision.detectors
    assert stages.count() == 1
