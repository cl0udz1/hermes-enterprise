"""Tests for enterprise gateway subject binding."""

from __future__ import annotations

from enterprise.audit import AuditStore
from enterprise.contracts import AuditEventType, DecisionOutcome
from enterprise.firewall.action import _subject_id
from enterprise.gateway_identity import evaluate_gateway_identity
from gateway.config import Platform
from gateway.session import SessionSource


def _source(user_id: str = "U-sensitive", chat_id: str = "C-sensitive") -> SessionSource:
    return SessionSource(
        platform=Platform.SLACK,
        user_id=user_id,
        chat_id=chat_id,
        thread_id="T-sensitive",
        user_name="tester",
        chat_type="dm",
    )


def test_gateway_identity_disabled_is_noop(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_gateway_identity(
        _source(),
        root_config={"enterprise": {"enabled": False}},
        audit_store=audit,
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.reason == "enterprise_gateway_identity_disabled"
    assert audit.count() == 0


def test_gateway_identity_binds_assignment_and_audits_without_raw_ids(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    root_config = {
        "enterprise": {
            "enabled": True,
            "gateway_identity": {
                "assignments": {
                    "slack-researcher": {
                        "subject_id": "employee-researcher",
                        "platform": "slack",
                        "user_id": "U-sensitive",
                        "chat_id": "C-sensitive",
                    }
                }
            },
        }
    }

    decision = evaluate_gateway_identity(
        _source(),
        root_config=root_config,
        audit_store=audit,
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.subject_id == "employee-researcher"
    assert decision.assignment_id == "slack-researcher"
    assert decision.user_id_hash
    assert decision.channel_hash
    event = audit.list_events()[0]
    rendered = event.to_json()
    assert event.event_type is AuditEventType.GATEWAY_IDENTITY_DECISION
    assert event.subject_id == "employee-researcher"
    assert event.metadata["platform"] == "slack"
    assert event.metadata["assignment_id"] == "slack-researcher"
    assert "U-sensitive" not in rendered
    assert "C-sensitive" not in rendered
    assert "T-sensitive" not in rendered


def test_gateway_identity_denies_unmapped_subject(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    root_config = {
        "enterprise": {
            "enabled": True,
            "gateway_identity": {
                "assignments": {
                    "someone-else": {
                        "subject_id": "employee-other",
                        "platform": "slack",
                        "user_id": "U-other",
                    }
                }
            },
        }
    }

    decision = evaluate_gateway_identity(
        _source(),
        root_config=root_config,
        audit_store=audit,
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.subject_id == "unmapped-gateway-subject"
    assert decision.assignment_id == ""
    assert audit.count() == 1


def test_action_firewall_prefers_enterprise_gateway_subject():
    class Agent:
        enterprise_subject_id = "employee-researcher"
        user_id = "raw-platform-user"
        session_id = "session-1"

    assert _subject_id(Agent()) == "employee-researcher"


def test_action_firewall_falls_back_to_private_gateway_user_id():
    class Agent:
        _user_id = "raw-platform-user"
        session_id = "session-1"

    assert _subject_id(Agent()) == "raw-platform-user"
