"""Tests for enterprise fake secret broker lifecycle."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from agent.tool_dispatch_helpers import make_tool_result_message
from enterprise.audit import AuditStore
from enterprise.contracts import AccessGrant, AuditEventType
from enterprise.provider_egress import govern_provider_payload
from enterprise.secrets import (
    SECRET_ISSUE_ACTION,
    FakeSecretBroker,
    SecretAccessDenied,
    build_secret_access_request,
    credential_reference,
    secret_resource,
)


def _future(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _grant(
    *,
    subject_id: str = "employee-1",
    secret_name: str = "OPENAI_API_KEY",
    actions: list[str] | None = None,
    revoked_at: str = "",
    expires_at: str | None = None,
) -> AccessGrant:
    return AccessGrant(
        grant_id="grant-secret-1",
        request_id="access-request-1",
        subject_id=subject_id,
        resource=secret_resource(secret_name),
        actions=actions or [SECRET_ISSUE_ACTION],
        expires_at=expires_at or _future(),
        policy_version="policy-1",
        created_at=datetime.now(timezone.utc).isoformat(),
        revoked_at=revoked_at,
        approved_by="manager-1",
    )


def _request(secret_name: str = "OPENAI_API_KEY"):
    return build_secret_access_request(
        subject_id="employee-1",
        secret_name=secret_name,
        purpose="call approved provider",
        scope=["provider:openai"],
        action_hash="action-secret-1",
        policy_version="policy-1",
    )


def _serialized(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def test_fake_secret_broker_denies_without_policy_grant(tmp_path, fake_enterprise_secret):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    broker = FakeSecretBroker({"OPENAI_API_KEY": fake_enterprise_secret}, audit_store=audit)
    request = _request()

    with pytest.raises(SecretAccessDenied, match="missing_access_grant"):
        broker.issue_credential(request, grant=None)

    events = audit.list_events()
    assert [event.event_type for event in events] == [
        AuditEventType.SECRET_ACCESS_REQUESTED,
        AuditEventType.SECRET_ACCESS_DENIED,
    ]
    assert fake_enterprise_secret not in _serialized(events)


def test_fake_secret_broker_issues_opaque_credential_after_valid_grant(
    tmp_path,
    fake_enterprise_secret,
):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    broker = FakeSecretBroker({"OPENAI_API_KEY": fake_enterprise_secret}, audit_store=audit)
    request = _request()

    credential = broker.issue_credential(
        request,
        grant=_grant(),
        ttl_minutes=10,
    )

    assert credential.subject_id == request.subject_id
    assert credential.secret_name == "OPENAI_API_KEY"
    assert credential.broker_uri == f"broker://credential/{credential.credential_id}"
    assert credential.access_grant_id == "grant-secret-1"
    assert credential.approved_by == "manager-1"
    assert credential.scope == ["provider:openai"]
    assert len(credential.secret_value_sha256) == 64
    assert fake_enterprise_secret not in credential.to_json()
    assert broker.get_credential(credential.credential_id) == credential

    events = audit.list_events()
    assert events[-1].event_type is AuditEventType.SECRET_CREDENTIAL_ISSUED
    assert events[-1].metadata["credential_id"] == credential.credential_id
    assert fake_enterprise_secret not in _serialized(events)


@pytest.mark.parametrize(
    ("grant", "reason"),
    [
        (_grant(subject_id="employee-2"), "subject_mismatch"),
        (_grant(secret_name="OTHER_API_KEY"), "resource_mismatch"),
        (_grant(actions=["read"]), "missing_secret_issue_action"),
        (_grant(expires_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()), "grant_expired"),
        (_grant(revoked_at=datetime.now(timezone.utc).isoformat()), "grant_revoked"),
    ],
)
def test_secret_broker_rejects_unscoped_or_stale_grants(
    tmp_path,
    fake_enterprise_secret,
    grant,
    reason,
):
    broker = FakeSecretBroker(
        {"OPENAI_API_KEY": fake_enterprise_secret},
        audit_store=AuditStore(tmp_path / "audit.sqlite3"),
    )

    with pytest.raises(SecretAccessDenied, match=reason):
        broker.issue_credential(_request(), grant=grant)


def test_secret_broker_reference_does_not_leak_raw_secret_to_governed_boundaries(
    tmp_path,
    monkeypatch,
    enterprise_enabled_config,
    fake_enterprise_secret,
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")
    broker = FakeSecretBroker({"OPENAI_API_KEY": fake_enterprise_secret}, audit_store=audit)
    credential = broker.issue_credential(_request(), grant=_grant())
    reference = credential_reference(credential)

    session_message = make_tool_result_message(
        "secret_lookup",
        {
            "credential": reference,
            "raw_secret": fake_enterprise_secret,
        },
        "call-secret",
        root_config=enterprise_enabled_config,
    )
    provider_payload, provider_decision = govern_provider_payload(
        {
            "model": "gpt-test",
            "messages": [
                {"role": "user", "content": f"use {reference['broker_uri']}"},
                {"role": "tool", "content": f"raw leak attempt {fake_enterprise_secret}"},
            ],
        },
        root_config=enterprise_enabled_config,
        audit_store=audit,
        route="secret-broker-boundary",
    )

    assert fake_enterprise_secret not in _serialized(reference)
    assert fake_enterprise_secret not in _serialized(session_message)
    assert fake_enterprise_secret not in _serialized(provider_payload)
    assert fake_enterprise_secret not in _serialized(audit.list_events())
    assert reference["broker_uri"] in _serialized(session_message)
    assert provider_decision.changed is True
