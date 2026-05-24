"""Fake secret broker for MVP-1 credential lifecycle tests.

The broker deliberately issues opaque credential metadata, not raw secret
values. Real vault/KMS integration belongs behind the same contracts later.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from enterprise.audit import AuditStore
from enterprise.contracts import (
    AccessGrant,
    AuditEvent,
    AuditEventType,
    IssuedCredential,
    SecretAccessRequest,
    stable_hash,
)


SECRET_ISSUE_ACTION = "secret:issue"


class SecretBrokerError(Exception):
    """Base class for secret broker failures."""


class SecretAccessDenied(SecretBrokerError):
    """Raised when a secret request has no valid policy grant."""


class FakeSecretBroker:
    """In-memory broker that proves lifecycle behavior without real KMS."""

    def __init__(
        self,
        secrets: Mapping[str, str] | None = None,
        *,
        audit_store: AuditStore | None = None,
        now: datetime | None = None,
    ):
        self._secrets = dict(secrets or {})
        self._issued: dict[str, IssuedCredential] = {}
        self._audit_store = audit_store
        self._now = now

    def register_secret(self, secret_name: str, secret_value: str) -> None:
        self._secrets[str(secret_name)] = str(secret_value)

    def issue_credential(
        self,
        request: SecretAccessRequest,
        *,
        grant: AccessGrant | None,
        ttl_minutes: int = 5,
        max_ttl_minutes: int = 60,
        audit_store: AuditStore | None = None,
    ) -> IssuedCredential:
        """Issue an opaque, scoped credential only when a grant permits it."""

        store = audit_store or self._audit_store
        _append_secret_event(
            store,
            event_type=AuditEventType.SECRET_ACCESS_REQUESTED,
            request=request,
            grant=grant,
            reason="secret access requested",
        )

        denial_reason = self._denial_reason(request, grant)
        if denial_reason:
            _append_secret_event(
                store,
                event_type=AuditEventType.SECRET_ACCESS_DENIED,
                request=request,
                grant=grant,
                reason=denial_reason,
            )
            raise SecretAccessDenied(denial_reason)

        secret_value = self._secrets[request.secret_name]
        now = self._current_time()
        ttl = min(max(1, int(ttl_minutes)), max(1, int(max_ttl_minutes)))
        expires_at = (now + timedelta(minutes=ttl)).isoformat()
        secret_value_sha256 = stable_hash(
            {
                "secret_name": request.secret_name,
                "secret_value": secret_value,
            }
        )
        credential_id = stable_hash(
            {
                "request_id": request.request_id,
                "subject_id": request.subject_id,
                "secret_name": request.secret_name,
                "scope": list(request.scope),
                "grant_id": grant.grant_id if grant else "",
                "expires_at": expires_at,
                "secret_value_sha256": secret_value_sha256,
            }
        )[:32]
        credential = IssuedCredential(
            credential_id=credential_id,
            request_id=request.request_id,
            subject_id=request.subject_id,
            secret_name=request.secret_name,
            broker_uri=f"broker://credential/{credential_id}",
            scope=list(dict.fromkeys(str(item) for item in request.scope)),
            expires_at=expires_at,
            policy_version=grant.policy_version if grant else request.policy_version,
            issued_at=now.isoformat(),
            approved_by=grant.approved_by if grant else "",
            access_grant_id=grant.grant_id if grant else "",
            secret_value_sha256=secret_value_sha256,
        )
        self._issued[credential_id] = credential
        _append_secret_event(
            store,
            event_type=AuditEventType.SECRET_CREDENTIAL_ISSUED,
            request=request,
            grant=grant,
            credential=credential,
            reason="opaque credential issued",
        )
        return credential

    def get_credential(self, credential_id: str) -> IssuedCredential | None:
        return self._issued.get(credential_id)

    def _denial_reason(self, request: SecretAccessRequest, grant: AccessGrant | None) -> str:
        if request.secret_name not in self._secrets:
            return "unknown_secret"
        if grant is None:
            return "missing_access_grant"
        if request.access_grant_id and request.access_grant_id != grant.grant_id:
            return "grant_id_mismatch"
        if grant.subject_id != request.subject_id:
            return "subject_mismatch"
        if grant.resource != secret_resource(request.secret_name):
            return "resource_mismatch"
        if SECRET_ISSUE_ACTION not in set(grant.actions):
            return "missing_secret_issue_action"
        if grant.revoked_at:
            return "grant_revoked"
        expires_at = _parse_time(grant.expires_at)
        if expires_at is None:
            return "grant_expiry_invalid"
        if expires_at <= self._current_time():
            return "grant_expired"
        return ""

    def _current_time(self) -> datetime:
        return self._now or datetime.now(timezone.utc)


def build_secret_access_request(
    *,
    subject_id: str,
    secret_name: str,
    purpose: str,
    scope: Iterable[str],
    requested_at: str | None = None,
    action_hash: str = "",
    access_grant_id: str = "",
    policy_version: str = "local",
) -> SecretAccessRequest:
    timestamp = requested_at or datetime.now(timezone.utc).isoformat()
    scope_list = list(dict.fromkeys(str(item) for item in scope))
    request_id = stable_hash(
        {
            "subject_id": subject_id,
            "secret_name": secret_name,
            "purpose": purpose,
            "scope": scope_list,
            "requested_at": timestamp,
            "action_hash": action_hash,
            "access_grant_id": access_grant_id,
            "policy_version": policy_version,
        }
    )[:32]
    return SecretAccessRequest(
        request_id=request_id,
        subject_id=subject_id,
        secret_name=secret_name,
        purpose=purpose,
        scope=scope_list,
        requested_at=timestamp,
        action_hash=action_hash,
        access_grant_id=access_grant_id,
        policy_version=policy_version,
    )


def credential_reference(credential: IssuedCredential) -> dict[str, Any]:
    """Return the safe prompt/tool reference for an issued credential."""

    return {
        "type": "enterprise_secret_credential",
        "credential_id": credential.credential_id,
        "broker_uri": credential.broker_uri,
        "secret_name": credential.secret_name,
        "scope": list(credential.scope),
        "expires_at": credential.expires_at,
    }


def secret_resource(secret_name: str) -> str:
    return f"secret://{secret_name}"


def _append_secret_event(
    audit_store: AuditStore | None,
    *,
    event_type: AuditEventType,
    request: SecretAccessRequest,
    grant: AccessGrant | None = None,
    credential: IssuedCredential | None = None,
    reason: str,
) -> tuple[str, ...]:
    if audit_store is None:
        return ()
    created_at = datetime.now(timezone.utc).isoformat()
    decision_id = credential.credential_id if credential is not None else request.request_id
    event_id = stable_hash(
        {
            "event_type": event_type.value,
            "request_id": request.request_id,
            "decision_id": decision_id,
            "created_at": created_at,
        }
    )[:32]
    metadata: dict[str, Any] = {
        "request_id": request.request_id,
        "secret_name": request.secret_name,
        "scope": list(request.scope),
        "purpose_hash": stable_hash(request.purpose),
        "action_hash": request.action_hash,
        "reason": reason,
    }
    if grant is not None:
        metadata.update(
            {
                "grant_id": grant.grant_id,
                "approved_by": grant.approved_by,
                "grant_expires_at": grant.expires_at,
                "policy_version": grant.policy_version,
            }
        )
    if credential is not None:
        metadata.update(
            {
                "credential_id": credential.credential_id,
                "broker_uri": credential.broker_uri,
                "credential_expires_at": credential.expires_at,
                "secret_value_sha256": credential.secret_value_sha256,
            }
        )
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=event_type,
            subject_id=request.subject_id,
            action_id=request.action_hash or request.request_id,
            decision_id=decision_id,
            redacted_preview=f"{event_type.value} secret={request.secret_name} scope={','.join(request.scope)}",
            raw_sha256=stable_hash(request.to_dict()),
            created_at=created_at,
            metadata=metadata,
        )
    )
    return (event_id,)


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
