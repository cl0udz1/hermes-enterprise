"""Access grant lifecycle for enterprise staged approvals."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from enterprise.audit import AuditStore
from enterprise.contracts import (
    AccessGrant,
    AuditEvent,
    AuditEventType,
    StageStatus,
    StagedExecutionRecord,
    stable_hash,
    stable_json,
)
from enterprise.staging import StageStore
from enterprise.triage.detectors import SECRET_PATTERNS
from hermes_constants import get_hermes_home


class AccessGrantStore:
    """Local SQLite store for scoped approval grants."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = get_hermes_home() / "enterprise" / "access" / "grants.sqlite3"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS access_grants (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    grant_id TEXT NOT NULL UNIQUE,
                    request_id TEXT NOT NULL,
                    stage_id TEXT NOT NULL,
                    action_hash TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    actions_json TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    approved_by TEXT NOT NULL DEFAULT '',
                    revoked_at TEXT NOT NULL DEFAULT '',
                    grant_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_access_grants_action
                ON access_grants(subject_id, action_hash, tool_name)
                """
            )

    def upsert_grant(self, grant: AccessGrant) -> int:
        actions_json = stable_json(list(grant.actions))
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                """
                INSERT INTO access_grants (
                    grant_id, request_id, stage_id, action_hash, subject_id,
                    tool_name, resource, actions_json, expires_at, policy_version,
                    created_at, approved_by, revoked_at, grant_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(grant_id) DO UPDATE SET
                    request_id = excluded.request_id,
                    stage_id = excluded.stage_id,
                    action_hash = excluded.action_hash,
                    subject_id = excluded.subject_id,
                    tool_name = excluded.tool_name,
                    resource = excluded.resource,
                    actions_json = excluded.actions_json,
                    expires_at = excluded.expires_at,
                    policy_version = excluded.policy_version,
                    created_at = excluded.created_at,
                    approved_by = excluded.approved_by,
                    revoked_at = excluded.revoked_at,
                    grant_json = excluded.grant_json
                """,
                (
                    grant.grant_id,
                    grant.request_id,
                    grant.stage_id,
                    grant.action_hash,
                    grant.subject_id,
                    grant.tool_name,
                    grant.resource,
                    actions_json,
                    grant.expires_at,
                    grant.policy_version,
                    grant.created_at,
                    grant.approved_by,
                    grant.revoked_at,
                    grant.to_json(),
                ),
            )
            row = conn.execute(
                "SELECT sequence FROM access_grants WHERE grant_id = ?",
                (grant.grant_id,),
            ).fetchone()
        if row is not None:
            return int(row["sequence"])
        return int(cursor.lastrowid)

    def get_grant(self, grant_id: str) -> AccessGrant | None:
        with closing(self._connect()) as conn, conn:
            row = conn.execute(
                "SELECT grant_json FROM access_grants WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
        if row is None:
            return None
        return AccessGrant.from_json(row["grant_json"])

    def list_for_action(
        self,
        *,
        subject_id: str,
        action_hash: str,
        tool_name: str,
    ) -> list[AccessGrant]:
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(
                """
                SELECT grant_json FROM access_grants
                WHERE subject_id = ? AND action_hash = ? AND tool_name = ?
                ORDER BY sequence ASC
                """,
                (subject_id, action_hash, tool_name),
            ).fetchall()
        return [AccessGrant.from_json(row["grant_json"]) for row in rows]

    def list_grants(self, limit: int | None = None) -> list[AccessGrant]:
        query = "SELECT grant_json FROM access_grants ORDER BY sequence ASC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(query, params).fetchall()
        return [AccessGrant.from_json(row["grant_json"]) for row in rows]

    def approve_stage(
        self,
        stage_id: str,
        *,
        stage_store: StageStore | None = None,
        approved_by: str,
        expires_at: str | None = None,
        ttl_minutes: int = 30,
        policy_version: str = "local",
        reason: str = "",
        audit_store: AuditStore | None = None,
    ) -> AccessGrant:
        stages = stage_store or StageStore()
        record = stages.get_record(stage_id)
        if record is None:
            raise KeyError(f"Staged execution not found: {stage_id}")
        expires = expires_at or (datetime.now(timezone.utc) + timedelta(minutes=max(1, int(ttl_minutes)))).isoformat()
        grant = build_access_grant(
            record,
            approved_by=approved_by,
            expires_at=expires,
            policy_version=policy_version,
        )
        self.upsert_grant(grant)
        stages.set_status(stage_id, StageStatus.APPROVED, approved_by=approved_by)
        _append_grant_event(
            audit_store or AuditStore(),
            grant,
            event_type=AuditEventType.ACTION_APPROVED,
            reason=reason,
        )
        return grant

    def revoke_grant(
        self,
        grant_id: str,
        *,
        revoked_by: str,
        revoked_at: str | None = None,
        audit_store: AuditStore | None = None,
    ) -> AccessGrant | None:
        grant = self.get_grant(grant_id)
        if grant is None:
            return None
        revoked = AccessGrant(
            grant_id=grant.grant_id,
            request_id=grant.request_id,
            subject_id=grant.subject_id,
            resource=grant.resource,
            actions=list(grant.actions),
            expires_at=grant.expires_at,
            policy_version=grant.policy_version,
            created_at=grant.created_at,
            revoked_at=revoked_at or datetime.now(timezone.utc).isoformat(),
            approved_by=grant.approved_by,
            stage_id=grant.stage_id,
            action_hash=grant.action_hash,
            tool_name=grant.tool_name,
        )
        self.upsert_grant(revoked)
        _append_grant_event(
            audit_store or AuditStore(),
            revoked,
            event_type=AuditEventType.ACCESS_GRANT_REVOKED,
            actor_id=revoked_by,
        )
        return revoked

    def count(self) -> int:
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM access_grants").fetchone()
        return int(row["count"])


def build_access_grant(
    record: StagedExecutionRecord,
    *,
    approved_by: str,
    expires_at: str,
    policy_version: str = "local",
    actions: Iterable[str] = ("execute",),
    created_at: str | None = None,
) -> AccessGrant:
    """Create a scoped grant bound to one staged action hash."""

    action_list = list(dict.fromkeys([record.tool_name, *[str(action) for action in actions]]))
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    grant_id = stable_hash(
        {
            "stage_id": record.stage_id,
            "action_hash": record.action_hash,
            "subject_id": record.subject_id,
            "tool_name": record.tool_name,
            "approved_by": approved_by,
            "expires_at": expires_at,
            "policy_version": policy_version,
            "actions": action_list,
        }
    )[:32]
    return AccessGrant(
        grant_id=grant_id,
        request_id=record.stage_id,
        subject_id=record.subject_id,
        resource=record.action_hash,
        actions=action_list,
        expires_at=expires_at,
        policy_version=policy_version,
        created_at=timestamp,
        approved_by=approved_by,
        stage_id=record.stage_id,
        action_hash=record.action_hash,
        tool_name=record.tool_name,
    )


def _append_grant_event(
    audit_store: AuditStore,
    grant: AccessGrant,
    *,
    event_type: AuditEventType,
    actor_id: str = "",
    reason: str = "",
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": event_type.value,
            "grant_id": grant.grant_id,
            "created_at": created_at,
        }
    )[:32]
    raw_sha256 = stable_hash(grant.to_dict())
    metadata: dict[str, Any] = {
        "grant_id": grant.grant_id,
        "request_id": grant.request_id,
        "stage_id": grant.stage_id,
        "action_hash": grant.action_hash,
        "tool_name": grant.tool_name,
        "expires_at": grant.expires_at,
        "policy_version": grant.policy_version,
        "approved_by": grant.approved_by,
        "revoked_at": grant.revoked_at,
    }
    if actor_id:
        metadata["actor_id"] = actor_id
    if reason:
        metadata["operator_reason"] = _safe_operator_text(reason)
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=event_type,
            subject_id=grant.subject_id,
            action_id=grant.action_hash,
            decision_id=grant.grant_id,
            redacted_preview=f"{event_type.value} grant={grant.grant_id} stage={grant.stage_id}",
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata=metadata,
        )
    )
    return (event_id,)


def _safe_operator_text(value: str, *, limit: int = 500) -> str:
    redacted = " ".join(str(value).split())
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    if len(redacted) > limit:
        return f"{redacted[:limit]}..."
    return redacted


def grants_for_action(
    store: AccessGrantStore,
    *,
    subject_id: str,
    action_hash: str,
    tool_name: str,
) -> tuple[AccessGrant, ...]:
    return tuple(
        grant
        for grant in store.list_for_action(
            subject_id=subject_id,
            action_hash=action_hash,
            tool_name=tool_name,
        )
        if grant.resource == action_hash
        and grant.action_hash == action_hash
        and grant.subject_id == subject_id
        and grant.tool_name == tool_name
    )
