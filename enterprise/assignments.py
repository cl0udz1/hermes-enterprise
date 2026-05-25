"""Agent assignment records for enterprise managed fleets."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from enterprise.audit import AuditStore
from enterprise.contracts import (
    AgentAssignmentRecord,
    AssignmentStatus,
    AuditEvent,
    AuditEventType,
    stable_hash,
)
from enterprise.triage.detectors import SECRET_PATTERNS
from hermes_constants import get_default_hermes_root


DEFAULT_ALLOWED_SURFACES = ("dashboard", "cli", "tui", "gateway")
MAX_REASON_LENGTH = 500


class AgentAssignmentStore:
    """Root-scoped SQLite store for managed agent assignments.

    The store is anchored to the default Hermes root, not the active profile,
    because assignments govern the whole profile fleet.
    """

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = get_default_hermes_root() / "enterprise" / "assignments" / "assignments.sqlite3"
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
                CREATE TABLE IF NOT EXISTS agent_assignments (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    assignment_id TEXT NOT NULL UNIQUE,
                    subject_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL DEFAULT '',
                    revoked_at TEXT NOT NULL DEFAULT '',
                    record_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_agent_assignments_subject
                ON agent_assignments(subject_id, status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_agent_assignments_profile
                ON agent_assignments(profile_id, status)
                """
            )

    def upsert(self, record: AgentAssignmentRecord) -> int:
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                """
                INSERT INTO agent_assignments (
                    assignment_id, subject_id, agent_id, profile_id, role,
                    status, assigned_by, created_at, expires_at, revoked_at,
                    record_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(assignment_id) DO UPDATE SET
                    subject_id = excluded.subject_id,
                    agent_id = excluded.agent_id,
                    profile_id = excluded.profile_id,
                    role = excluded.role,
                    status = excluded.status,
                    assigned_by = excluded.assigned_by,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    revoked_at = excluded.revoked_at,
                    record_json = excluded.record_json
                """,
                (
                    record.assignment_id,
                    record.subject_id,
                    record.agent_id,
                    record.profile_id,
                    record.role,
                    record.status.value,
                    record.assigned_by,
                    record.created_at,
                    record.expires_at,
                    record.revoked_at,
                    record.to_json(),
                ),
            )
            row = conn.execute(
                "SELECT sequence FROM agent_assignments WHERE assignment_id = ?",
                (record.assignment_id,),
            ).fetchone()
        if row is not None:
            return int(row["sequence"])
        return int(cursor.lastrowid)

    def create(
        self,
        *,
        subject_id: str,
        agent_id: str,
        profile_id: str,
        role: str,
        assigned_by: str,
        assignment_reason: str,
        allowed_surfaces: list[str] | tuple[str, ...] | None = None,
        workspace_scope: list[str] | tuple[str, ...] | None = None,
        tool_policy: list[str] | tuple[str, ...] | None = None,
        memory_scope: list[str] | tuple[str, ...] | None = None,
        expires_at: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AgentAssignmentRecord:
        record = build_assignment_record(
            subject_id=subject_id,
            agent_id=agent_id,
            profile_id=profile_id,
            role=role,
            assigned_by=assigned_by,
            assignment_reason=assignment_reason,
            allowed_surfaces=list(allowed_surfaces or DEFAULT_ALLOWED_SURFACES),
            workspace_scope=list(workspace_scope or []),
            tool_policy=list(tool_policy or []),
            memory_scope=list(memory_scope or []),
            expires_at=expires_at,
            metadata=metadata or {},
        )
        self.upsert(record)
        return record

    def get(self, assignment_id: str) -> AgentAssignmentRecord | None:
        with closing(self._connect()) as conn, conn:
            row = conn.execute(
                "SELECT record_json FROM agent_assignments WHERE assignment_id = ?",
                (assignment_id,),
            ).fetchone()
        if row is None:
            return None
        return AgentAssignmentRecord.from_json(row["record_json"])

    def list(self, limit: int | None = None) -> list[AgentAssignmentRecord]:
        query = "SELECT record_json FROM agent_assignments ORDER BY sequence ASC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(query, params).fetchall()
        return [AgentAssignmentRecord.from_json(row["record_json"]) for row in rows]

    def revoke(
        self,
        assignment_id: str,
        *,
        revoked_by: str,
        revoked_at: str | None = None,
    ) -> AgentAssignmentRecord | None:
        record = self.get(assignment_id)
        if record is None:
            return None
        revoked = AgentAssignmentRecord(
            assignment_id=record.assignment_id,
            subject_id=record.subject_id,
            agent_id=record.agent_id,
            profile_id=record.profile_id,
            role=record.role,
            status=AssignmentStatus.REVOKED,
            assigned_by=record.assigned_by,
            assignment_reason=record.assignment_reason,
            allowed_surfaces=list(record.allowed_surfaces),
            workspace_scope=list(record.workspace_scope),
            tool_policy=list(record.tool_policy),
            memory_scope=list(record.memory_scope),
            created_at=record.created_at,
            expires_at=record.expires_at,
            revoked_at=revoked_at or datetime.now(timezone.utc).isoformat(),
            metadata={**record.metadata, "revoked_by": _safe_text(revoked_by)},
        )
        self.upsert(revoked)
        return revoked

    def active_for_subject(
        self,
        subject_id: str,
        *,
        surface: str | None = None,
        now: datetime | None = None,
    ) -> list[AgentAssignmentRecord]:
        current = now or datetime.now(timezone.utc)
        active: list[AgentAssignmentRecord] = []
        for record in self.list():
            if record.subject_id != subject_id:
                continue
            if record.status is not AssignmentStatus.ACTIVE:
                continue
            if record.revoked_at:
                continue
            if record.expires_at and _parse_time(record.expires_at) <= current:
                continue
            if surface and surface not in record.allowed_surfaces:
                continue
            active.append(record)
        return active


def build_assignment_record(
    *,
    subject_id: str,
    agent_id: str,
    profile_id: str,
    role: str,
    assigned_by: str,
    assignment_reason: str,
    allowed_surfaces: list[str],
    workspace_scope: list[str],
    tool_policy: list[str],
    memory_scope: list[str],
    expires_at: str = "",
    metadata: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> AgentAssignmentRecord:
    subject = _required_id("subject_id", subject_id)
    agent = _required_id("agent_id", agent_id)
    profile = _normalize_profile_id(profile_id)
    operator = _required_id("assigned_by", assigned_by)
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    assignment_id = stable_hash(
        {
            "subject_id": subject,
            "agent_id": agent,
            "profile_id": profile,
            "role": _normalize_role(role),
            "created_at": timestamp,
            "assigned_by": operator,
        }
    )[:32]
    return AgentAssignmentRecord(
        assignment_id=assignment_id,
        subject_id=subject,
        agent_id=agent,
        profile_id=profile,
        role=_normalize_role(role),
        status=AssignmentStatus.ACTIVE,
        assigned_by=operator,
        assignment_reason=_safe_text(assignment_reason),
        allowed_surfaces=_clean_list(allowed_surfaces) or list(DEFAULT_ALLOWED_SURFACES),
        workspace_scope=_clean_list(workspace_scope),
        tool_policy=_clean_list(tool_policy),
        memory_scope=_clean_list(memory_scope),
        created_at=timestamp,
        expires_at=str(expires_at or ""),
        metadata=dict(metadata or {}),
    )


def assignment_to_summary(
    record: AgentAssignmentRecord,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    status = record.status.value
    if status == AssignmentStatus.ACTIVE.value and record.expires_at and _parse_time(record.expires_at) <= current:
        status = AssignmentStatus.EXPIRED.value
    return {
        "assignment_id": record.assignment_id,
        "subject_id": record.subject_id,
        "agent_id": record.agent_id,
        "profile_id": record.profile_id,
        "role": record.role,
        "status": status,
        "assigned_by": record.assigned_by,
        "assignment_reason": record.assignment_reason,
        "allowed_surfaces": list(record.allowed_surfaces),
        "workspace_scope": list(record.workspace_scope),
        "tool_policy": list(record.tool_policy),
        "memory_scope": list(record.memory_scope),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
    }


def assignment_counts(records: list[AgentAssignmentRecord], *, now: datetime | None = None) -> dict[str, int]:
    counts = {"active": 0, "paused": 0, "revoked": 0, "expired": 0, "total": len(records)}
    current = now or datetime.now(timezone.utc)
    for record in records:
        status = record.status.value
        if status == AssignmentStatus.ACTIVE.value and record.expires_at and _parse_time(record.expires_at) <= current:
            status = AssignmentStatus.EXPIRED.value
        counts[status] = counts.get(status, 0) + 1
    return counts


def append_assignment_audit_event(
    audit_store: AuditStore,
    record: AgentAssignmentRecord,
    *,
    event_type: AuditEventType,
    actor_id: str = "",
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": event_type.value,
            "assignment_id": record.assignment_id,
            "created_at": created_at,
        }
    )[:32]
    metadata: dict[str, Any] = {
        "assignment_id": record.assignment_id,
        "agent_id": record.agent_id,
        "profile_id": record.profile_id,
        "role": record.role,
        "status": record.status.value,
        "allowed_surfaces": list(record.allowed_surfaces),
        "workspace_scope": list(record.workspace_scope),
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
    }
    if actor_id:
        metadata["actor_id"] = _safe_text(actor_id)
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=event_type,
            subject_id=record.subject_id,
            action_id=record.assignment_id,
            decision_id=record.assignment_id,
            redacted_preview=f"{event_type.value} assignment={record.assignment_id} profile={record.profile_id}",
            raw_sha256=stable_hash(record.to_dict()),
            created_at=created_at,
            metadata=metadata,
        )
    )
    return (event_id,)


def _required_id(label: str, value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    if len(normalized) > 128:
        raise ValueError(f"{label} is too long")
    return normalized


def _normalize_profile_id(value: str) -> str:
    normalized = str(value or "default").strip().lower() or "default"
    if normalized == "default":
        return normalized
    if not all(ch.isalnum() or ch in {"_", "-"} for ch in normalized):
        raise ValueError("profile_id must be a Hermes profile id")
    return normalized


def _normalize_role(value: str) -> str:
    normalized = str(value or "employee").strip().lower().replace(" ", "_")
    return normalized or "employee"


def _clean_list(values: list[str] | tuple[str, ...]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if item and item not in cleaned:
            cleaned.append(item)
    return cleaned


def _safe_text(value: str, *, limit: int = MAX_REASON_LENGTH) -> str:
    redacted = " ".join(str(value or "").split())
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    if len(redacted) > limit:
        return f"{redacted[:limit]}..."
    return redacted


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
