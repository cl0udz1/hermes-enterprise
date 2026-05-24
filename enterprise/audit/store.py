"""Local SQLite audit store for enterprise events."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from enterprise.contracts import AuditEvent
from hermes_constants import get_hermes_home


class AuditStore:
    """Append-only local audit store for structured enterprise events."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = get_hermes_home() / "enterprise" / "audit" / "events.sqlite3"
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
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    action_id TEXT NOT NULL DEFAULT '',
                    decision_id TEXT NOT NULL DEFAULT '',
                    redacted_preview TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    event_json TEXT NOT NULL
                )
                """
            )

    def append_event(self, event: AuditEvent) -> int:
        """Append one audit event and return its sequence number."""
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, event_type, subject_id, action_id, decision_id,
                    redacted_preview, raw_sha256, created_at, event_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type.value,
                    event.subject_id,
                    event.action_id,
                    event.decision_id,
                    event.redacted_preview,
                    event.raw_sha256,
                    event.created_at,
                    event.to_json(),
                ),
            )
            return int(cursor.lastrowid)

    def list_events(self, limit: int | None = None) -> list[AuditEvent]:
        """Return events in append order."""
        query = "SELECT event_json FROM audit_events ORDER BY sequence ASC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(query, params).fetchall()
        return [AuditEvent.from_json(row["event_json"]) for row in rows]

    def get_event(self, event_id: str) -> AuditEvent | None:
        with closing(self._connect()) as conn, conn:
            row = conn.execute(
                "SELECT event_json FROM audit_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        return AuditEvent.from_json(row["event_json"])

    def count(self) -> int:
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()
        return int(row["count"])
