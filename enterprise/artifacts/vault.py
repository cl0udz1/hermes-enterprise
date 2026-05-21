"""Local artifact vault for enterprise evidence and hydration tests."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from enterprise.contracts import ArtifactVaultRecord, stable_hash, stable_json
from enterprise.triage.detectors import SECRET_PATTERNS
from hermes_constants import get_hermes_home


DEFAULT_PREVIEW_CHARS = 500


class ArtifactVault:
    """SQLite-backed artifact store.

    MVP-0 stores text artifacts locally and exposes only records/URIs until the
    hydration boundary explicitly releases a permitted view.
    """

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = get_hermes_home() / "enterprise" / "artifacts" / "vault.sqlite3"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id TEXT NOT NULL UNIQUE,
                    data_class TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    redacted_preview TEXT NOT NULL,
                    storage_uri TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    content_text TEXT NOT NULL,
                    record_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_artifacts_data_class
                ON artifacts(data_class)
                """
            )

    def put_artifact(
        self,
        *,
        content: str | bytes,
        data_class: str,
        metadata: Mapping[str, Any] | None = None,
        redacted_preview: str | None = None,
        created_at: str | None = None,
    ) -> ArtifactVaultRecord:
        """Store an artifact and return its vault record."""
        metadata_dict = dict(metadata or {})
        content_text, content_bytes = _normalize_content(content)
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        metadata_dict.setdefault("content_size_bytes", len(content_bytes))
        artifact_id = stable_hash(
            {
                "data_class": data_class,
                "content_sha256": content_sha256,
                "metadata": metadata_dict,
            }
        )[:32]
        timestamp = created_at or datetime.now(timezone.utc).isoformat()
        preview_source = redacted_preview or str(metadata_dict.get("summary") or content_text)
        preview = _redact_and_truncate(preview_source, DEFAULT_PREVIEW_CHARS)
        record = ArtifactVaultRecord(
            artifact_id=artifact_id,
            data_class=str(data_class),
            content_sha256=content_sha256,
            redacted_preview=preview,
            storage_uri=f"artifact://{artifact_id}",
            created_at=timestamp,
            metadata=metadata_dict,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, data_class, content_sha256, redacted_preview,
                    storage_uri, created_at, metadata_json, content_text, record_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET
                    data_class = excluded.data_class,
                    content_sha256 = excluded.content_sha256,
                    redacted_preview = excluded.redacted_preview,
                    storage_uri = excluded.storage_uri,
                    created_at = excluded.created_at,
                    metadata_json = excluded.metadata_json,
                    content_text = excluded.content_text,
                    record_json = excluded.record_json
                """,
                (
                    record.artifact_id,
                    record.data_class,
                    record.content_sha256,
                    record.redacted_preview,
                    record.storage_uri,
                    record.created_at,
                    stable_json(metadata_dict),
                    content_text,
                    record.to_json(),
                ),
            )
        return record

    def get_record(self, artifact_id: str) -> ArtifactVaultRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT record_json FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            return None
        return ArtifactVaultRecord.from_json(row["record_json"])

    def read_content(self, artifact_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT content_text FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            return None
        return str(row["content_text"])

    def list_records(self, limit: int | None = None) -> list[ArtifactVaultRecord]:
        query = "SELECT record_json FROM artifacts ORDER BY sequence ASC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [ArtifactVaultRecord.from_json(row["record_json"]) for row in rows]

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM artifacts").fetchone()
        return int(row["count"])


def _normalize_content(content: str | bytes) -> tuple[str, bytes]:
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace"), content
    content_text = str(content)
    return content_text, content_text.encode("utf-8")


def _redact_and_truncate(value: str, budget_chars: int) -> str:
    redacted = value
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    if len(redacted) > budget_chars:
        return f"{redacted[:budget_chars]}..."
    return redacted
