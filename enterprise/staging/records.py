"""Staged execution records for approval-required enterprise actions.

MVP-0 staging is deliberately narrow: it records deterministic previews and
idempotency keys before execution. It does not claim rollback or execute
approved actions yet.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from enterprise.contracts import (
    DecisionOutcome,
    RiskTier,
    RuntimeTriageDecision,
    StageStatus,
    StagedExecutionRecord,
    stable_hash,
    stable_json,
)
from enterprise.manifests.schema import ToolCapability
from enterprise.triage.detectors import SECRET_PATTERNS
from hermes_constants import get_hermes_home


STAGEABLE_SIDE_EFFECTS = frozenset(
    {
        "filesystem_write",
        "process_spawn",
        "code_execution",
        "external_send",
        "scheduled_execution",
        "agent_delegation",
        "memory_write",
        "provider_egress",
        "browser_state",
    }
)

PREVIEW_ARG_KEYS = frozenset(
    {
        "command",
        "cmd",
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "target",
        "target_path",
        "directory",
        "cwd",
        "workdir",
        "working_directory",
        "url",
        "urls",
        "uri",
        "endpoint",
        "host",
        "query",
    }
)

MAX_PREVIEW_TEXT = 500


class StageStore:
    """Local SQLite store for staged execution records and previews."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = get_hermes_home() / "enterprise" / "staging" / "staged.sqlite3"
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
                CREATE TABLE IF NOT EXISTS staged_executions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    stage_id TEXT NOT NULL UNIQUE,
                    action_hash TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    preview_uri TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    approved_by TEXT NOT NULL DEFAULT '',
                    preview_json TEXT NOT NULL,
                    record_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_staged_executions_action_hash
                ON staged_executions(action_hash)
                """
            )

    def upsert_record(self, record: StagedExecutionRecord, preview: Mapping[str, Any]) -> int:
        """Create or update a staged record and return its row sequence."""
        preview_json = stable_json(dict(preview))
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO staged_executions (
                    stage_id, action_hash, subject_id, tool_name, preview_uri,
                    idempotency_key, status, created_at, approved_by,
                    preview_json, record_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stage_id) DO UPDATE SET
                    action_hash = excluded.action_hash,
                    subject_id = excluded.subject_id,
                    tool_name = excluded.tool_name,
                    preview_uri = excluded.preview_uri,
                    idempotency_key = excluded.idempotency_key,
                    status = excluded.status,
                    created_at = excluded.created_at,
                    approved_by = excluded.approved_by,
                    preview_json = excluded.preview_json,
                    record_json = excluded.record_json
                """,
                (
                    record.stage_id,
                    record.action_hash,
                    record.subject_id,
                    record.tool_name,
                    record.preview_uri,
                    record.idempotency_key,
                    record.status.value,
                    record.created_at,
                    record.approved_by,
                    preview_json,
                    record.to_json(),
                ),
            )
            row = conn.execute(
                "SELECT sequence FROM staged_executions WHERE stage_id = ?",
                (record.stage_id,),
            ).fetchone()
        if row is not None:
            return int(row["sequence"])
        return int(cursor.lastrowid)

    def get_record(self, stage_id: str) -> StagedExecutionRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT record_json FROM staged_executions WHERE stage_id = ?",
                (stage_id,),
            ).fetchone()
        if row is None:
            return None
        return StagedExecutionRecord.from_json(row["record_json"])

    def get_by_action_hash(self, action_hash: str) -> list[StagedExecutionRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT record_json FROM staged_executions
                WHERE action_hash = ?
                ORDER BY sequence ASC
                """,
                (action_hash,),
            ).fetchall()
        return [StagedExecutionRecord.from_json(row["record_json"]) for row in rows]

    def get_preview(self, stage_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT preview_json FROM staged_executions WHERE stage_id = ?",
                (stage_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["preview_json"])

    def list_records(self, limit: int | None = None) -> list[StagedExecutionRecord]:
        query = "SELECT record_json FROM staged_executions ORDER BY sequence ASC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [StagedExecutionRecord.from_json(row["record_json"]) for row in rows]

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM staged_executions").fetchone()
        return int(row["count"])


def should_stage_action(
    triage_decision: RuntimeTriageDecision,
    *,
    capability: ToolCapability | None = None,
    requested_side_effects: Iterable[str] = (),
) -> bool:
    """Return whether an approval-required action has a v0 staging path."""
    if triage_decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
        return False
    effects = {str(effect) for effect in requested_side_effects}
    if not effects and capability is not None:
        effects = set(capability.side_effects)
    if not effects.intersection(STAGEABLE_SIDE_EFFECTS):
        return False
    if capability is not None and capability.approval_required:
        return True
    return triage_decision.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}


def build_staged_execution_record(
    *,
    subject_id: str,
    tool_name: str,
    tool_args: Mapping[str, Any],
    action_hash: str,
    triage_decision: RuntimeTriageDecision,
    requested_side_effects: Iterable[str] = (),
    capability: ToolCapability | None = None,
    created_at: str | None = None,
) -> tuple[StagedExecutionRecord, dict[str, Any]]:
    """Build a deterministic staged record plus a redacted approval preview."""
    effects = tuple(dict.fromkeys(str(effect) for effect in requested_side_effects))
    if not effects and capability is not None:
        effects = tuple(capability.side_effects)
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    idempotency_key = stable_hash(
        {
            "action_hash": action_hash,
            "subject_id": subject_id,
            "tool_name": tool_name,
            "requested_side_effects": list(effects),
        }
    )
    stage_id = stable_hash(
        {
            "idempotency_key": idempotency_key,
            "action_hash": action_hash,
        }
    )[:32]
    preview_uri = f"stage://{stage_id}/preview"
    preview = {
        "schema_version": 1,
        "stage_id": stage_id,
        "action_hash": action_hash,
        "subject_id": subject_id,
        "tool_name": tool_name,
        "risk_tier": triage_decision.risk_tier.value,
        "outcome": triage_decision.outcome.value,
        "decision_id": triage_decision.decision_id,
        "detectors": list(triage_decision.detectors),
        "requested_side_effects": list(effects),
        "arg_keys": sorted(str(key) for key in tool_args.keys()),
        "safe_args": _safe_args_preview(tool_args),
        "created_at": timestamp,
    }
    if capability is not None:
        preview["sandbox_profile"] = capability.sandbox_profile
        preview["data_classes"] = list(capability.data_classes)
    record = StagedExecutionRecord(
        stage_id=stage_id,
        action_hash=action_hash,
        subject_id=subject_id,
        tool_name=tool_name,
        preview_uri=preview_uri,
        idempotency_key=idempotency_key,
        status=StageStatus.STAGED,
        created_at=timestamp,
    )
    return record, preview


def _safe_args_preview(value: Mapping[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, item in value.items():
        normalized = str(key)
        if normalized.lower() in PREVIEW_ARG_KEYS:
            safe[normalized] = _safe_preview_value(item)
    return safe


def _safe_preview_value(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, Path):
        return _redact_and_truncate(str(value))
    if isinstance(value, str):
        return _redact_and_truncate(value)
    if isinstance(value, Mapping):
        return {
            str(key): _safe_preview_value(item)
            for key, item in value.items()
            if str(key).lower() in PREVIEW_ARG_KEYS
        }
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return [_safe_preview_value(item) for item in value]
    return _redact_and_truncate(str(value))


def _redact_and_truncate(value: str) -> str:
    redacted = value
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    if len(redacted) > MAX_PREVIEW_TEXT:
        return f"{redacted[:MAX_PREVIEW_TEXT]}..."
    return redacted
