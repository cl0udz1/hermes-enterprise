"""Tests for enterprise staged execution v0."""

from __future__ import annotations

import json

from enterprise.audit import AuditStore
from enterprise.contracts import (
    DecisionOutcome,
    RiskTier,
    RuntimeTriageDecision,
    StageStatus,
    stable_json,
)
from enterprise.firewall.action import evaluate_tool_call
from enterprise.staging import StageStore, build_staged_execution_record, should_stage_action


FAKE_OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"


def _triage(outcome: DecisionOutcome = DecisionOutcome.APPROVAL_REQUIRED) -> RuntimeTriageDecision:
    return RuntimeTriageDecision(
        decision_id="decision-stage-1",
        outcome=outcome,
        risk_tier=RiskTier.CRITICAL,
        detectors=["manifest:approval_required"],
        latency_ms=1,
        escalated=False,
        reason="high-risk side effect",
    )


def test_staged_execution_record_has_deterministic_binding():
    left, left_preview = build_staged_execution_record(
        subject_id="employee-1",
        tool_name="terminal",
        tool_args={"command": "echo hello"},
        action_hash="actionhash",
        triage_decision=_triage(),
        requested_side_effects=("process_spawn",),
        created_at="2026-05-20T00:00:00+00:00",
    )
    right, right_preview = build_staged_execution_record(
        subject_id="employee-1",
        tool_name="terminal",
        tool_args={"command": "echo hello"},
        action_hash="actionhash",
        triage_decision=_triage(),
        requested_side_effects=("process_spawn",),
        created_at="2026-05-20T00:00:00+00:00",
    )

    assert left == right
    assert left_preview == right_preview
    assert left.status is StageStatus.STAGED
    assert left.preview_uri == f"stage://{left.stage_id}/preview"


def test_stage_store_upserts_record_and_preview(tmp_path):
    store = StageStore(tmp_path / "staged.sqlite3")
    record, preview = build_staged_execution_record(
        subject_id="employee-1",
        tool_name="write_file",
        tool_args={"path": "README.md", "content": "not stored in preview"},
        action_hash="actionhash",
        triage_decision=_triage(),
        requested_side_effects=("filesystem_write",),
        created_at="2026-05-20T00:00:00+00:00",
    )

    first_sequence = store.upsert_record(record, preview)
    second_sequence = store.upsert_record(record, preview)

    assert first_sequence == second_sequence
    assert store.count() == 1
    assert store.get_record(record.stage_id) == record
    stored_preview = store.get_preview(record.stage_id)
    assert stored_preview is not None
    assert stored_preview["safe_args"] == {"path": "README.md"}
    assert "not stored in preview" not in stable_json(stored_preview)


def test_action_firewall_stages_approval_required_tool_and_audits(tmp_path):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")

    decision = evaluate_tool_call(
        "terminal",
        {"command": "echo hello"},
        root_config={"enterprise": {"enabled": True}},
        audit_store=audit,
        stage_store=stages,
        task_id="task-1",
        tool_call_id="call-1",
    )

    assert decision.allows_execution is False
    assert decision.staged_record is not None
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
    assert stages.count() == 1
    assert audit.count() == 3

    payload = json.loads(decision.tool_result)
    assert payload["error"] == "Enterprise action firewall staged this action for approval before execution."
    assert payload["enterprise"]["stage"]["stage_id"] == decision.staged_record.stage_id
    assert payload["enterprise"]["stage"]["preview_uri"] == decision.staged_record.preview_uri
    assert payload["enterprise"]["stage"]["idempotency_key"] == decision.staged_record.idempotency_key

    stored_record = stages.get_record(decision.staged_record.stage_id)
    assert stored_record == decision.staged_record
    assert stored_record is not None
    assert stored_record.action_hash == decision.action_hash

    events = audit.list_events()
    assert [event.event_type.value for event in events] == [
        "action_proposed",
        "policy_decision",
        "action_staged",
    ]
    assert events[-1].metadata["stage_id"] == decision.staged_record.stage_id


def test_staging_failure_fails_closed_for_high_risk_action(tmp_path):
    class FailingStageStore:
        def upsert_record(self, _record, _preview):
            raise RuntimeError("staging db unavailable")

    audit = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_tool_call(
        "terminal",
        {"command": "echo hello"},
        root_config={"enterprise": {"enabled": True}},
        audit_store=audit,
        stage_store=FailingStageStore(),
        task_id="task-fail",
        tool_call_id="call-fail",
    )

    assert decision.allows_execution is False
    assert decision.staged_record is None
    payload = json.loads(decision.tool_result)
    assert payload["error"] == "Enterprise action firewall could not stage this high-risk action; execution was denied."
    assert payload["enterprise"]["staging_error"] == "staging db unavailable"
    assert audit.count() == 2
    assert audit.list_events()[-1].metadata["staging_error"] == "staging db unavailable"


def test_unstageable_low_risk_decision_does_not_stage():
    assert should_stage_action(
        _triage(DecisionOutcome.ALLOW),
        requested_side_effects=("user_prompt",),
    ) is False


def test_stage_preview_redacts_secret_like_values():
    _record, preview = build_staged_execution_record(
        subject_id="employee-1",
        tool_name="terminal",
        tool_args={"command": f"export OPENAI_API_KEY={FAKE_OPENAI_KEY}"},
        action_hash="actionhash",
        triage_decision=_triage(),
        requested_side_effects=("process_spawn",),
        created_at="2026-05-20T00:00:00+00:00",
    )

    serialized = stable_json(preview)
    assert FAKE_OPENAI_KEY not in serialized
    assert "[REDACTED:openai_key]" in serialized
