import pytest

from enterprise.contracts import (
    AccessGrant,
    AccessRequest,
    ActionManifest,
    ArtifactVaultRecord,
    AuditEvent,
    AuditEventType,
    ContextHydrationRequest,
    CronGovernanceDecision,
    CronIntentEnvelope,
    DecisionOutcome,
    EvaluationRunRecord,
    GovernanceChangeRecord,
    HydrationView,
    IntentEnvelope,
    IssuedCredential,
    PolicyDecision,
    RiskTier,
    RuntimeTriageDecision,
    SecretAccessRequest,
    StageStatus,
    StagedExecutionRecord,
    stable_hash,
)


def test_contracts_round_trip_to_stable_json():
    records = [
        IntentEnvelope(
            intent_id="intent-1",
            subject_id="user-1",
            session_id="session-1",
            purpose="local development",
            data_classes=["source"],
            created_at="2026-05-20T00:00:00Z",
        ),
        ActionManifest(
            action_id="action-1",
            tool_name="terminal",
            tool_args_hash="abc123",
            risk_tier=RiskTier.HIGH,
            side_effects=["process", "filesystem"],
            sandbox_profile="local-dev",
            requires_approval=True,
            created_at="2026-05-20T00:00:01Z",
        ),
        AuditEvent(
            event_id="event-1",
            event_type=AuditEventType.ACTION_PROPOSED,
            subject_id="user-1",
            action_id="action-1",
            redacted_preview="terminal command preview",
            raw_sha256="rawhash",
            created_at="2026-05-20T00:00:02Z",
            metadata={"risk": "high"},
        ),
        PolicyDecision(
            decision_id="decision-1",
            outcome=DecisionOutcome.APPROVAL_REQUIRED,
            reason="high risk action",
            policy_version="policy-1",
            action_hash="actionhash",
            expires_at="2026-05-20T01:00:00Z",
        ),
        CronIntentEnvelope(
            job_id="cron-1",
            owner_id="user-1",
            intent_hash="intenthash",
            expires_at="2026-05-21T00:00:00Z",
            policy_context_hash="policyhash",
            schedule_hash="schedulehash",
            created_at="2026-05-20T00:00:02Z",
        ),
        CronGovernanceDecision(
            decision_id="cron-decision-1",
            outcome=DecisionOutcome.ALLOW,
            reason="cron_intent_envelope_valid",
            job_id="cron-1",
            owner_id="user-1",
            intent_hash="intenthash",
            expires_at="2026-05-21T00:00:00Z",
            policy_context_hash="policyhash",
            schedule_hash="schedulehash",
        ),
        RuntimeTriageDecision(
            decision_id="triage-1",
            outcome=DecisionOutcome.ALLOW,
            risk_tier=RiskTier.LOW,
            detectors=["path_allow"],
            latency_ms=7,
            escalated=False,
            reason="owner workspace",
        ),
        AccessRequest(
            request_id="request-1",
            subject_id="user-1",
            resource="repo",
            action="write",
            reason="assigned project work",
            risk_tier=RiskTier.MODERATE,
            data_classes=["source"],
            requested_at="2026-05-20T00:00:03Z",
        ),
        AccessGrant(
            grant_id="grant-1",
            request_id="request-1",
            subject_id="user-1",
            resource="repo",
            actions=["read", "write"],
            expires_at="2026-05-20T02:00:00Z",
            policy_version="policy-1",
            created_at="2026-05-20T00:00:04Z",
            approved_by="manager-1",
            stage_id="stage-1",
            action_hash="actionhash",
            tool_name="write_file",
        ),
        SecretAccessRequest(
            request_id="secret-request-1",
            subject_id="user-1",
            secret_name="OPENAI_API_KEY",
            purpose="call approved provider",
            scope=["provider:openai"],
            requested_at="2026-05-20T00:00:04Z",
            action_hash="actionhash",
            access_grant_id="grant-1",
            policy_version="policy-1",
        ),
        IssuedCredential(
            credential_id="cred-1",
            request_id="secret-request-1",
            subject_id="user-1",
            secret_name="OPENAI_API_KEY",
            broker_uri="broker://credential/cred-1",
            scope=["provider:openai"],
            expires_at="2026-05-20T00:05:00Z",
            policy_version="policy-1",
            issued_at="2026-05-20T00:00:04Z",
            approved_by="manager-1",
            access_grant_id="grant-1",
            secret_value_sha256="secrethash",
        ),
        ArtifactVaultRecord(
            artifact_id="artifact-1",
            data_class="source",
            content_sha256="contenthash",
            redacted_preview="diff preview",
            storage_uri="artifact://artifact-1",
            created_at="2026-05-20T00:00:05Z",
            metadata={"repo": "hermes-enterprise"},
        ),
        ContextHydrationRequest(
            request_id="hydration-1",
            artifact_id="artifact-1",
            subject_id="user-1",
            route="local-model",
            view=HydrationView.REDACTED,
            reason="summarize diff",
            requested_at="2026-05-20T00:00:06Z",
        ),
        StagedExecutionRecord(
            stage_id="stage-1",
            action_hash="actionhash",
            subject_id="user-1",
            tool_name="file_edit",
            preview_uri="artifact://stage-1",
            idempotency_key="idem-1",
            status=StageStatus.STAGED,
            created_at="2026-05-20T00:00:07Z",
        ),
        GovernanceChangeRecord(
            change_id="change-1",
            actor_id="admin-1",
            target="policy/default",
            change_type="policy_update",
            before_hash="before",
            after_hash="after",
            reason="tighten writes",
            created_at="2026-05-20T00:00:08Z",
        ),
        EvaluationRunRecord(
            run_id="eval-1",
            suite="mvp0",
            policy_version="policy-1",
            passed=True,
            started_at="2026-05-20T00:00:09Z",
            completed_at="2026-05-20T00:00:10Z",
            summary={"tests": 12},
        ),
    ]

    for record in records:
        restored = type(record).from_json(record.to_json())
        assert restored == record
        assert restored.to_json() == record.to_json()
        assert restored.content_hash() == record.content_hash()


def test_stable_hash_is_independent_of_dict_key_order():
    left = {"tool": "terminal", "args": {"b": 2, "a": 1}}
    right = {"args": {"a": 1, "b": 2}, "tool": "terminal"}

    assert stable_hash(left) == stable_hash(right)


def test_invalid_enum_values_fail_closed_at_contract_boundary():
    with pytest.raises(ValueError):
        ActionManifest.from_dict(
            {
                "action_id": "action-1",
                "tool_name": "terminal",
                "tool_args_hash": "abc123",
                "risk_tier": "extreme",
            }
        )
