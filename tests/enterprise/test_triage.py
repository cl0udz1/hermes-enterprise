from datetime import datetime, timezone

from enterprise.contracts import (
    AccessGrant,
    DecisionOutcome,
    PolicyDecision,
    RiskTier,
)
from enterprise.policy import PolicyCacheKey, PolicyDecisionCache
from enterprise.triage import RuntimeTriageEngine, TriageRequest


NOW = datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc)


def test_low_risk_clarify_action_is_allowed_without_llm_escalation():
    engine = RuntimeTriageEngine(now=NOW)

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="clarify",
            tool_args={"question": "Which file?"},
            requested_side_effects=("user_prompt",),
        )
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.risk_tier is RiskTier.LOW
    assert decision.escalated is False
    assert decision.latency_ms >= 0
    assert decision.detectors == ["deterministic_allow"]


def test_high_risk_manifested_tool_requires_approval():
    engine = RuntimeTriageEngine(now=NOW)

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="terminal",
            tool_args={"command": "pytest"},
            requested_side_effects=("process_spawn",),
        )
    )

    assert decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
    assert decision.risk_tier is RiskTier.CRITICAL
    assert decision.escalated is False


def test_missing_manifest_denies_action():
    engine = RuntimeTriageEngine(now=NOW)

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="unknown_tool",
            tool_args={},
        )
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert "manifest:missing" in decision.detectors
    assert "No capability manifest" in decision.reason


def test_manifest_side_effect_mismatch_denies_action():
    engine = RuntimeTriageEngine(now=NOW)

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="read_file",
            tool_args={"path": "README.md"},
            requested_side_effects=("filesystem_write",),
        )
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert "manifest:side_effect_mismatch" in decision.detectors


def test_secret_pattern_denies_action_before_execution():
    engine = RuntimeTriageEngine(now=NOW)

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="send_message",
            tool_args={"text": "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456"},
            requested_side_effects=("external_send", "network_egress"),
        )
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert any(detector.startswith("secret_pattern:") for detector in decision.detectors)
    assert decision.risk_tier is RiskTier.CRITICAL


def test_path_policy_denies_paths_outside_allowed_roots(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    engine = RuntimeTriageEngine(allowed_roots=(workspace,), now=NOW)

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="read_file",
            tool_args={"path": str(tmp_path / "outside.txt")},
            requested_side_effects=("filesystem_read",),
            resource_paths=(tmp_path / "outside.txt",),
        )
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert "path_policy:outside_allowed_roots" in decision.detectors


def test_network_policy_denies_private_and_denied_hosts():
    engine = RuntimeTriageEngine(denied_hosts=("evil.example",), now=NOW)

    private_decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="web_extract",
            tool_args={"url": "http://127.0.0.1/admin"},
            requested_side_effects=("network_egress",),
            network_destinations=("http://127.0.0.1/admin",),
        )
    )
    denied_decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="web_extract",
            tool_args={"url": "https://evil.example/data"},
            requested_side_effects=("network_egress",),
            network_destinations=("https://evil.example/data",),
        )
    )

    assert private_decision.outcome is DecisionOutcome.DENY
    assert "network_policy:private_host" in private_decision.detectors
    assert denied_decision.outcome is DecisionOutcome.DENY
    assert "network_policy:denied_host" in denied_decision.detectors


def test_revoked_or_expired_grant_denies_action():
    engine = RuntimeTriageEngine(now=NOW)
    expired = AccessGrant(
        grant_id="grant-expired",
        request_id="request-1",
        subject_id="user-1",
        resource="repo",
        actions=["write"],
        expires_at="2026-05-20T11:00:00Z",
        policy_version="policy-1",
    )
    revoked = AccessGrant(
        grant_id="grant-revoked",
        request_id="request-2",
        subject_id="user-1",
        resource="repo",
        actions=["write"],
        expires_at="2026-05-21T11:00:00Z",
        policy_version="policy-1",
        revoked_at="2026-05-20T11:30:00Z",
    )

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="write_file",
            tool_args={"path": "file.txt"},
            requested_side_effects=("filesystem_write",),
            grants=(expired, revoked),
        )
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert "grant_status:expired" in decision.detectors
    assert "grant_status:revoked" in decision.detectors


def test_valid_access_grant_allows_high_risk_action():
    engine = RuntimeTriageEngine(now=NOW)
    grant = AccessGrant(
        grant_id="grant-valid",
        request_id="stage-1",
        subject_id="user-1",
        resource="actionhash",
        actions=["terminal", "execute"],
        expires_at="2026-05-20T12:30:00Z",
        policy_version="policy-1",
        action_hash="actionhash",
        tool_name="terminal",
        approved_by="manager-1",
        stage_id="stage-1",
    )

    decision = engine.evaluate(
        TriageRequest(
            subject_id="user-1",
            tool_name="terminal",
            tool_args={"command": "pytest"},
            action_hash="actionhash",
            requested_side_effects=("process_spawn",),
            grants=(grant,),
        )
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.risk_tier is RiskTier.CRITICAL
    assert "grant_status:valid" in decision.detectors


def test_policy_decision_cache_is_keyed_and_expires():
    decision = PolicyDecision(
        decision_id="decision-1",
        outcome=DecisionOutcome.ALLOW,
        reason="cached allow",
        policy_version="policy-1",
        action_hash="hash-1",
        expires_at="2026-05-20T12:30:00Z",
    )
    cache = PolicyDecisionCache(now=NOW)

    key = cache.set(
        subject_id="user-1",
        tool_name="read_file",
        data_classes=("source", "config"),
        decision=decision,
    )

    assert cache.get(key) == decision
    assert cache.get(
        PolicyCacheKey.build(
            policy_version="policy-1",
            action_hash="hash-1",
            subject_id="user-2",
            tool_name="read_file",
            data_classes=("config", "source"),
            expires_at="2026-05-20T12:30:00Z",
        )
    ) is None

    expired_cache = PolicyDecisionCache(now=datetime(2026, 5, 20, 13, 0, tzinfo=timezone.utc))
    expired_key = expired_cache.set(
        subject_id="user-1",
        tool_name="read_file",
        data_classes=("source",),
        decision=decision,
    )

    assert expired_cache.get(expired_key) is None
