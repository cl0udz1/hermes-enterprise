"""Tests for enterprise sandbox profile enforcement."""

from __future__ import annotations

from enterprise.audit import AuditStore
from enterprise.contracts import AuditEventType, DecisionOutcome, RiskTier
from enterprise.firewall.action import evaluate_tool_call
from enterprise.manifests import load_core_tool_manifest
from enterprise.manifests.schema import ToolCapability
from enterprise.sandbox import evaluate_sandbox, sandbox_profile_names


FAKE_OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"


def test_sandbox_profiles_cover_core_manifest_profiles():
    manifest = load_core_tool_manifest()
    missing = {
        capability.sandbox_profile
        for capability in manifest.tools.values()
        if capability.sandbox_profile not in sandbox_profile_names()
    }

    assert missing == set()


def test_sandbox_detects_network_attempt_not_declared_by_tool():
    capability = ToolCapability(
        tool_name="browser_snapshot",
        risk_tier=RiskTier.MODERATE,
        side_effects=["browser_state"],
        sandbox_profile="browser_read",
        data_classes=["public"],
    )

    decision = evaluate_sandbox(
        "browser_snapshot",
        {"url": "https://example.com/page"},
        capability,
    )

    assert decision.allowed is False
    assert decision.observation.observed_side_effects == ("network_egress",)
    assert "https://example.com/page" in decision.observation.network_destinations
    assert {finding.detector for finding in decision.findings} >= {
        "sandbox:profile_side_effect_blocked",
        "sandbox:undeclared_side_effect",
    }


def test_sandbox_detects_secret_environment_forwarding():
    capability = ToolCapability(
        tool_name="terminal",
        risk_tier=RiskTier.CRITICAL,
        side_effects=["process_spawn", "filesystem_read", "filesystem_write", "network_egress"],
        sandbox_profile="command_local",
        approval_required=True,
        data_classes=["source", "secrets"],
    )

    decision = evaluate_sandbox(
        "terminal",
        {
            "command": "env",
            "env": {"OPENAI_API_KEY": FAKE_OPENAI_KEY},
        },
        capability,
    )

    assert decision.allowed is False
    assert decision.observation.env_key_count == 1
    assert decision.observation.env_secret_like is True
    assert "sandbox:env_forwarding_blocked" in {finding.detector for finding in decision.findings}
    assert "sandbox:env_secret_forwarding" in {finding.detector for finding in decision.findings}


def test_action_firewall_denies_sandbox_violation_and_audits(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_tool_call(
        "browser_snapshot",
        {"url": "https://example.com/page"},
        root_config={"enterprise": {"enabled": True}},
        audit_store=store,
        task_id="task-sandbox",
        tool_call_id="call-sandbox",
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.DENY
    assert "sandbox:undeclared_side_effect" in decision.triage_decision.detectors
    assert "manifest:side_effect_mismatch" in decision.triage_decision.detectors

    events = store.list_events()
    assert [event.event_type for event in events] == [
        AuditEventType.ACTION_PROPOSED,
        AuditEventType.POLICY_DECISION,
        AuditEventType.SANDBOX_VIOLATION,
    ]
    violation = events[-1]
    assert violation.metadata["sandbox_profile"] == "browser_read"
    assert violation.metadata["observed_side_effects"] == ["network_egress"]
    assert violation.metadata["network_destination_count"] == 1


def test_action_firewall_sandbox_env_violation_does_not_leak_secret(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_tool_call(
        "terminal",
        {
            "command": "env",
            "env": {"OPENAI_API_KEY": FAKE_OPENAI_KEY},
        },
        root_config={"enterprise": {"enabled": True}},
        audit_store=store,
        task_id="task-env",
        tool_call_id="call-env",
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert "sandbox:env_secret_forwarding" in decision.triage_decision.detectors
    assert "sandbox:env_forwarding_blocked" in decision.triage_decision.detectors

    serialized_events = "\n".join(event.to_json() for event in store.list_events())
    assert FAKE_OPENAI_KEY not in serialized_events
    assert "terminal(command, env)" in serialized_events


def test_action_firewall_disabled_skips_sandbox_enforcement():
    decision = evaluate_tool_call(
        "browser_snapshot",
        {"url": "https://example.com/page"},
        root_config={"enterprise": {"enabled": False}},
    )

    assert decision.allows_execution is True
    assert decision.triage_decision is None
