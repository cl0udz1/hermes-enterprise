from pathlib import Path

from enterprise import EnterpriseEdition, EnterpriseMode, is_enterprise_enabled
from enterprise.audit import AuditStore
from enterprise.config import DEFAULT_ENTERPRISE_CONFIG, enterprise_config_from_root
from enterprise.contracts import AuditEvent, AuditEventType
from hermes_cli.config import DEFAULT_CONFIG, load_config, validate_config_structure


def test_enterprise_defaults_disabled_in_hermes_config():
    enterprise_cfg = DEFAULT_CONFIG["enterprise"]

    assert enterprise_cfg["enabled"] is False
    assert enterprise_cfg["edition"] == "developer_secure"
    assert enterprise_cfg["fail_closed_high_risk"] is True
    assert enterprise_cfg["triage"]["llm_evaluator_enabled"] is False
    assert enterprise_cfg["hydration"]["full_allowed_routes"] == ["local", "local-model", "trusted-local"]


def test_load_config_includes_enterprise_defaults_without_user_config():
    cfg = load_config()

    assert cfg["enterprise"]["enabled"] is False
    assert cfg["enterprise"]["developer_fast_path"]["enabled"] is True
    assert cfg["enterprise"]["developer_fast_path"]["owner_workspace_roots"] == {}
    assert cfg["enterprise"]["hydration"]["enabled"] is True
    assert validate_config_structure(cfg) == []


def test_enterprise_mode_is_noop_until_enabled():
    assert is_enterprise_enabled({}) is False

    mode = EnterpriseMode.from_config({})

    assert mode.enabled is False
    assert mode.edition is EnterpriseEdition.DEVELOPER_SECURE
    assert mode.is_enforcing is False


def test_enterprise_config_deep_merges_user_overrides():
    cfg = enterprise_config_from_root(
        {
            "enterprise": {
                "enabled": True,
                "edition": "team",
                "triage": {"low_risk_latency_budget_ms": 25},
            }
        }
    )

    assert cfg["enabled"] is True
    assert cfg["edition"] == "team"
    assert cfg["triage"]["low_risk_latency_budget_ms"] == 25
    assert cfg["triage"]["llm_evaluator_enabled"] is False
    assert cfg["sandbox"] == DEFAULT_ENTERPRISE_CONFIG["sandbox"]
    assert cfg["hydration"] == DEFAULT_ENTERPRISE_CONFIG["hydration"]
    assert cfg["developer_fast_path"] == DEFAULT_ENTERPRISE_CONFIG["developer_fast_path"]


def test_enterprise_import_does_not_create_runtime_state(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    __import__("enterprise")

    assert not (tmp_path / "enterprise").exists()


def test_audit_store_appends_structured_events(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    event = AuditEvent(
        event_id="event-1",
        event_type=AuditEventType.ACTION_PROPOSED,
        subject_id="user-1",
        action_id="action-1",
        redacted_preview="safe preview",
        raw_sha256="rawhash",
        created_at="2026-05-20T00:00:00Z",
        metadata={"tool": "terminal"},
    )

    sequence = store.append_event(event)

    assert sequence == 1
    assert store.count() == 1
    assert store.get_event("event-1") == event
    assert store.list_events() == [event]
    assert Path(tmp_path / "audit.sqlite3").exists()
