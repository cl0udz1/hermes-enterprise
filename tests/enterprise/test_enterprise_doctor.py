"""Tests for enterprise doctor diagnostics."""

from __future__ import annotations

from pathlib import Path

from enterprise.doctor import EnterpriseDoctorStatus, run_enterprise_doctor


def test_enterprise_doctor_disabled_mode_is_machine_readable(tmp_path):
    report = run_enterprise_doctor(
        root_config={"enterprise": {"enabled": False}},
        hermes_home=tmp_path,
    )

    payload = report.to_dict()
    assert payload["status"] == "pass"
    assert payload["mode"] == "developer_secure"
    assert payload["enabled"] is False
    assert {item["name"] for item in payload["checks"]} >= {
        "enterprise_mode",
        "audit_store",
        "action_firewall_hook",
        "manifest_loader",
        "triage_latency",
        "sandbox_profiles",
        "result_sanitizer",
        "provider_egress",
        "memory_governance",
        "plugin_mcp_admission",
        "gateway_identity",
        "streaming_policy",
    }


def test_enterprise_doctor_developer_secure_warns_for_missing_streaming_policy(tmp_path):
    report = run_enterprise_doctor(
        root_config={"enterprise": {"enabled": True, "edition": "developer_secure"}},
        hermes_home=tmp_path,
    )

    assert report.status is EnterpriseDoctorStatus.WARN
    streaming = next(check for check in report.checks if check.name == "streaming_policy")
    assert streaming.status is EnterpriseDoctorStatus.WARN
    assert "streaming scanner" in streaming.detail


def test_enterprise_doctor_team_fails_missing_streaming_policy(tmp_path):
    report = run_enterprise_doctor(
        root_config={"enterprise": {"enabled": True, "edition": "team"}},
        hermes_home=tmp_path,
    )

    assert report.status is EnterpriseDoctorStatus.FAIL
    streaming = next(check for check in report.checks if check.name == "streaming_policy")
    assert streaming.status is EnterpriseDoctorStatus.FAIL


def test_enterprise_doctor_detects_manifest_loader_failure(monkeypatch, tmp_path):
    import enterprise.manifests as manifests

    def broken_manifest():
        raise ValueError("manifest broken")

    monkeypatch.setattr(manifests, "load_core_tool_manifest", broken_manifest)

    report = run_enterprise_doctor(
        root_config={"enterprise": {"enabled": True}},
        hermes_home=tmp_path,
    )

    manifest = next(check for check in report.checks if check.name == "manifest_loader")
    sandbox = next(check for check in report.checks if check.name == "sandbox_profiles")
    assert report.status is EnterpriseDoctorStatus.FAIL
    assert manifest.status is EnterpriseDoctorStatus.FAIL
    assert sandbox.status is EnterpriseDoctorStatus.FAIL
    assert "manifest broken" in manifest.detail


def test_enterprise_doctor_bad_latency_config_fails(tmp_path):
    report = run_enterprise_doctor(
        root_config={
            "enterprise": {
                "enabled": True,
                "triage": {"low_risk_latency_budget_ms": 0},
            }
        },
        hermes_home=tmp_path,
    )

    triage = next(check for check in report.checks if check.name == "triage_latency")
    assert report.status is EnterpriseDoctorStatus.FAIL
    assert triage.status is EnterpriseDoctorStatus.FAIL


def test_hermes_cli_renders_enterprise_doctor_section(monkeypatch, tmp_path, capsys):
    import hermes_cli.doctor as doctor_mod

    monkeypatch.setattr(doctor_mod, "HERMES_HOME", Path(tmp_path))
    monkeypatch.setattr(doctor_mod, "PROJECT_ROOT", Path(tmp_path) / "project")
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {"enterprise": {"enabled": True, "edition": "team"}},
    )

    issues: list[str] = []
    doctor_mod._check_enterprise_security(issues)
    out = capsys.readouterr().out

    assert "Enterprise Security" in out
    assert "Streaming policy" in out
    assert issues
    assert any("Enterprise security check failed" in issue for issue in issues)
