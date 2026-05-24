"""Cron scheduler enforcement tests for enterprise governance."""

from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def hermes_env(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "scripts").mkdir()
    (home / "cron").mkdir()

    monkeypatch.setenv("HERMES_HOME", str(home))

    import hermes_constants
    import cron.jobs
    import cron.scheduler

    importlib.reload(hermes_constants)
    importlib.reload(cron.jobs)
    importlib.reload(cron.scheduler)

    return home


def _enterprise_config():
    return {"enterprise": {"enabled": True, "cron_governance": {"max_ttl_days": 90}}}


def _governance_fields():
    return {
        "owner_id": "employee-researcher",
        "intent": "run scripted enterprise watchdog",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        "policy_context": {"policy_id": "cron-watchdog", "policy_version": "v1"},
    }


def test_enterprise_cron_without_owner_fails_closed_before_script(hermes_env, monkeypatch):
    from cron.jobs import create_job
    import cron.scheduler as scheduler

    script_path = hermes_env / "scripts" / "touch_marker.py"
    script_path.write_text(
        "from pathlib import Path\n"
        "Path('marker.txt').write_text('ran')\n"
        "print('should not run')\n"
    )
    job = create_job(
        prompt=None,
        schedule="every 5m",
        script="touch_marker.py",
        no_agent=True,
        deliver="local",
    )
    monkeypatch.setattr(scheduler, "load_config", _enterprise_config)

    success, doc, final_response, error = scheduler.run_job(job)

    assert success is False
    assert final_response == ""
    assert error is not None
    assert "missing_owner" in error
    assert "BLOCKED" in doc
    assert not (hermes_env / "scripts" / "marker.txt").exists()


def test_enterprise_cron_valid_governance_preserves_no_agent_execution(hermes_env, monkeypatch):
    from cron.jobs import create_job
    import cron.scheduler as scheduler

    script_path = hermes_env / "scripts" / "alert.py"
    script_path.write_text("print('governed alert')\n")
    job = create_job(
        prompt=None,
        schedule="every 5m",
        script="alert.py",
        no_agent=True,
        deliver="local",
        **_governance_fields(),
    )
    monkeypatch.setattr(scheduler, "load_config", _enterprise_config)

    success, doc, final_response, error = scheduler.run_job(job)

    assert success is True
    assert error is None
    assert "governed alert" in final_response
    assert "governed alert" in doc


def test_enterprise_off_cron_behavior_is_unchanged(hermes_env, monkeypatch):
    from cron.jobs import create_job
    import cron.scheduler as scheduler

    script_path = hermes_env / "scripts" / "legacy.py"
    script_path.write_text("print('legacy alert')\n")
    job = create_job(
        prompt=None,
        schedule="every 5m",
        script="legacy.py",
        no_agent=True,
        deliver="local",
    )
    monkeypatch.setattr(scheduler, "load_config", lambda: {"enterprise": {"enabled": False}})

    success, _doc, final_response, error = scheduler.run_job(job)

    assert success is True
    assert error is None
    assert "legacy alert" in final_response
