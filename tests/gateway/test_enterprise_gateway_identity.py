"""Gateway runner tests for enterprise identity binding."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent
from gateway.session import SessionSource


def _clear_auth_env(monkeypatch) -> None:
    for key in (
        "WHATSAPP_ALLOWED_USERS",
        "GATEWAY_ALLOWED_USERS",
        "WHATSAPP_ALLOW_ALL_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
    ):
        monkeypatch.delenv(key, raising=False)


def _make_event(user_id: str = "15551234567@s.whatsapp.net") -> MessageEvent:
    return MessageEvent(
        text="please research this",
        message_id="m1",
        source=SessionSource(
            platform=Platform.WHATSAPP,
            user_id=user_id,
            chat_id=user_id,
            user_name="tester",
            chat_type="dm",
        ),
    )


def _make_runner():
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(
        platforms={Platform.WHATSAPP: PlatformConfig(enabled=True)},
    )
    runner.adapters = {Platform.WHATSAPP: SimpleNamespace(send=AsyncMock())}
    runner.pairing_store = MagicMock()
    runner.pairing_store.is_approved.return_value = False
    runner.pairing_store._is_rate_limited.return_value = False
    runner.session_store = MagicMock()
    runner._running_agents = {}
    runner._running_agents_ts = {}
    runner._update_prompt_pending = {}
    return runner


@pytest.mark.asyncio
async def test_enterprise_gateway_identity_blocks_authorized_unmapped_user(monkeypatch):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", "*")
    monkeypatch.setattr("hermes_cli.plugins.invoke_hook", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "gateway.run._load_gateway_config",
        lambda: {"enterprise": {"enabled": True, "gateway_identity": {"assignments": {}}}},
    )
    runner = _make_runner()
    runner._handle_message_with_agent = AsyncMock(return_value="should-not-run")

    result = await runner._handle_message(_make_event())

    assert result is not None
    assert "Enterprise policy blocked" in result
    runner._handle_message_with_agent.assert_not_awaited()


@pytest.mark.asyncio
async def test_enterprise_gateway_identity_binds_before_agent_dispatch(monkeypatch):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", "*")
    monkeypatch.setattr("hermes_cli.plugins.invoke_hook", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "gateway.run._load_gateway_config",
        lambda: {
            "enterprise": {
                "enabled": True,
                "gateway_identity": {
                    "assignments": {
                        "wa-analyst": {
                            "subject_id": "employee-analyst",
                            "platform": "whatsapp",
                            "user_id": "15551234567@s.whatsapp.net",
                            "chat_id": "15551234567@s.whatsapp.net",
                        }
                    }
                },
            }
        },
    )
    runner = _make_runner()
    seen = {}

    async def _capture(event, source, _quick_key, _run_generation):
        seen["event_subject"] = getattr(event, "enterprise_subject_id", "")
        seen["source_subject"] = getattr(source, "enterprise_subject_id", "")
        seen["assignment_id"] = getattr(source, "enterprise_assignment_id", "")
        return "ok"

    runner._handle_message_with_agent = _capture

    result = await runner._handle_message(_make_event())

    assert result == "ok"
    assert seen["event_subject"] == "employee-analyst"
    assert seen["source_subject"] == "employee-analyst"
    assert seen["assignment_id"] == "wa-analyst"
