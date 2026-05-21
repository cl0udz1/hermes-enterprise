"""Tests for the enterprise action firewall runtime hook."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent import tool_executor
from enterprise.audit import AuditStore
from enterprise.contracts import DecisionOutcome
from enterprise.firewall.action import ActionFirewallDecision, evaluate_tool_call
from run_agent import AIAgent


def _make_tool_defs(*names: str) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": f"{name} tool",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        for name in names
    ]


def _mock_tool_call(name: str, arguments: dict, call_id: str | None = None):
    return SimpleNamespace(
        id=call_id or f"call_{uuid.uuid4().hex[:8]}",
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def _make_agent(*tool_names: str, config: dict | None = None) -> AIAgent:
    root_config = config or {}
    with (
        patch("run_agent.get_tool_definitions", return_value=_make_tool_defs(*tool_names)),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("hermes_cli.config.load_config", return_value=root_config),
        patch("run_agent.OpenAI"),
    ):
        agent = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://openrouter.ai/api/v1",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
        )
    agent.client = MagicMock()
    agent.config = root_config
    agent._cached_system_prompt = "You are helpful."
    agent._use_prompt_caching = False
    agent.tool_delay = 0
    agent.compression_enabled = False
    agent.save_trajectories = False
    return agent


def test_action_firewall_disabled_is_a_true_noop():
    decision = evaluate_tool_call(
        "terminal",
        {"command": "echo should-not-matter"},
        root_config={"enterprise": {"enabled": False}},
    )

    assert decision.allows_execution is True
    assert decision.tool_result == ""
    assert decision.triage_decision is None
    assert decision.audit_event_ids == ()


def test_action_firewall_blocks_approval_required_tool_and_audits(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_tool_call(
        "terminal",
        {"command": "echo hello"},
        root_config={"enterprise": {"enabled": True}},
        audit_store=store,
        task_id="task-1",
        tool_call_id="call-1",
    )

    assert decision.allows_execution is False
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
    assert store.count() == 2

    payload = json.loads(decision.tool_result)
    assert payload["error"] == "Enterprise action firewall requires approval before executing this tool."
    assert payload["enterprise"]["tool_name"] == "terminal"
    assert payload["enterprise"]["outcome"] == "approval_required"
    assert payload["enterprise"]["risk_tier"] == "critical"

    events = store.list_events()
    assert [event.event_type.value for event in events] == ["action_proposed", "policy_decision"]
    assert events[0].redacted_preview == "terminal(command)"
    assert "echo hello" not in events[0].redacted_preview


def test_action_firewall_allows_low_risk_tool_and_audits(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")

    decision = evaluate_tool_call(
        "clarify",
        {"question": "Which workspace?"},
        root_config={"enterprise": {"enabled": True}},
        audit_store=store,
    )

    assert decision.allows_execution is True
    assert decision.triage_decision is not None
    assert decision.triage_decision.outcome is DecisionOutcome.ALLOW
    assert store.count() == 2


def test_enterprise_off_sequential_tool_execution_is_unchanged():
    agent = _make_agent("web_search", config={"enterprise": {"enabled": False}})
    tc = _mock_tool_call("web_search", {"query": "hermes"}, "c-off")
    msg = SimpleNamespace(content="", tool_calls=[tc])
    messages = []

    with patch("run_agent.handle_function_call", return_value=json.dumps({"ok": True})) as mock_hfc:
        agent._execute_tool_calls_sequential(msg, messages, "task-1")

    mock_hfc.assert_called_once()
    assert len(messages) == 1
    assert messages[0]["tool_call_id"] == "c-off"
    assert json.loads(messages[0]["content"]) == {"ok": True}


def test_action_firewall_blocked_sequential_call_never_reaches_tool_runner(monkeypatch):
    agent = _make_agent("terminal")
    starts = []
    progress = []
    agent.tool_start_callback = lambda *args, **kwargs: starts.append((args, kwargs))
    agent.tool_progress_callback = lambda *args, **kwargs: progress.append((args, kwargs))
    tc = _mock_tool_call("terminal", {"command": "whoami"}, "c-block-seq")
    msg = SimpleNamespace(content="", tool_calls=[tc])
    messages = []
    block_result = json.dumps({"error": "blocked by enterprise"})

    monkeypatch.setattr(
        tool_executor,
        "_enterprise_pre_tool_decision",
        lambda *args, **kwargs: ActionFirewallDecision.block(block_result),
    )
    with patch("run_agent.handle_function_call", side_effect=AssertionError("should not run")) as mock_hfc:
        agent._execute_tool_calls_sequential(msg, messages, "task-1")

    mock_hfc.assert_not_called()
    assert starts == []
    assert progress == []
    assert len(messages) == 1
    assert messages[0]["tool_call_id"] == "c-block-seq"
    assert json.loads(messages[0]["content"]) == {"error": "blocked by enterprise"}


def test_action_firewall_blocked_concurrent_call_is_not_submitted(monkeypatch):
    agent = _make_agent("terminal", "web_search")
    calls = [
        _mock_tool_call("terminal", {"command": "whoami"}, "c-block-con"),
        _mock_tool_call("web_search", {"query": "allowed"}, "c-allow-con"),
    ]
    msg = SimpleNamespace(content="", tool_calls=calls)
    messages = []
    block_result = json.dumps({"error": "blocked by enterprise"})

    def fake_enterprise_decision(_agent, name, _args, _task_id, _tool_call_id):
        if name == "terminal":
            return ActionFirewallDecision.block(block_result)
        return ActionFirewallDecision.allow()

    monkeypatch.setattr(tool_executor, "_enterprise_pre_tool_decision", fake_enterprise_decision)

    def fake_handle(name, args, task_id, **kwargs):
        assert name == "web_search"
        return json.dumps({"ok": args["query"], "tool_call_id": kwargs["tool_call_id"]})

    with patch("run_agent.handle_function_call", side_effect=fake_handle) as mock_hfc:
        agent._execute_tool_calls_concurrent(msg, messages, "task-1")

    mock_hfc.assert_called_once()
    assert [message["tool_call_id"] for message in messages] == ["c-block-con", "c-allow-con"]
    assert json.loads(messages[0]["content"]) == {"error": "blocked by enterprise"}
    assert json.loads(messages[1]["content"]) == {"ok": "allowed", "tool_call_id": "c-allow-con"}
