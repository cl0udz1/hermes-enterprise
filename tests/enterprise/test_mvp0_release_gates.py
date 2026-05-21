"""Release-blocking enterprise MVP-0 regression gates."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from agent import tool_executor
from agent.memory_manager import MemoryManager
from agent.transports.chat_completions import ChatCompletionsTransport
from enterprise.audit import AuditStore
from enterprise.firewall.action import ActionFirewallDecision, evaluate_tool_call
from enterprise.firewall.result import sanitize_tool_result
from enterprise.staging import StageStore


def _serialized(value) -> str:
    return json.dumps(
        value,
        default=lambda item: item.to_dict() if hasattr(item, "to_dict") else str(item),
        sort_keys=True,
    )


def test_release_gate_blocked_tool_action_does_not_execute(
    make_enterprise_agent,
    make_mock_tool_call,
    monkeypatch,
):
    agent = make_enterprise_agent("terminal", config={"enterprise": {"enabled": True}})
    starts = []
    progress = []
    agent.tool_start_callback = lambda *args, **kwargs: starts.append((args, kwargs))
    agent.tool_progress_callback = lambda *args, **kwargs: progress.append((args, kwargs))
    tool_call = make_mock_tool_call("terminal", {"command": "whoami"}, "call-blocked")
    assistant_message = SimpleNamespace(content="", tool_calls=[tool_call])
    messages: list[dict] = []

    monkeypatch.setattr(
        tool_executor,
        "_enterprise_pre_tool_decision",
        lambda *args, **kwargs: ActionFirewallDecision.block(
            json.dumps({"error": "blocked by enterprise regression gate"})
        ),
    )

    with patch("run_agent.handle_function_call", side_effect=AssertionError("tool executed")) as mock_runner:
        agent._execute_tool_calls_sequential(assistant_message, messages, "task-release")

    mock_runner.assert_not_called()
    assert starts == []
    assert progress == []
    assert len(messages) == 1
    assert messages[0]["tool_call_id"] == "call-blocked"
    assert json.loads(messages[0]["content"]) == {"error": "blocked by enterprise regression gate"}


def test_release_gate_changed_action_args_invalidate_staged_approval(tmp_path, enterprise_enabled_config):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")

    original = evaluate_tool_call(
        "terminal",
        {"command": "echo original"},
        root_config=enterprise_enabled_config,
        audit_store=audit,
        stage_store=stages,
        task_id="task-release",
        tool_call_id="call-same-id",
    )
    changed = evaluate_tool_call(
        "terminal",
        {"command": "echo changed"},
        root_config=enterprise_enabled_config,
        audit_store=audit,
        stage_store=stages,
        task_id="task-release",
        tool_call_id="call-same-id",
    )

    assert original.staged_record is not None
    assert changed.staged_record is not None
    assert original.allows_execution is False
    assert changed.allows_execution is False
    assert original.action_hash != changed.action_hash
    assert original.staged_record.stage_id != changed.staged_record.stage_id
    assert original.staged_record.idempotency_key != changed.staged_record.idempotency_key
    assert stages.get_by_action_hash(original.action_hash) == [original.staged_record]
    assert stages.get_by_action_hash(changed.action_hash) == [changed.staged_record]


def test_release_gate_fake_secret_absent_from_provider_audit_session_and_memory(
    tmp_path,
    monkeypatch,
    enterprise_enabled_config,
    fake_enterprise_secret,
    fake_untrusted_tool_output,
    fake_provider_capture_factory,
    fake_memory_provider_factory,
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    audit = AuditStore(tmp_path / "audit.sqlite3")

    decision = sanitize_tool_result(
        "web_extract",
        fake_untrusted_tool_output,
        tool_call_id="call-secret",
        root_config=enterprise_enabled_config,
        audit_store=audit,
    )
    session_history = [
        {"role": "user", "content": "summarize the retrieved page"},
        {
            "role": "tool",
            "name": "web_extract",
            "tool_name": "web_extract",
            "content": decision.content,
            "tool_call_id": "call-secret",
        },
    ]

    transport = ChatCompletionsTransport()
    provider_payload = transport.build_kwargs("gpt-test", session_history)
    provider = fake_provider_capture_factory()
    provider.create(**provider_payload)

    memory = MemoryManager()
    memory_sink = fake_memory_provider_factory()
    memory.add_provider(memory_sink)
    memory.on_session_end(session_history)

    assert decision.changed is True
    assert fake_enterprise_secret not in decision.redacted_preview
    assert fake_enterprise_secret not in _serialized(audit.list_events())
    assert fake_enterprise_secret not in _serialized(session_history)
    assert fake_enterprise_secret not in _serialized(provider.calls)
    assert fake_enterprise_secret not in _serialized(memory_sink.session_end_payloads)
    assert "tool_name" not in provider.calls[0]["messages"][1]


def test_release_gate_enterprise_off_smoke_preserves_normal_tool_path(
    tmp_path,
    enterprise_disabled_config,
    fake_enterprise_secret,
    fake_untrusted_tool_output,
    make_enterprise_agent,
    make_mock_tool_call,
):
    audit = AuditStore(tmp_path / "audit.sqlite3")
    stages = StageStore(tmp_path / "staged.sqlite3")
    decision = evaluate_tool_call(
        "terminal",
        {"command": f"echo {fake_enterprise_secret}"},
        root_config=enterprise_disabled_config,
        audit_store=audit,
        stage_store=stages,
        task_id="task-off",
        tool_call_id="call-off",
    )

    assert decision.allows_execution is True
    assert decision.audit_event_ids == ()
    assert audit.count() == 0
    assert stages.count() == 0

    agent = make_enterprise_agent("web_search", config=enterprise_disabled_config)
    tool_call = make_mock_tool_call("web_search", {"query": "enterprise"}, "call-off-runtime")
    assistant_message = SimpleNamespace(content="", tool_calls=[tool_call])
    messages: list[dict] = []

    with patch("run_agent.handle_function_call", return_value=fake_untrusted_tool_output) as mock_runner:
        agent._execute_tool_calls_sequential(assistant_message, messages, "task-off")

    mock_runner.assert_called_once()
    assert len(messages) == 1
    assert fake_enterprise_secret in messages[0]["content"]
    assert "Enterprise result sanitizer" not in messages[0]["content"]
