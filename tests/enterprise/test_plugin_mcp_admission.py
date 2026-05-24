"""Enterprise plugin and MCP admission tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from enterprise.admission import (
    evaluate_mcp_server,
    evaluate_mcp_tool,
    evaluate_plugin_manifest,
    evaluate_plugin_tool,
)
from enterprise.contracts import AuditEventType, DecisionOutcome


class CapturingAuditStore:
    def __init__(self):
        self.events = []

    def append_event(self, event):
        self.events.append(event)
        return len(self.events)


@pytest.fixture
def isolated_plugin_manager(tmp_path, monkeypatch):
    import hermes_cli.plugins as plugins_mod

    hermes_home = tmp_path / "home"
    bundled_plugins = tmp_path / "bundled-plugins"
    hermes_home.mkdir()
    bundled_plugins.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(plugins_mod, "get_bundled_plugins_dir", lambda: bundled_plugins)
    plugins_mod._plugin_manager = plugins_mod.PluginManager()
    yield plugins_mod, hermes_home
    plugins_mod._plugin_manager = plugins_mod.PluginManager()


def _write_plugin(hermes_home, name: str, manifest: str, init_body: str):
    plugin_dir = hermes_home / "plugins" / name
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text(manifest, encoding="utf-8")
    (plugin_dir / "__init__.py").write_text(init_body, encoding="utf-8")
    return plugin_dir


def _tool_registration_body(tool_names: list[str]) -> str:
    lines = ["def register(ctx):"]
    for tool_name in tool_names:
        lines.extend(
            [
                f"    ctx.register_tool(",
                f"        name={tool_name!r},",
                f"        toolset='enterprise_admission_test',",
                f"        schema={{'name': {tool_name!r}, 'description': 'test tool', 'parameters': {{'type': 'object', 'properties': {{}}}}}},",
                f"        handler=lambda args, **kw: '{{}}',",
                f"    )",
            ]
        )
    return "\n".join(lines) + "\n"


def test_admission_disabled_allows_untrusted_plugin_without_audit():
    manifest = SimpleNamespace(
        name="plain-plugin",
        key="plain-plugin",
        source="user",
        provides_tools=[],
    )
    audit_store = CapturingAuditStore()

    decision = evaluate_plugin_manifest(
        manifest,
        root_config={"enterprise": {"enabled": False}},
        audit_store=audit_store,
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert audit_store.events == []


def test_untrusted_plugin_is_not_imported_in_enterprise_mode(
    isolated_plugin_manager,
    monkeypatch,
):
    plugins_mod, hermes_home = isolated_plugin_manager
    _write_plugin(
        hermes_home,
        "untrusted-enterprise-plugin",
        "name: untrusted-enterprise-plugin\n",
        "raise RuntimeError('this plugin should not be imported')\n",
    )
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "enterprise": {"enabled": True},
            "plugins": {"enabled": ["untrusted-enterprise-plugin"]},
        },
    )

    plugins_mod.discover_plugins(force=True)

    loaded = plugins_mod.get_plugin_manager()._plugins["untrusted-enterprise-plugin"]
    assert loaded.enabled is False
    assert loaded.error is not None
    assert "enterprise plugin admission quarantined" in loaded.error


def test_plugin_tool_admission_requires_admitted_plugin():
    manifest = SimpleNamespace(
        name="untrusted-tool-plugin",
        key="untrusted-tool-plugin",
        source="user",
        provides_tools=["declared_but_untrusted_tool"],
    )

    decision = evaluate_plugin_tool(
        manifest,
        "declared_but_untrusted_tool",
        root_config={"enterprise": {"enabled": True}},
        audit_store=CapturingAuditStore(),
    )

    assert decision.outcome is DecisionOutcome.QUARANTINE
    assert "manifest" in decision.reason


def test_enterprise_off_plugin_tool_registration_is_unchanged(
    isolated_plugin_manager,
    monkeypatch,
):
    from tools.registry import registry

    plugins_mod, hermes_home = isolated_plugin_manager
    tool_name = "enterprise_off_unmanifested_plugin_tool"
    _write_plugin(
        hermes_home,
        "enterprise-off-plugin",
        "name: enterprise-off-plugin\n",
        _tool_registration_body([tool_name]),
    )
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "enterprise": {"enabled": False},
            "plugins": {"enabled": ["enterprise-off-plugin"]},
        },
    )

    plugins_mod.discover_plugins(force=True)

    assert registry.get_entry(tool_name) is not None
    registry.deregister(tool_name)


def test_approved_plugin_can_only_register_declared_tools(
    isolated_plugin_manager,
    monkeypatch,
):
    from tools.registry import registry

    plugins_mod, hermes_home = isolated_plugin_manager
    declared_tool = "declared_enterprise_plugin_tool"
    rogue_tool = "rogue_enterprise_plugin_tool"
    _write_plugin(
        hermes_home,
        "approved-enterprise-plugin",
        (
            "name: approved-enterprise-plugin\n"
            "provides_tools:\n"
            f"  - {declared_tool}\n"
        ),
        _tool_registration_body([rogue_tool, declared_tool]),
    )
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "enterprise": {
                "enabled": True,
                "plugin_mcp_admission": {
                    "plugin_trust": {
                        "approved-enterprise-plugin": {"approved": True},
                    }
                },
            },
            "plugins": {"enabled": ["approved-enterprise-plugin"]},
        },
    )

    plugins_mod.discover_plugins(force=True)

    assert registry.get_entry(rogue_tool) is None
    assert registry.get_entry(declared_tool) is not None
    registry.deregister(declared_tool)


def test_mcp_server_and_tool_admission_decisions_are_audited():
    audit_store = CapturingAuditStore()
    root_config = {"enterprise": {"enabled": True}}

    server_decision = evaluate_mcp_server(
        "untrusted-mcp",
        {"command": "untrusted"},
        root_config=root_config,
        audit_store=audit_store,
    )
    trusted_server = {
        "enterprise_trust": {
            "approved": True,
            "tools": ["safe_tool"],
        }
    }
    safe_tool_decision = evaluate_mcp_tool(
        "trusted-mcp",
        "safe_tool",
        trusted_server,
        root_config=root_config,
        audit_store=audit_store,
    )
    rogue_tool_decision = evaluate_mcp_tool(
        "trusted-mcp",
        "rogue_tool",
        trusted_server,
        root_config=root_config,
        audit_store=audit_store,
    )

    assert server_decision.outcome is DecisionOutcome.QUARANTINE
    assert safe_tool_decision.outcome is DecisionOutcome.ALLOW
    assert rogue_tool_decision.outcome is DecisionOutcome.QUARANTINE
    assert {event.event_type for event in audit_store.events} == {
        AuditEventType.AUTHORITY_ADMISSION_DECISION
    }
    assert len(audit_store.events) == 2


def test_untrusted_mcp_server_is_not_started_in_enterprise_mode(monkeypatch):
    import tools.mcp_tool as mcp_mod

    with mcp_mod._lock:
        mcp_mod._servers.clear()
        mcp_mod._parallel_safe_servers.clear()
        mcp_mod._mcp_tool_server_names.clear()
    monkeypatch.setattr(mcp_mod, "_MCP_AVAILABLE", True)
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {"enterprise": {"enabled": True}},
    )
    monkeypatch.setattr(
        mcp_mod,
        "_ensure_mcp_loop",
        lambda: (_ for _ in ()).throw(AssertionError("untrusted server started")),
    )

    assert mcp_mod.register_mcp_servers({"untrusted": {"command": "evil"}}) == []


def test_mcp_tool_registration_requires_declared_tool(monkeypatch):
    import tools.mcp_tool as mcp_mod
    from tools.registry import registry

    with mcp_mod._lock:
        mcp_mod._servers.clear()
        mcp_mod._parallel_safe_servers.clear()
        mcp_mod._mcp_tool_server_names.clear()
    safe_tool = "safe_admission_tool"
    rogue_tool = "rogue_admission_tool"
    fake_server = SimpleNamespace(
        name="admission_lab",
        tool_timeout=1,
        session=SimpleNamespace(),
        initialize_result=SimpleNamespace(
            capabilities=SimpleNamespace(resources=None, prompts=None)
        ),
        _tools=[
            SimpleNamespace(name=safe_tool, description="safe", inputSchema={}),
            SimpleNamespace(name=rogue_tool, description="rogue", inputSchema={}),
        ],
    )
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {"enterprise": {"enabled": True}},
    )

    registered = mcp_mod._register_server_tools(
        "admission_lab",
        fake_server,
        {
            "enterprise_trust": {
                "approved": True,
                "tools": [safe_tool],
            }
        },
    )

    safe_prefixed = "mcp_admission_lab_safe_admission_tool"
    rogue_prefixed = "mcp_admission_lab_rogue_admission_tool"
    assert registered == [safe_prefixed]
    assert registry.get_entry(safe_prefixed) is not None
    assert registry.get_entry(rogue_prefixed) is None
    registry.deregister(safe_prefixed)
