import textwrap

import pytest

from enterprise.contracts import RiskTier
from enterprise.manifests import ManifestIndex, load_core_tool_manifest, load_manifest_file


def _write_manifest(tmp_path, body: str):
    path = tmp_path / "manifest.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def test_core_tool_manifest_loads_required_high_risk_tools():
    manifest = load_core_tool_manifest()

    assert isinstance(manifest, ManifestIndex)
    assert manifest.version == "0.1"
    assert "tool_execution" in manifest.covered_runtime_surfaces

    required_tools = {
        "terminal",
        "process",
        "execute_code",
        "write_file",
        "patch",
        "web_extract",
        "browser_navigate",
        "browser_cdp",
        "memory",
        "send_message",
        "cronjob",
        "delegate_task",
    }

    assert required_tools <= set(manifest.tools)
    assert required_tools <= manifest.high_risk_tools()

    terminal = manifest.require("terminal")
    assert terminal.risk_tier is RiskTier.CRITICAL
    assert terminal.approval_required is True
    assert terminal.sandbox_profile == "command_local"
    assert "process_spawn" in terminal.side_effects
    assert terminal.network_access is True


def test_manifest_loader_requires_risk_tier(tmp_path):
    path = _write_manifest(
        tmp_path,
        """
        version: "0.1"
        tools:
          terminal:
            side_effects: [process_spawn]
            sandbox_profile: command_local
        """,
    )

    with pytest.raises(ValueError, match="risk_tier"):
        load_manifest_file(path)


def test_manifest_loader_requires_sandbox_profile(tmp_path):
    path = _write_manifest(
        tmp_path,
        """
        version: "0.1"
        tools:
          terminal:
            risk_tier: critical
            side_effects: [process_spawn]
        """,
    )

    with pytest.raises(ValueError, match="sandbox_profile"):
        load_manifest_file(path)


def test_manifest_loader_rejects_empty_side_effects(tmp_path):
    path = _write_manifest(
        tmp_path,
        """
        version: "0.1"
        tools:
          read_file:
            risk_tier: moderate
            side_effects: []
            sandbox_profile: workspace_read
        """,
    )

    with pytest.raises(ValueError, match="side_effects"):
        load_manifest_file(path)


def test_manifest_loader_rejects_unknown_side_effects(tmp_path):
    path = _write_manifest(
        tmp_path,
        """
        version: "0.1"
        tools:
          terminal:
            risk_tier: critical
            side_effects: [time_travel]
            sandbox_profile: command_local
        """,
    )

    with pytest.raises(ValueError, match="time_travel"):
        load_manifest_file(path)


def test_manifest_loader_rejects_unknown_risk_tier(tmp_path):
    path = _write_manifest(
        tmp_path,
        """
        version: "0.1"
        tools:
          terminal:
            risk_tier: extreme
            side_effects: [process_spawn]
            sandbox_profile: command_local
        """,
    )

    with pytest.raises(ValueError, match="extreme"):
        load_manifest_file(path)


def test_manifest_index_requires_known_tool():
    manifest = load_core_tool_manifest()

    assert manifest.has_tool("terminal")
    assert not manifest.has_tool("unknown_tool")
    with pytest.raises(KeyError, match="unknown_tool"):
        manifest.require("unknown_tool")
