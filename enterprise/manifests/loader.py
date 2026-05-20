"""Load and validate enterprise capability manifests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from enterprise.manifests.schema import ToolCapability


@dataclass(frozen=True)
class ManifestIndex:
    version: str
    tools: dict[str, ToolCapability]
    covered_runtime_surfaces: tuple[str, ...] = ()

    def get(self, tool_name: str) -> ToolCapability | None:
        return self.tools.get(tool_name)

    def require(self, tool_name: str) -> ToolCapability:
        capability = self.get(tool_name)
        if capability is None:
            raise KeyError(f"No enterprise capability manifest for tool: {tool_name}")
        return capability

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self.tools

    def high_risk_tools(self) -> set[str]:
        return {name for name, capability in self.tools.items() if capability.is_high_risk}


def _load_yaml_mapping(path: Path) -> Mapping[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ValueError(f"Manifest {path} must contain a mapping")
    return data


def manifest_from_mapping(data: Mapping[str, Any]) -> ManifestIndex:
    version = str(data.get("version", "")).strip()
    if not version:
        raise ValueError("Manifest missing required field: version")

    tools = data.get("tools")
    if not isinstance(tools, Mapping) or not tools:
        raise ValueError("Manifest must define a non-empty tools mapping")

    parsed_tools: dict[str, ToolCapability] = {}
    for tool_name, entry in tools.items():
        normalized_name = str(tool_name).strip()
        if not normalized_name:
            raise ValueError("Manifest contains an empty tool name")
        parsed_tools[normalized_name] = ToolCapability.from_mapping(normalized_name, entry)

    surfaces = data.get("covered_runtime_surfaces", [])
    if not isinstance(surfaces, list):
        raise ValueError("Manifest covered_runtime_surfaces must be a list")

    return ManifestIndex(
        version=version,
        tools=parsed_tools,
        covered_runtime_surfaces=tuple(str(surface) for surface in surfaces),
    )


def load_manifest_file(path: str | Path) -> ManifestIndex:
    return manifest_from_mapping(_load_yaml_mapping(Path(path)))


def core_tool_manifest_path() -> Path:
    return Path(__file__).with_name("core_tools.yaml")


def load_core_tool_manifest() -> ManifestIndex:
    return load_manifest_file(core_tool_manifest_path())
