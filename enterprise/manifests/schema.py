"""Capability manifest schema for enterprise tool governance."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from enterprise.contracts import RiskTier


VALID_SIDE_EFFECTS = frozenset(
    {
        "filesystem_read",
        "filesystem_write",
        "process_spawn",
        "code_execution",
        "network_egress",
        "provider_egress",
        "memory_read",
        "memory_write",
        "external_send",
        "browser_state",
        "scheduled_execution",
        "smart_home_action",
        "agent_delegation",
        "user_prompt",
    }
)


@dataclass(frozen=True)
class ToolCapability:
    tool_name: str
    risk_tier: RiskTier
    side_effects: list[str]
    sandbox_profile: str
    approval_required: bool = False
    data_classes: list[str] = field(default_factory=list)
    network_access: bool = False
    model_egress: bool = False
    notes: str = ""

    @classmethod
    def from_mapping(cls, tool_name: str, data: Mapping[str, Any]) -> "ToolCapability":
        if not isinstance(data, Mapping):
            raise TypeError(f"Manifest entry for {tool_name!r} must be a mapping")

        missing = [
            field_name
            for field_name in ("risk_tier", "side_effects", "sandbox_profile")
            if field_name not in data
        ]
        if missing:
            raise ValueError(f"Manifest entry for {tool_name!r} missing required fields: {missing}")

        risk_tier = RiskTier(str(data["risk_tier"]))
        side_effects = data["side_effects"]
        if not isinstance(side_effects, list) or not side_effects:
            raise ValueError(f"Manifest entry for {tool_name!r} must define non-empty side_effects")
        normalized_effects = [str(effect) for effect in side_effects]
        invalid_effects = sorted(set(normalized_effects) - VALID_SIDE_EFFECTS)
        if invalid_effects:
            raise ValueError(f"Manifest entry for {tool_name!r} has invalid side_effects: {invalid_effects}")

        sandbox_profile = str(data["sandbox_profile"]).strip()
        if not sandbox_profile:
            raise ValueError(f"Manifest entry for {tool_name!r} must define sandbox_profile")

        data_classes = data.get("data_classes", [])
        if not isinstance(data_classes, list):
            raise ValueError(f"Manifest entry for {tool_name!r} data_classes must be a list")

        return cls(
            tool_name=tool_name,
            risk_tier=risk_tier,
            side_effects=normalized_effects,
            sandbox_profile=sandbox_profile,
            approval_required=bool(data.get("approval_required", False)),
            data_classes=[str(item) for item in data_classes],
            network_access=bool(data.get("network_access", False)),
            model_egress=bool(data.get("model_egress", False)),
            notes=str(data.get("notes", "")),
        )

    @property
    def is_high_risk(self) -> bool:
        return self.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
