"""Enterprise configuration helpers.

The enterprise section is disabled by default and deliberately contains no
secrets. Secrets belong in later broker/vault paths, not in config.yaml.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any


DEFAULT_ENTERPRISE_CONFIG: dict[str, Any] = {
    "enabled": False,
    "edition": "developer_secure",
    "fail_closed_high_risk": True,
    "audit": {
        "backend": "sqlite",
    },
    "policy": {
        "bundle_path": None,
    },
    "triage": {
        "low_risk_latency_budget_ms": 150,
        "llm_evaluator_enabled": False,
    },
    "sandbox": {
        "enforce_manifests": True,
    },
    "developer_fast_path": {
        "enabled": True,
        "no_egress_default": True,
    },
}


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def enterprise_config_from_root(root_config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return the enterprise config with defaults filled in."""
    if not root_config:
        return copy.deepcopy(DEFAULT_ENTERPRISE_CONFIG)
    section = root_config.get("enterprise", {})
    if not isinstance(section, Mapping):
        section = {}
    return _deep_merge(DEFAULT_ENTERPRISE_CONFIG, section)


def load_enterprise_config(root_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Load enterprise config from a supplied root config or Hermes config.yaml."""
    if root_config is None:
        from hermes_cli.config import load_config

        root_config = load_config()
    return enterprise_config_from_root(root_config)
