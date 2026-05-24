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
    "staging": {
        "backend": "sqlite",
        "enabled": True,
    },
    "artifacts": {
        "backend": "sqlite",
        "max_preview_chars": 500,
    },
    "hydration": {
        "enabled": True,
        "default_budget_bytes": 4096,
        "view_budgets": {
            "metadata": 0,
            "summary": 1024,
            "redacted": 4096,
            "full": 8192,
        },
        "full_allowed_routes": ["local", "local-model", "trusted-local"],
        "denied_routes": [],
        "secret_data_classes": ["secrets", "credentials", "tokens", "private_key"],
        "allow_secret_full": False,
    },
    "policy": {
        "bundle_path": None,
    },
    "triage": {
        "low_risk_latency_budget_ms": 150,
        "llm_evaluator_enabled": False,
    },
    "runtime": {
        "allowed_roots": [],
        "denied_roots": [],
        "allowed_hosts": [],
        "denied_hosts": [],
        "allow_private_network": False,
    },
    "provider_egress": {
        "enabled": True,
        "route": "chat_completions",
        "streaming_posture": "request_payload_only",
    },
    "memory_governance": {
        "enabled": True,
        "action": "redact",
        "covered_routes": [
            "system_prompt_block",
            "prefetch_query",
            "prefetch_result",
            "queue_prefetch_query",
            "sync_turn",
            "tool_call_args",
            "tool_result",
            "session_end_messages",
            "pre_compress_messages",
            "pre_compress_result",
            "memory_write",
            "delegation",
        ],
    },
    "plugin_mcp_admission": {
        "enabled": True,
        "trusted_plugin_sources": ["bundled"],
        "allowed_plugins": [],
        "plugin_trust": {},
        "allowed_mcp_servers": [],
        "mcp_server_trust": {},
        "require_declared_plugin_tools": True,
        "require_declared_mcp_tools": True,
        "allow_mcp_tools_include_as_manifest": True,
        "audit_all_decisions": False,
    },
    "gateway_identity": {
        "enabled": True,
        "unmapped_action": "deny",
        "audit_all_decisions": True,
        "assignments": {},
    },
    "cron_governance": {
        "enabled": True,
        "require_owner": True,
        "require_intent": True,
        "require_expiry": True,
        "require_policy_context": True,
        "max_ttl_days": 90,
        "audit_all_decisions": True,
    },
    "sandbox": {
        "enforce_manifests": True,
    },
    "developer_fast_path": {
        "enabled": True,
        "no_egress_default": True,
        "subject_ids": ["local-agent"],
        "workspace_roots": [],
        "owner_workspace_roots": {},
        "allowed_tools": ["read_file", "search_files", "write_file", "patch"],
        "allowed_side_effects": ["filesystem_read", "filesystem_write"],
        "denied_path_markers": [
            ".env",
            ".pem",
            ".key",
            ".p12",
            "id_rsa",
            "id_dsa",
            "secrets",
            "credentials",
            "credential",
            "token",
            "production",
            "prod",
            ".kube",
            "terraform.tfstate",
        ],
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
