"""Sandbox manifest/profile enforcement for proposed tool calls."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from enterprise.contracts import DecisionOutcome, RiskTier
from enterprise.manifests.schema import ToolCapability
from enterprise.sandbox.profiles import get_sandbox_profile
from enterprise.triage.detectors import DetectorFinding, SECRET_PATTERNS


PATH_ARG_KEYS = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "file_paths",
        "target",
        "target_file",
        "target_path",
        "directory",
        "directories",
        "cwd",
        "workdir",
        "working_directory",
    }
)

NETWORK_ARG_KEYS = frozenset(
    {
        "url",
        "urls",
        "uri",
        "uris",
        "href",
        "endpoint",
        "endpoints",
        "base_url",
        "api_url",
        "target_url",
        "host",
        "hosts",
        "domain",
        "domains",
    }
)

ENV_ARG_KEYS = frozenset(
    {
        "env",
        "environment",
        "env_vars",
        "extra_env",
        "docker_env",
        "forward_env",
        "docker_forward_env",
    }
)

FILE_WRITE_TOOLS = frozenset({"write_file", "patch"})
FILE_READ_TOOLS = frozenset({"read_file", "search_files"})
PROCESS_TOOLS = frozenset({"terminal", "process"})
CODE_TOOLS = frozenset({"execute_code"})
SENSITIVE_ENV_KEY_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")


@dataclass(frozen=True)
class SandboxObservation:
    sandbox_profile: str = ""
    observed_side_effects: tuple[str, ...] = ()
    resource_paths: tuple[str, ...] = ()
    network_destinations: tuple[str, ...] = ()
    env_key_count: int = 0
    env_secret_like: bool = False


@dataclass(frozen=True)
class SandboxDecision:
    observation: SandboxObservation
    findings: tuple[DetectorFinding, ...] = ()

    @property
    def allowed(self) -> bool:
        return not self.findings


def evaluate_sandbox(
    tool_name: str,
    tool_args: Mapping[str, Any],
    capability: ToolCapability | None,
    *,
    enforce_manifests: bool = True,
) -> SandboxDecision:
    """Evaluate observed tool-call intent against manifest sandbox metadata."""

    resource_paths = tuple(_extract_values_for_keys(tool_args, PATH_ARG_KEYS))
    network_destinations = tuple(_extract_values_for_keys(tool_args, NETWORK_ARG_KEYS))
    env_values = _extract_env_values(tool_args)
    observed_side_effects = _observed_side_effects(
        tool_name,
        tool_args,
        resource_paths=resource_paths,
        network_destinations=network_destinations,
    )
    observation = SandboxObservation(
        sandbox_profile=capability.sandbox_profile if capability else "",
        observed_side_effects=observed_side_effects,
        resource_paths=resource_paths,
        network_destinations=network_destinations,
        env_key_count=len(env_values),
        env_secret_like=_env_secret_like(env_values),
    )

    if not enforce_manifests or capability is None:
        return SandboxDecision(observation=observation)

    findings: list[DetectorFinding] = []
    profile = get_sandbox_profile(capability.sandbox_profile)
    if profile is None:
        findings.append(
            DetectorFinding(
                detector="sandbox:unknown_profile",
                outcome=DecisionOutcome.DENY,
                risk_tier=RiskTier.HIGH,
                reason=f"Sandbox profile is not defined: {capability.sandbox_profile}",
            )
        )
    else:
        allowed_by_profile = set(profile.allowed_side_effects)
        for side_effect in observed_side_effects:
            if side_effect not in allowed_by_profile:
                findings.append(
                    DetectorFinding(
                        detector="sandbox:profile_side_effect_blocked",
                        outcome=DecisionOutcome.DENY,
                        risk_tier=RiskTier.HIGH,
                        reason=(
                            f"Observed side effect {side_effect!r} is not allowed by "
                            f"sandbox profile {profile.name!r}"
                        ),
                    )
                )
        if env_values and not profile.allow_env_forwarding:
            findings.append(
                DetectorFinding(
                    detector="sandbox:env_forwarding_blocked",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Sandbox profile {profile.name!r} does not allow explicit environment forwarding.",
                )
            )

    declared = set(capability.side_effects)
    for side_effect in observed_side_effects:
        if side_effect not in declared:
            findings.append(
                DetectorFinding(
                    detector="sandbox:undeclared_side_effect",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Observed side effect {side_effect!r} is not declared by tool {tool_name!r}.",
                )
            )

    if observation.env_secret_like:
        findings.append(
            DetectorFinding(
                detector="sandbox:env_secret_forwarding",
                outcome=DecisionOutcome.DENY,
                risk_tier=RiskTier.CRITICAL,
                reason="Tool arguments attempt to forward secret-like environment data.",
            )
        )

    return SandboxDecision(observation=observation, findings=tuple(findings))


def _observed_side_effects(
    tool_name: str,
    tool_args: Mapping[str, Any],
    *,
    resource_paths: tuple[str, ...],
    network_destinations: tuple[str, ...],
) -> tuple[str, ...]:
    observed: list[str] = []
    if tool_name in PROCESS_TOOLS or _has_any_key(tool_args, frozenset({"command", "cmd"})):
        observed.append("process_spawn")
    if tool_name in CODE_TOOLS or _has_any_key(tool_args, frozenset({"code", "script"})):
        observed.append("code_execution")
    if resource_paths:
        if tool_name == "patch":
            observed.extend(["filesystem_read", "filesystem_write"])
        elif tool_name in FILE_WRITE_TOOLS:
            observed.append("filesystem_write")
        else:
            observed.append("filesystem_read")
    if network_destinations:
        observed.append("network_egress")
    return tuple(dict.fromkeys(observed))


def _has_any_key(value: Any, keys: frozenset[str]) -> bool:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            if str(raw_key).lower() in keys:
                return True
            if _has_any_key(item, keys):
                return True
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return any(_has_any_key(item, keys) for item in value)
    return False


def _extract_values_for_keys(value: Any, keys: frozenset[str]) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).lower()
            if key in keys:
                found.extend(_string_values(item))
            found.extend(_extract_values_for_keys(item, keys))
        return found
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        for item in value:
            found.extend(_extract_values_for_keys(item, keys))
    return found


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Path):
        return [str(value)]
    if isinstance(value, Mapping):
        values: list[str] = []
        for item in value.values():
            values.extend(_string_values(item))
        return values
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        values: list[str] = []
        for item in value:
            values.extend(_string_values(item))
        return values
    return []


def _extract_env_values(value: Any) -> dict[str, str]:
    found: dict[str, str] = {}
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key)
            if key.lower() in ENV_ARG_KEYS:
                found.update(_env_mapping(item))
            else:
                found.update(_extract_env_values(item))
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        for item in value:
            found.update(_extract_env_values(item))
    return found


def _env_mapping(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key): str(item) for key, item in value.items()}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return {str(item): "" for item in value}
    return {}


def _env_secret_like(values: Mapping[str, str]) -> bool:
    for key, value in values.items():
        upper_key = key.upper()
        if any(marker in upper_key for marker in SENSITIVE_ENV_KEY_MARKERS):
            return True
        for _name, pattern in SECRET_PATTERNS:
            if pattern.search(value):
                return True
    return False
