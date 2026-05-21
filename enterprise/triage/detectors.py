"""Fast deterministic detectors for enterprise runtime triage."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from enterprise.contracts import AccessGrant, DecisionOutcome, RiskTier
from enterprise.manifests.schema import ToolCapability


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "generic_secret_assignment",
        re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]{12,}"),
    ),
)


@dataclass(frozen=True)
class DetectorFinding:
    detector: str
    outcome: DecisionOutcome
    risk_tier: RiskTier
    reason: str


def _flatten_values(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _flatten_values(item)
        return
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            yield from _flatten_values(item)
        return
    yield str(value)


def detect_secret_patterns(value: Any) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    joined = "\n".join(_flatten_values(value))
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(joined):
            findings.append(
                DetectorFinding(
                    detector=f"secret_pattern:{name}",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.CRITICAL,
                    reason=f"Detected secret-like content: {name}",
                )
            )
    return findings


def _resolve_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def detect_path_policy(
    paths: Iterable[str | Path],
    *,
    allowed_roots: Iterable[str | Path] = (),
    denied_roots: Iterable[str | Path] = (),
) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    resolved_allowed = [_resolve_path(root) for root in allowed_roots]
    resolved_denied = [_resolve_path(root) for root in denied_roots]

    for raw_path in paths:
        path = _resolve_path(raw_path)
        if any(path == denied or _is_relative_to(path, denied) for denied in resolved_denied):
            findings.append(
                DetectorFinding(
                    detector="path_policy:denied_root",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Path is inside a denied root: {path}",
                )
            )
            continue

        if resolved_allowed and not any(
            path == allowed or _is_relative_to(path, allowed) for allowed in resolved_allowed
        ):
            findings.append(
                DetectorFinding(
                    detector="path_policy:outside_allowed_roots",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Path is outside allowed roots: {path}",
                )
            )
    return findings


def _host_matches(host: str, patterns: Iterable[str]) -> bool:
    normalized = host.lower().strip(".")
    for pattern in patterns:
        candidate = str(pattern).lower().strip(".")
        if normalized == candidate or normalized.endswith(f".{candidate}"):
            return True
    return False


def _host_from_destination(destination: str) -> str:
    parsed = urlparse(destination)
    if parsed.hostname:
        return parsed.hostname
    if "://" not in destination:
        parsed = urlparse(f"//{destination}")
        if parsed.hostname:
            return parsed.hostname
    return destination.split("/", 1)[0].split(":", 1)[0]


def _is_private_host(host: str) -> bool:
    normalized = host.lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def detect_network_policy(
    destinations: Iterable[str],
    *,
    allowed_hosts: Iterable[str] = (),
    denied_hosts: Iterable[str] = (),
    allow_private: bool = False,
) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    allowed = tuple(allowed_hosts)
    denied = tuple(denied_hosts)

    for destination in destinations:
        host = _host_from_destination(destination)
        if not host:
            findings.append(
                DetectorFinding(
                    detector="network_policy:invalid_destination",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Network destination is invalid: {destination}",
                )
            )
            continue
        if not allow_private and _is_private_host(host):
            findings.append(
                DetectorFinding(
                    detector="network_policy:private_host",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Private network destination is not allowed: {host}",
                )
            )
            continue
        if denied and _host_matches(host, denied):
            findings.append(
                DetectorFinding(
                    detector="network_policy:denied_host",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Network destination is denied: {host}",
                )
            )
            continue
        if allowed and not _host_matches(host, allowed):
            findings.append(
                DetectorFinding(
                    detector="network_policy:not_allowed_host",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Network destination is outside allow-list: {host}",
                )
            )
    return findings


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def detect_grant_status(
    grants: Iterable[AccessGrant],
    *,
    now: datetime | None = None,
) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    current = now or datetime.now(timezone.utc)
    for grant in grants:
        if grant.revoked_at:
            findings.append(
                DetectorFinding(
                    detector="grant_status:revoked",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Grant is revoked: {grant.grant_id}",
                )
            )
            continue
        expires_at = _parse_time(grant.expires_at)
        if expires_at is None:
            findings.append(
                DetectorFinding(
                    detector="grant_status:invalid_expiry",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Grant expiry is invalid: {grant.grant_id}",
                )
            )
            continue
        if expires_at <= current:
            findings.append(
                DetectorFinding(
                    detector="grant_status:expired",
                    outcome=DecisionOutcome.DENY,
                    risk_tier=RiskTier.HIGH,
                    reason=f"Grant is expired: {grant.grant_id}",
                )
            )
    return findings


def detect_manifest_mismatch(
    capability: ToolCapability | None,
    *,
    tool_name: str,
    requested_side_effects: Iterable[str],
) -> list[DetectorFinding]:
    if capability is None:
        return [
            DetectorFinding(
                detector="manifest:missing",
                outcome=DecisionOutcome.DENY,
                risk_tier=RiskTier.HIGH,
                reason=f"No capability manifest for tool: {tool_name}",
            )
        ]

    requested = {str(effect) for effect in requested_side_effects}
    if not requested:
        return []
    declared = set(capability.side_effects)
    extra = sorted(requested - declared)
    if not extra:
        return []
    return [
        DetectorFinding(
            detector="manifest:side_effect_mismatch",
            outcome=DecisionOutcome.DENY,
            risk_tier=RiskTier.HIGH,
            reason=f"Requested side effects are not declared for {tool_name}: {extra}",
        )
    ]
