"""Developer local fast path policy for low-blast-radius workspace actions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from enterprise.contracts import DecisionOutcome, RuntimeTriageDecision, stable_hash
from enterprise.manifests.schema import ToolCapability
from enterprise.sandbox import SandboxDecision


DEFAULT_ALLOWED_TOOLS = frozenset({"read_file", "search_files", "write_file", "patch"})
DEFAULT_ALLOWED_SIDE_EFFECTS = frozenset({"filesystem_read", "filesystem_write"})
DEFAULT_DENIED_PATH_MARKERS = (
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
)
BLOCKING_OUTCOMES = frozenset({DecisionOutcome.DENY, DecisionOutcome.QUARANTINE})


@dataclass(frozen=True)
class FastPathDecision:
    """Result of developer fast-path evaluation."""

    allowed: bool
    reason: str
    detectors: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


def apply_developer_fast_path(
    triage_decision: RuntimeTriageDecision,
    *,
    subject_id: str,
    tool_name: str,
    action_hash: str,
    capability: ToolCapability | None,
    sandbox_decision: SandboxDecision,
    enterprise_cfg: Mapping[str, Any],
) -> tuple[RuntimeTriageDecision, FastPathDecision]:
    """Allow owner-scoped, sandbox-only, no-egress local workspace actions."""
    decision = evaluate_developer_fast_path(
        subject_id=subject_id,
        tool_name=tool_name,
        capability=capability,
        sandbox_decision=sandbox_decision,
        triage_decision=triage_decision,
        enterprise_cfg=enterprise_cfg,
    )
    if not decision.allowed:
        return triage_decision, decision

    detectors = tuple(dict.fromkeys([*triage_decision.detectors, *decision.detectors]))
    reason = f"{triage_decision.reason} {decision.reason}".strip()
    payload = {
        "action_hash": action_hash,
        "subject_id": subject_id,
        "tool_name": tool_name,
        "previous_decision_id": triage_decision.decision_id,
        "outcome": DecisionOutcome.ALLOW.value,
        "detectors": list(detectors),
        "reason": reason,
    }
    return (
        RuntimeTriageDecision(
            decision_id=stable_hash(payload)[:32],
            outcome=DecisionOutcome.ALLOW,
            risk_tier=triage_decision.risk_tier,
            detectors=list(detectors),
            latency_ms=triage_decision.latency_ms,
            escalated=triage_decision.escalated,
            reason=reason,
        ),
        decision,
    )


def evaluate_developer_fast_path(
    *,
    subject_id: str,
    tool_name: str,
    capability: ToolCapability | None,
    sandbox_decision: SandboxDecision,
    triage_decision: RuntimeTriageDecision,
    enterprise_cfg: Mapping[str, Any],
) -> FastPathDecision:
    fast_cfg = enterprise_cfg.get("developer_fast_path", {})
    if not isinstance(fast_cfg, Mapping):
        fast_cfg = {}
    if not bool(fast_cfg.get("enabled", True)):
        return _deny("Developer fast path is disabled.", "developer_fast_path:disabled")
    if triage_decision.outcome in BLOCKING_OUTCOMES:
        return _deny("Developer fast path cannot override deny/quarantine decisions.", "developer_fast_path:blocking_decision")
    if sandbox_decision.findings:
        return _deny("Developer fast path cannot override sandbox findings.", "developer_fast_path:sandbox_findings")

    allowed_tools = set(_as_tuple(fast_cfg.get("allowed_tools"))) or set(DEFAULT_ALLOWED_TOOLS)
    if tool_name not in allowed_tools:
        return _deny(f"Tool is not eligible for developer fast path: {tool_name}", "developer_fast_path:tool_not_allowed")

    effects = set(sandbox_decision.observation.observed_side_effects)
    if not effects and capability is not None:
        effects = set(capability.side_effects)
    allowed_effects = set(_as_tuple(fast_cfg.get("allowed_side_effects"))) or set(DEFAULT_ALLOWED_SIDE_EFFECTS)
    if not effects or not effects.issubset(allowed_effects):
        return _deny("Action has side effects outside the local workspace fast path.", "developer_fast_path:side_effects_not_allowed")
    if bool(fast_cfg.get("no_egress_default", True)) and (
        "network_egress" in effects or sandbox_decision.observation.network_destinations
    ):
        return _deny("Developer fast path does not allow network egress.", "developer_fast_path:egress_blocked")
    if sandbox_decision.observation.env_key_count:
        return _deny("Developer fast path does not allow explicit environment forwarding.", "developer_fast_path:env_blocked")

    paths = tuple(sandbox_decision.observation.resource_paths)
    if not paths:
        return _deny("Developer fast path requires explicit workspace paths.", "developer_fast_path:no_paths")
    roots = _workspace_roots_for(subject_id, enterprise_cfg, fast_cfg)
    if not roots:
        return _deny("No owner workspace roots are configured for developer fast path.", "developer_fast_path:no_workspace")
    denied_roots = _resolved_paths(_as_tuple(_runtime_cfg(enterprise_cfg).get("denied_roots")))
    resolved_paths = _resolved_paths(paths)
    if any(_inside_any(path, denied_roots) for path in resolved_paths):
        return _deny("Action targets a denied root.", "developer_fast_path:denied_root")
    if any(not _inside_any(path, roots) for path in resolved_paths):
        return _deny("Action targets a path outside the owner workspace.", "developer_fast_path:outside_workspace")
    denied_markers = _as_tuple(fast_cfg.get("denied_path_markers")) or DEFAULT_DENIED_PATH_MARKERS
    if any(_has_denied_marker(path, denied_markers) for path in resolved_paths):
        return _deny("Action targets a secret or production-like path.", "developer_fast_path:sensitive_path")

    return FastPathDecision(
        allowed=True,
        reason="Developer local fast path allowed owner-scoped no-egress workspace action.",
        detectors=("developer_fast_path:owner_workspace",),
        metadata={
            "fast_path": True,
            "subject_id": subject_id,
            "workspace_roots": [str(root) for root in roots],
            "resource_path_count": len(resolved_paths),
            "observed_side_effects": sorted(effects),
        },
    )


def _deny(reason: str, detector: str) -> FastPathDecision:
    return FastPathDecision(
        allowed=False,
        reason=reason,
        detectors=(detector,),
        metadata={"fast_path": False, "fast_path_reason": reason},
    )


def _workspace_roots_for(
    subject_id: str,
    enterprise_cfg: Mapping[str, Any],
    fast_cfg: Mapping[str, Any],
) -> tuple[Path, ...]:
    owner_roots_cfg = fast_cfg.get("owner_workspace_roots", {})
    if isinstance(owner_roots_cfg, Mapping):
        owner_roots = _as_tuple(owner_roots_cfg.get(subject_id))
        if owner_roots:
            return _resolved_paths(owner_roots)
        if owner_roots_cfg:
            return ()

    subject_ids = set(_as_tuple(fast_cfg.get("subject_ids")))
    if subject_ids and subject_id not in subject_ids:
        return ()
    workspace_roots = _as_tuple(fast_cfg.get("workspace_roots"))
    if workspace_roots:
        return _resolved_paths(workspace_roots)
    runtime_roots = _as_tuple(_runtime_cfg(enterprise_cfg).get("allowed_roots"))
    return _resolved_paths(runtime_roots)


def _runtime_cfg(enterprise_cfg: Mapping[str, Any]) -> Mapping[str, Any]:
    runtime_cfg = enterprise_cfg.get("runtime", {})
    if isinstance(runtime_cfg, Mapping):
        return runtime_cfg
    return {}


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        return tuple(str(item) for item in value if str(item))
    return ()


def _resolved_paths(paths: Iterable[str | Path]) -> tuple[Path, ...]:
    return tuple(Path(path).expanduser().resolve(strict=False) for path in paths if str(path))


def _inside_any(path: Path, roots: Iterable[Path]) -> bool:
    return any(_is_relative_to(path, root) for root in roots)


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return child == parent


def _has_denied_marker(path: Path, markers: Iterable[str]) -> bool:
    normalized = str(path).lower()
    return any(str(marker).lower() in normalized for marker in markers if str(marker))
