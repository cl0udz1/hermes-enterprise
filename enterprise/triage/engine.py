"""Runtime triage engine with deterministic, non-LLM checks."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from enterprise.contracts import (
    AccessGrant,
    DecisionOutcome,
    RiskTier,
    RuntimeTriageDecision,
    stable_hash,
)
from enterprise.manifests import ManifestIndex, load_core_tool_manifest
from enterprise.triage.detectors import (
    DetectorFinding,
    detect_grant_status,
    detect_manifest_mismatch,
    detect_network_policy,
    detect_path_policy,
    detect_secret_patterns,
)


@dataclass(frozen=True)
class TriageRequest:
    subject_id: str
    tool_name: str
    tool_args: Mapping[str, Any] = field(default_factory=dict)
    action_hash: str = ""
    requested_side_effects: tuple[str, ...] = ()
    resource_paths: tuple[str | Path, ...] = ()
    network_destinations: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    grants: tuple[AccessGrant, ...] = ()
    extra_findings: tuple[DetectorFinding, ...] = ()
    created_at: str = ""

    def resolved_action_hash(self) -> str:
        if self.action_hash:
            return self.action_hash
        return stable_hash(
            {
                "subject_id": self.subject_id,
                "tool_name": self.tool_name,
                "tool_args": dict(self.tool_args),
                "requested_side_effects": list(self.requested_side_effects),
                "resource_paths": [str(path) for path in self.resource_paths],
                "network_destinations": list(self.network_destinations),
                "data_classes": list(self.data_classes),
            }
        )


class RuntimeTriageEngine:
    """Fast triage for covered runtime actions.

    This engine deliberately performs deterministic checks only. LLM evaluators
    belong behind an explicit escalation path later, not in the MVP-0 hot path.
    """

    def __init__(
        self,
        *,
        manifest_index: ManifestIndex | None = None,
        allowed_roots: tuple[str | Path, ...] = (),
        denied_roots: tuple[str | Path, ...] = (),
        allowed_hosts: tuple[str, ...] = (),
        denied_hosts: tuple[str, ...] = (),
        allow_private_network: bool = False,
        now: datetime | None = None,
    ):
        self.manifest_index = manifest_index or load_core_tool_manifest()
        self.allowed_roots = allowed_roots
        self.denied_roots = denied_roots
        self.allowed_hosts = allowed_hosts
        self.denied_hosts = denied_hosts
        self.allow_private_network = allow_private_network
        self.now = now

    def evaluate(self, request: TriageRequest) -> RuntimeTriageDecision:
        started = time.perf_counter()
        capability = self.manifest_index.get(request.tool_name)
        findings: list[DetectorFinding] = list(request.extra_findings)

        findings.extend(
            detect_manifest_mismatch(
                capability,
                tool_name=request.tool_name,
                requested_side_effects=request.requested_side_effects,
            )
        )
        findings.extend(detect_secret_patterns(request.tool_args))
        findings.extend(
            detect_path_policy(
                request.resource_paths,
                allowed_roots=self.allowed_roots,
                denied_roots=self.denied_roots,
            )
        )
        findings.extend(
            detect_network_policy(
                request.network_destinations,
                allowed_hosts=self.allowed_hosts,
                denied_hosts=self.denied_hosts,
                allow_private=self.allow_private_network,
            )
        )
        findings.extend(
            detect_grant_status(
                request.grants,
                now=self.now or datetime.now(timezone.utc),
            )
        )

        latency_ms = max(0, int((time.perf_counter() - started) * 1000))
        outcome = self._outcome_for(capability, findings)
        risk_tier = self._risk_tier_for(capability, findings)
        detectors = [finding.detector for finding in findings] or ["deterministic_allow"]
        reason = "; ".join(finding.reason for finding in findings)
        if not reason:
            reason = "Deterministic triage allowed the action."

        decision_payload = {
            "subject_id": request.subject_id,
            "tool_name": request.tool_name,
            "action_hash": request.resolved_action_hash(),
            "outcome": outcome.value,
            "risk_tier": risk_tier.value,
            "detectors": detectors,
            "reason": reason,
        }
        return RuntimeTriageDecision(
            decision_id=stable_hash(decision_payload)[:32],
            outcome=outcome,
            risk_tier=risk_tier,
            detectors=detectors,
            latency_ms=latency_ms,
            escalated=False,
            reason=reason,
        )

    @staticmethod
    def _outcome_for(
        capability: Any,
        findings: list[DetectorFinding],
    ) -> DecisionOutcome:
        if any(finding.outcome is DecisionOutcome.DENY for finding in findings):
            return DecisionOutcome.DENY
        if any(finding.outcome is DecisionOutcome.QUARANTINE for finding in findings):
            return DecisionOutcome.QUARANTINE
        if capability and capability.approval_required:
            return DecisionOutcome.APPROVAL_REQUIRED
        if capability and capability.is_high_risk:
            return DecisionOutcome.APPROVAL_REQUIRED
        return DecisionOutcome.ALLOW

    @staticmethod
    def _risk_tier_for(capability: Any, findings: list[DetectorFinding]) -> RiskTier:
        tiers = [finding.risk_tier for finding in findings]
        if capability is not None:
            tiers.append(capability.risk_tier)
        order = {
            RiskTier.LOW: 0,
            RiskTier.MODERATE: 1,
            RiskTier.HIGH: 2,
            RiskTier.CRITICAL: 3,
        }
        if not tiers:
            return RiskTier.LOW
        return max(tiers, key=lambda tier: order[tier])
