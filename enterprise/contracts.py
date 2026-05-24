"""Enterprise runtime contracts.

These dataclasses are intentionally lightweight and stdlib-only. They define the
shape of the control-plane records before runtime enforcement is wired in.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import MISSING, dataclass, field, fields
from enum import Enum
from typing import Any, get_args, get_origin, get_type_hints


class RiskTier(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    QUARANTINE = "quarantine"


class AuditEventType(str, Enum):
    ACTION_PROPOSED = "action_proposed"
    POLICY_DECISION = "policy_decision"
    ACTION_DENIED = "action_denied"
    ACTION_APPROVED = "action_approved"
    ACTION_STAGED = "action_staged"
    ACTION_EXECUTED = "action_executed"
    RESULT_SANITIZED = "result_sanitized"
    PROVIDER_EGRESS_SANITIZED = "provider_egress_sanitized"
    MEMORY_GOVERNANCE_SANITIZED = "memory_governance_sanitized"
    AUTHORITY_ADMISSION_DECISION = "authority_admission_decision"
    SANDBOX_VIOLATION = "sandbox_violation"
    HYDRATION_DECISION = "hydration_decision"
    AUDIT_ERROR = "audit_error"


class HydrationView(str, Enum):
    METADATA = "metadata"
    SUMMARY = "summary"
    REDACTED = "redacted"
    FULL = "full"


class StageStatus(str, Enum):
    STAGED = "staged"
    APPROVED = "approved"
    EXECUTED = "executed"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def stable_json(value: Any) -> str:
    """Serialize a value into deterministic JSON."""
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(value: Any) -> str:
    """Return a stable SHA-256 hash for a JSON-serializable value."""
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _coerce_value(expected_type: Any, value: Any) -> Any:
    origin = get_origin(expected_type)
    args = get_args(expected_type)

    if isinstance(expected_type, type) and issubclass(expected_type, Enum):
        return expected_type(value)
    if origin is list:
        if not isinstance(value, list):
            raise TypeError(f"Expected list, got {type(value).__name__}")
        inner = args[0] if args else Any
        return [_coerce_value(inner, item) for item in value]
    if origin is dict:
        if not isinstance(value, Mapping):
            raise TypeError(f"Expected mapping, got {type(value).__name__}")
        return dict(value)
    return value


class JsonContract:
    """Mixin for deterministic JSON contracts."""

    def to_dict(self) -> dict[str, Any]:
        return {item.name: _json_value(getattr(self, item.name)) for item in fields(self)}

    def to_json(self) -> str:
        return stable_json(self.to_dict())

    def content_hash(self) -> str:
        return stable_hash(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "JsonContract":
        if not isinstance(data, Mapping):
            raise TypeError(f"{cls.__name__}.from_dict expects a mapping")
        kwargs: dict[str, Any] = {}
        type_hints = get_type_hints(cls)
        for item in fields(cls):
            if item.name in data:
                expected_type = type_hints.get(item.name, item.type)
                kwargs[item.name] = _coerce_value(expected_type, data[item.name])
            elif item.default is not MISSING:
                kwargs[item.name] = item.default
            elif item.default_factory is not MISSING:  # type: ignore[attr-defined]
                kwargs[item.name] = item.default_factory()  # type: ignore[misc]
            else:
                raise KeyError(f"Missing required field: {item.name}")
        return cls(**kwargs)

    @classmethod
    def from_json(cls, payload: str) -> "JsonContract":
        return cls.from_dict(json.loads(payload))


@dataclass(frozen=True)
class IntentEnvelope(JsonContract):
    intent_id: str
    subject_id: str
    session_id: str
    purpose: str
    data_classes: list[str] = field(default_factory=list)
    created_at: str = ""


@dataclass(frozen=True)
class ActionManifest(JsonContract):
    action_id: str
    tool_name: str
    tool_args_hash: str
    risk_tier: RiskTier
    side_effects: list[str] = field(default_factory=list)
    sandbox_profile: str = "default"
    requires_approval: bool = False
    created_at: str = ""


@dataclass(frozen=True)
class AuditEvent(JsonContract):
    event_id: str
    event_type: AuditEventType
    subject_id: str
    redacted_preview: str
    raw_sha256: str
    created_at: str
    action_id: str = ""
    decision_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision(JsonContract):
    decision_id: str
    outcome: DecisionOutcome
    reason: str
    policy_version: str
    action_hash: str
    expires_at: str = ""


@dataclass(frozen=True)
class RuntimeTriageDecision(JsonContract):
    decision_id: str
    outcome: DecisionOutcome
    risk_tier: RiskTier
    detectors: list[str]
    latency_ms: int
    escalated: bool
    reason: str = ""


@dataclass(frozen=True)
class ProviderEgressDecision(JsonContract):
    decision_id: str
    route: str
    changed: bool
    findings: list[str]
    raw_sha256: str
    sanitized_sha256: str
    streaming_posture: str = "request_payload_only"
    audit_event_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MemoryGovernanceDecision(JsonContract):
    decision_id: str
    route: str
    changed: bool
    findings: list[str]
    raw_sha256: str
    sanitized_sha256: str
    action: str = "redact"
    audit_event_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuthorityAdmissionDecision(JsonContract):
    decision_id: str
    surface: str
    resource: str
    outcome: DecisionOutcome
    reason: str
    trust_source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    audit_event_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AccessRequest(JsonContract):
    request_id: str
    subject_id: str
    resource: str
    action: str
    reason: str
    risk_tier: RiskTier
    data_classes: list[str] = field(default_factory=list)
    requested_at: str = ""


@dataclass(frozen=True)
class AccessGrant(JsonContract):
    grant_id: str
    request_id: str
    subject_id: str
    resource: str
    actions: list[str]
    expires_at: str
    policy_version: str
    created_at: str = ""
    revoked_at: str = ""


@dataclass(frozen=True)
class ArtifactVaultRecord(JsonContract):
    artifact_id: str
    data_class: str
    content_sha256: str
    redacted_preview: str
    storage_uri: str
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ContextHydrationRequest(JsonContract):
    request_id: str
    artifact_id: str
    subject_id: str
    route: str
    view: HydrationView
    reason: str
    requested_at: str = ""


@dataclass(frozen=True)
class StagedExecutionRecord(JsonContract):
    stage_id: str
    action_hash: str
    subject_id: str
    tool_name: str
    preview_uri: str
    idempotency_key: str
    status: StageStatus
    created_at: str = ""
    approved_by: str = ""


@dataclass(frozen=True)
class GovernanceChangeRecord(JsonContract):
    change_id: str
    actor_id: str
    target: str
    change_type: str
    before_hash: str
    after_hash: str
    reason: str
    created_at: str = ""


@dataclass(frozen=True)
class EvaluationRunRecord(JsonContract):
    run_id: str
    suite: str
    policy_version: str
    passed: bool
    started_at: str
    completed_at: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
