"""Server-side role checks for the enterprise control center."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from enterprise.mode import EnterpriseMode


DEFAULT_ROLE_MATRIX = {
    "view": {"admin", "security_admin", "operator", "manager", "auditor"},
    "approve": {"admin", "security_admin", "operator", "manager"},
    "assign": {"admin", "security_admin", "operator", "manager"},
    "administer": {"admin", "security_admin"},
}


@dataclass(frozen=True)
class ControlCenterSubject:
    subject_id: str
    roles: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class ControlCenterDecision:
    allowed: bool
    subject: ControlCenterSubject
    capability: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "capability": self.capability,
            "reason": self.reason,
            "subject": {
                "subject_id": self.subject.subject_id,
                "roles": list(self.subject.roles),
                "source": self.subject.source,
            },
        }


def evaluate_control_center_access(
    headers: Mapping[str, Any] | None = None,
    *,
    root_config: Mapping[str, Any] | None = None,
    capability: str = "view",
) -> ControlCenterDecision:
    """Evaluate whether a request may access enterprise control-plane APIs."""

    cfg = _control_config(root_config)
    mode = EnterpriseMode.from_config(root_config)
    subject = _subject_from_headers(headers or {}, cfg)
    requested = str(capability or "view").strip().lower()
    allowed_roles = _allowed_roles(cfg, requested)

    if subject.subject_id == "local-admin" and subject.source == "local_bootstrap":
        if _requires_proxy_identity(cfg, mode):
            return ControlCenterDecision(False, subject, requested, "proxy_identity_required")
        return ControlCenterDecision(True, subject, requested, "local_bootstrap_admin")

    if not subject.subject_id:
        return ControlCenterDecision(False, subject, requested, "missing_subject")

    if set(subject.roles).intersection(allowed_roles):
        return ControlCenterDecision(True, subject, requested, "role_allowed")

    return ControlCenterDecision(False, subject, requested, "role_denied")


def _control_config(root_config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    enterprise_cfg: Any = {}
    if isinstance(root_config, Mapping):
        enterprise_cfg = root_config.get("enterprise", {})
    if not isinstance(enterprise_cfg, Mapping):
        return {}
    control_cfg = enterprise_cfg.get("control_center", {})
    return control_cfg if isinstance(control_cfg, Mapping) else {}


def _subject_from_headers(headers: Mapping[str, Any], cfg: Mapping[str, Any]) -> ControlCenterSubject:
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    subject_header = str(cfg.get("subject_header", "x-hermes-subject")).lower()
    roles_header = str(cfg.get("roles_header", "x-hermes-roles")).lower()
    subject_id = normalized.get(subject_header, "").strip()
    roles = _parse_roles(normalized.get(roles_header, ""))
    if not subject_id:
        return ControlCenterSubject("local-admin", ("admin",), "local_bootstrap")
    return ControlCenterSubject(subject_id, roles or ("employee",), "request_header")


def _allowed_roles(cfg: Mapping[str, Any], capability: str) -> set[str]:
    raw_matrix = cfg.get("role_matrix", {})
    if isinstance(raw_matrix, Mapping):
        raw_roles = raw_matrix.get(capability)
        if isinstance(raw_roles, list):
            return {_normalize_role(role) for role in raw_roles if str(role).strip()}
    return set(DEFAULT_ROLE_MATRIX.get(capability, DEFAULT_ROLE_MATRIX["view"]))


def _requires_proxy_identity(cfg: Mapping[str, Any], mode: EnterpriseMode) -> bool:
    if "require_proxy_identity" in cfg:
        return bool(cfg.get("require_proxy_identity"))
    return bool(mode.is_enforcing and cfg.get("enabled") and cfg.get("production"))


def _parse_roles(value: str) -> tuple[str, ...]:
    roles: list[str] = []
    for item in str(value or "").replace(";", ",").split(","):
        role = _normalize_role(item)
        if role and role not in roles:
            roles.append(role)
    return tuple(roles)


def _normalize_role(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
