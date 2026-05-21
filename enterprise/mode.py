"""Enterprise mode resolution.

This module is intentionally small and side-effect free so core Hermes adapter
hooks can import it safely once enforcement slices start landing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from enterprise.config import load_enterprise_config


class EnterpriseEdition(str, Enum):
    DEVELOPER_SECURE = "developer_secure"
    TEAM = "team"
    ENTERPRISE = "enterprise"
    REGULATED = "regulated"


@dataclass(frozen=True)
class EnterpriseMode:
    enabled: bool = False
    edition: EnterpriseEdition = EnterpriseEdition.DEVELOPER_SECURE
    fail_closed_high_risk: bool = True

    @classmethod
    def from_config(cls, root_config: Mapping[str, Any] | None = None) -> "EnterpriseMode":
        cfg = load_enterprise_config(root_config)
        return cls(
            enabled=bool(cfg.get("enabled", False)),
            edition=EnterpriseEdition(str(cfg.get("edition", EnterpriseEdition.DEVELOPER_SECURE.value))),
            fail_closed_high_risk=bool(cfg.get("fail_closed_high_risk", True)),
        )

    @property
    def is_enforcing(self) -> bool:
        return self.enabled


def is_enterprise_enabled(root_config: Mapping[str, Any] | None = None) -> bool:
    """Return whether enterprise enforcement is enabled for a root config."""
    return EnterpriseMode.from_config(root_config).enabled
