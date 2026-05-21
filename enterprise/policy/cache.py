"""Small deterministic policy-decision cache."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from enterprise.contracts import PolicyDecision


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class PolicyCacheKey:
    policy_version: str
    action_hash: str
    subject_id: str
    tool_name: str
    data_classes: tuple[str, ...] = ()
    expires_at: str = ""

    @classmethod
    def build(
        cls,
        *,
        policy_version: str,
        action_hash: str,
        subject_id: str,
        tool_name: str,
        data_classes: tuple[str, ...] = (),
        expires_at: str = "",
    ) -> "PolicyCacheKey":
        return cls(
            policy_version=policy_version,
            action_hash=action_hash,
            subject_id=subject_id,
            tool_name=tool_name,
            data_classes=tuple(sorted(data_classes)),
            expires_at=expires_at,
        )


class PolicyDecisionCache:
    def __init__(self, *, now: datetime | None = None):
        self._entries: dict[PolicyCacheKey, PolicyDecision] = {}
        self.now = now

    def set(
        self,
        *,
        subject_id: str,
        tool_name: str,
        data_classes: tuple[str, ...],
        decision: PolicyDecision,
    ) -> PolicyCacheKey:
        key = PolicyCacheKey.build(
            policy_version=decision.policy_version,
            action_hash=decision.action_hash,
            subject_id=subject_id,
            tool_name=tool_name,
            data_classes=data_classes,
            expires_at=decision.expires_at,
        )
        self._entries[key] = decision
        return key

    def get(self, key: PolicyCacheKey) -> PolicyDecision | None:
        decision = self._entries.get(key)
        if decision is None:
            return None
        if self._is_expired(key.expires_at or decision.expires_at):
            self._entries.pop(key, None)
            return None
        return decision

    def clear(self) -> None:
        self._entries.clear()

    def _is_expired(self, expires_at: str) -> bool:
        parsed = _parse_time(expires_at)
        if parsed is None:
            return False
        return parsed <= (self.now or datetime.now(timezone.utc))
