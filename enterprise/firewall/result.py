"""Tool-result sanitizer for enterprise model-context boundaries."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from enterprise.audit import AuditStore
from enterprise.config import enterprise_config_from_root
from enterprise.contracts import AuditEvent, AuditEventType, stable_hash
from enterprise.mode import EnterpriseMode
from enterprise.triage.detectors import SECRET_PATTERNS


PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "instruction_override",
        re.compile(r"(?i)\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+instructions?\b"),
        "[neutralized instruction override]",
    ),
    (
        "control_tag",
        re.compile(r"(?i)</?(?:system|developer|assistant|tool_result|tool_call|function_call|function)[^>]*>"),
        "[neutralized control tag]",
    ),
    (
        "tool_call_bait",
        re.compile(r"(?i)\b(?:call|invoke|use|run)\s+(?:the\s+)?(?:terminal|write_file|send_message|browser|delegate_task|tool)\b"),
        "[neutralized tool-use bait]",
    ),
)

ROLE_MARKER = re.compile(r"(?im)^\s*(system|developer|assistant|user)\s*:")


@dataclass(frozen=True)
class ResultSanitizerDecision:
    """Result of sanitizing a tool output before it becomes model context."""

    content: Any
    changed: bool
    raw_sha256: str = ""
    findings: tuple[str, ...] = ()
    redacted_preview: str = ""
    audit_event_ids: tuple[str, ...] = ()


def sanitize_tool_result(
    tool_name: str,
    content: Any,
    *,
    tool_call_id: str = "",
    root_config: Mapping[str, Any] | None = None,
    audit_store: AuditStore | None = None,
) -> ResultSanitizerDecision:
    """Sanitize a tool result before the model can see it.

    Enterprise mode is disabled by default. In that mode the content is returned
    byte-for-byte as supplied and no audit storage is touched.
    """

    resolved_config = _resolve_root_config(root_config)
    mode = EnterpriseMode.from_config(resolved_config)
    if not mode.is_enforcing:
        return ResultSanitizerDecision(content=content, changed=False)

    raw_sha256 = stable_hash(_json_safe(content))
    sanitized, findings = _sanitize_content(content, raw_sha256=raw_sha256)
    unique_findings = tuple(dict.fromkeys(findings))
    changed = sanitized != content
    preview = _redacted_preview(sanitized)
    audit_event_ids: tuple[str, ...] = ()

    if changed:
        try:
            audit_event_ids = _append_result_sanitized_event(
                audit_store or AuditStore(),
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                raw_sha256=raw_sha256,
                findings=unique_findings,
                redacted_preview=preview,
            )
        except Exception:
            audit_event_ids = ()

    return ResultSanitizerDecision(
        content=sanitized,
        changed=changed,
        raw_sha256=raw_sha256,
        findings=unique_findings,
        redacted_preview=preview,
        audit_event_ids=audit_event_ids,
    )


def _resolve_root_config(root_config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if root_config is not None:
        return root_config
    return _cached_root_config()


@lru_cache(maxsize=1)
def _cached_root_config() -> Mapping[str, Any]:
    from hermes_cli.config import load_config

    return load_config()


def _sanitize_content(content: Any, *, raw_sha256: str) -> tuple[Any, list[str]]:
    if isinstance(content, str):
        sanitized, findings = _sanitize_text(content)
        if findings:
            sanitized = _label(raw_sha256, findings) + sanitized
        return sanitized, findings

    if isinstance(content, list):
        sanitized_items: list[Any] = []
        findings: list[str] = []
        for item in content:
            sanitized_item, item_findings = _sanitize_content(item, raw_sha256=raw_sha256)
            sanitized_items.append(sanitized_item)
            findings.extend(item_findings)
        if findings:
            sanitized_items.insert(0, {"type": "text", "text": _label(raw_sha256, findings).rstrip()})
        return sanitized_items, findings

    if isinstance(content, Mapping):
        sanitized_dict: dict[str, Any] = {}
        findings: list[str] = []
        for key, value in content.items():
            sanitized_value, value_findings = _sanitize_content(value, raw_sha256=raw_sha256)
            sanitized_dict[str(key)] = sanitized_value
            findings.extend(value_findings)
        if findings:
            return (
                json.dumps(
                    {
                        "enterprise_sanitized": True,
                        "raw_sha256": raw_sha256,
                        "findings": tuple(dict.fromkeys(findings)),
                        "content": sanitized_dict,
                    },
                    ensure_ascii=False,
                ),
                findings,
            )
        return sanitized_dict, findings

    return content, []


def _sanitize_text(text: str) -> tuple[str, list[str]]:
    sanitized = text
    findings: list[str] = []

    for name, pattern in SECRET_PATTERNS:
        if name == "generic_secret_assignment":
            sanitized, count = pattern.subn(_generic_secret_replacement(name), sanitized)
        else:
            sanitized, count = pattern.subn(f"[REDACTED:{name}]", sanitized)
        if count:
            findings.append(f"secret_pattern:{name}")

    def _role_replacement(match: re.Match[str]) -> str:
        role = match.group(1).lower()
        return f"[neutralized role marker:{role}]:"

    sanitized, count = ROLE_MARKER.subn(_role_replacement, sanitized)
    if count:
        findings.append("prompt_injection:role_marker")

    for name, pattern, replacement in PROMPT_INJECTION_PATTERNS:
        sanitized, count = pattern.subn(replacement, sanitized)
        if count:
            findings.append(f"prompt_injection:{name}")

    return sanitized, findings


def _generic_secret_replacement(name: str):
    def _replace(match: re.Match[str]) -> str:
        matched = match.group(0)
        if "[REDACTED:" in matched:
            return matched
        return f"[REDACTED:{name}]"

    return _replace


def _label(raw_sha256: str, findings: Iterable[str]) -> str:
    finding_text = ", ".join(dict.fromkeys(findings))
    return (
        "Enterprise result sanitizer: untrusted tool output was sanitized before model context.\n"
        f"Raw SHA-256: {raw_sha256}\n"
        f"Findings: {finding_text}\n"
        "--- sanitized data ---\n"
    )


def _append_result_sanitized_event(
    audit_store: AuditStore,
    *,
    tool_name: str,
    tool_call_id: str,
    raw_sha256: str,
    findings: tuple[str, ...],
    redacted_preview: str,
) -> tuple[str, ...]:
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = stable_hash(
        {
            "event_type": AuditEventType.RESULT_SANITIZED.value,
            "tool_name": tool_name,
            "tool_call_id": tool_call_id,
            "raw_sha256": raw_sha256,
            "created_at": created_at,
        }
    )[:32]
    audit_store.append_event(
        AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.RESULT_SANITIZED,
            subject_id="tool-result-sanitizer",
            action_id=tool_call_id,
            redacted_preview=redacted_preview,
            raw_sha256=raw_sha256,
            created_at=created_at,
            metadata={
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                "findings": list(findings),
            },
        )
    )
    return (event_id,)


def _redacted_preview(content: Any, max_len: int = 240) -> str:
    text = _plain_text(content)
    text = " ".join(text.split())
    if len(text) > max_len:
        return text[: max_len - 1] + "..."
    return text


def _plain_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if isinstance(value.get("text"), str):
            return value["text"]
        return " ".join(_plain_text(item) for item in value.values())
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return " ".join(_plain_text(item) for item in value)
    return str(value)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, str)):
        return [_json_safe(item) for item in value]
    return str(value)
