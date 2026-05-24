"""Shared deterministic sanitizers for enterprise model boundaries."""

from __future__ import annotations

import re

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


def sanitize_text_for_model_boundary(text: str) -> tuple[str, list[str]]:
    """Redact secret-like text and neutralize prompt-control bait."""

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
