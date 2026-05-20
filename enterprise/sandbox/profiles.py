"""Sandbox profile definitions for enterprise tool governance."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    allowed_side_effects: tuple[str, ...]
    allow_env_forwarding: bool = False
    notes: str = ""


DEFAULT_SANDBOX_PROFILES: dict[str, SandboxProfile] = {
    "command_local": SandboxProfile(
        name="command_local",
        allowed_side_effects=("process_spawn", "filesystem_read", "filesystem_write", "network_egress"),
        notes="Local command execution profile; high-risk actions still require policy approval.",
    ),
    "process_control": SandboxProfile(
        name="process_control",
        allowed_side_effects=("process_spawn",),
        notes="Process inspection/control without declared filesystem or network access.",
    ),
    "code_execution": SandboxProfile(
        name="code_execution",
        allowed_side_effects=("code_execution", "filesystem_read", "filesystem_write", "network_egress"),
        notes="Code execution profile for tools that can run arbitrary code.",
    ),
    "workspace_write": SandboxProfile(
        name="workspace_write",
        allowed_side_effects=("filesystem_read", "filesystem_write"),
        notes="Workspace file mutation profile.",
    ),
    "workspace_read": SandboxProfile(
        name="workspace_read",
        allowed_side_effects=("filesystem_read",),
        notes="Workspace file read/search profile.",
    ),
    "network_fetch": SandboxProfile(
        name="network_fetch",
        allowed_side_effects=("network_egress",),
        notes="Network fetch profile with URL/host policy handled by triage.",
    ),
    "browser_control": SandboxProfile(
        name="browser_control",
        allowed_side_effects=("network_egress", "browser_state", "filesystem_read", "filesystem_write"),
        notes="Browser automation profile.",
    ),
    "browser_read": SandboxProfile(
        name="browser_read",
        allowed_side_effects=("browser_state",),
        notes="Browser state read-only profile.",
    ),
    "memory_control": SandboxProfile(
        name="memory_control",
        allowed_side_effects=("memory_read", "memory_write"),
        notes="Durable memory read/write profile.",
    ),
    "outbound_send": SandboxProfile(
        name="outbound_send",
        allowed_side_effects=("external_send", "network_egress"),
        notes="External send profile.",
    ),
    "scheduled_authority": SandboxProfile(
        name="scheduled_authority",
        allowed_side_effects=("scheduled_execution",),
        notes="Scheduled autonomous work profile.",
    ),
    "agent_delegation": SandboxProfile(
        name="agent_delegation",
        allowed_side_effects=("agent_delegation", "provider_egress"),
        notes="Subagent delegation profile.",
    ),
    "user_prompt": SandboxProfile(
        name="user_prompt",
        allowed_side_effects=("user_prompt",),
        notes="User clarification profile with no filesystem, network, process, or env forwarding.",
    ),
}


def get_sandbox_profile(name: str) -> SandboxProfile | None:
    return DEFAULT_SANDBOX_PROFILES.get(str(name))


def sandbox_profile_names() -> set[str]:
    return set(DEFAULT_SANDBOX_PROFILES)
