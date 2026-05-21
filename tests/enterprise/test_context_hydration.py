"""Tests for enterprise artifact vault and context hydration boundary."""

from __future__ import annotations

from enterprise.artifacts import ArtifactVault, hydrate_context
from enterprise.audit import AuditStore
from enterprise.contracts import AuditEventType, ContextHydrationRequest, HydrationView, stable_json


FAKE_OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"


def _request(
    *,
    artifact_id: str,
    view: HydrationView,
    route: str = "external-provider",
    request_id: str = "hydration-1",
) -> ContextHydrationRequest:
    return ContextHydrationRequest(
        request_id=request_id,
        artifact_id=artifact_id,
        subject_id="employee-1",
        route=route,
        view=view,
        reason="review artifact",
        requested_at="2026-05-20T00:00:00+00:00",
    )


def test_artifact_vault_stores_record_without_raw_secret_preview(tmp_path):
    vault = ArtifactVault(tmp_path / "vault.sqlite3")

    record = vault.put_artifact(
        content=f"Report contains token {FAKE_OPENAI_KEY}",
        data_class="secrets",
        metadata={"kind": "evidence", "summary": "Secret-bearing evidence"},
        created_at="2026-05-20T00:00:00+00:00",
    )

    assert vault.count() == 1
    assert vault.get_record(record.artifact_id) == record
    assert vault.read_content(record.artifact_id) == f"Report contains token {FAKE_OPENAI_KEY}"
    assert FAKE_OPENAI_KEY not in record.redacted_preview
    assert record.metadata["content_size_bytes"] > 0


def test_hydration_denies_full_content_to_provider_route_and_audits(tmp_path):
    vault = ArtifactVault(tmp_path / "vault.sqlite3")
    audit = AuditStore(tmp_path / "audit.sqlite3")
    record = vault.put_artifact(
        content="customer report raw content",
        data_class="business",
        metadata={"summary": "Customer report summary"},
    )

    result = hydrate_context(
        _request(artifact_id=record.artifact_id, view=HydrationView.FULL, route="external-provider"),
        vault=vault,
        root_config={"enterprise": {"enabled": True}},
        audit_store=audit,
    )

    assert result.allowed is False
    assert result.content == ""
    assert "Full hydration is not allowed for route" in result.reason
    assert audit.count() == 1

    event = audit.list_events()[0]
    assert event.event_type is AuditEventType.HYDRATION_DECISION
    assert event.metadata["route"] == "external-provider"
    assert event.metadata["requested_view"] == "full"
    assert event.metadata["budget_bytes"] == 8192
    assert event.metadata["data_class"] == "business"
    assert event.metadata["allowed"] is False
    assert "customer report raw content" not in event.to_json()


def test_hydration_allows_redacted_view_without_secret_leak(tmp_path):
    vault = ArtifactVault(tmp_path / "vault.sqlite3")
    audit = AuditStore(tmp_path / "audit.sqlite3")
    record = vault.put_artifact(
        content=f"env OPENAI_API_KEY={FAKE_OPENAI_KEY}",
        data_class="secrets",
        metadata={"summary": "Secret evidence summary"},
    )

    result = hydrate_context(
        _request(artifact_id=record.artifact_id, view=HydrationView.REDACTED, route="external-provider"),
        vault=vault,
        root_config={"enterprise": {"enabled": True}},
        audit_store=audit,
    )

    assert result.allowed is True
    assert "[REDACTED:openai_key]" in result.content
    assert FAKE_OPENAI_KEY not in result.content
    serialized_events = "\n".join(event.to_json() for event in audit.list_events())
    assert FAKE_OPENAI_KEY not in serialized_events


def test_hydration_denies_full_secret_content_even_on_allowed_route(tmp_path):
    vault = ArtifactVault(tmp_path / "vault.sqlite3")
    audit = AuditStore(tmp_path / "audit.sqlite3")
    record = vault.put_artifact(
        content=f"secret token {FAKE_OPENAI_KEY}",
        data_class="secrets",
        metadata={"summary": "Secret evidence summary"},
    )

    result = hydrate_context(
        _request(artifact_id=record.artifact_id, view=HydrationView.FULL, route="local"),
        vault=vault,
        root_config={"enterprise": {"enabled": True}},
        audit_store=audit,
    )

    assert result.allowed is False
    assert result.content == ""
    assert "secret-bearing data class" in result.reason
    assert FAKE_OPENAI_KEY not in stable_json(audit.list_events()[0].to_dict())


def test_hydration_summary_and_metadata_views_do_not_release_raw_content(tmp_path):
    vault = ArtifactVault(tmp_path / "vault.sqlite3")
    record = vault.put_artifact(
        content="raw long report body",
        data_class="business",
        metadata={"summary": "Executive-safe summary"},
    )

    summary = hydrate_context(
        _request(artifact_id=record.artifact_id, view=HydrationView.SUMMARY, route="external-provider"),
        vault=vault,
        root_config={"enterprise": {"enabled": True}},
        audit_store=AuditStore(tmp_path / "summary-audit.sqlite3"),
    )
    metadata = hydrate_context(
        _request(
            artifact_id=record.artifact_id,
            view=HydrationView.METADATA,
            route="external-provider",
            request_id="hydration-2",
        ),
        vault=vault,
        root_config={"enterprise": {"enabled": True}},
        audit_store=AuditStore(tmp_path / "metadata-audit.sqlite3"),
    )

    assert summary.allowed is True
    assert summary.content == "Executive-safe summary"
    assert "raw long report body" not in summary.content
    assert metadata.allowed is True
    assert metadata.content == ""


def test_hydration_disabled_returns_requested_view_without_audit(tmp_path):
    vault = ArtifactVault(tmp_path / "vault.sqlite3")
    audit = AuditStore(tmp_path / "audit.sqlite3")
    record = vault.put_artifact(
        content="raw local content",
        data_class="business",
    )

    result = hydrate_context(
        _request(artifact_id=record.artifact_id, view=HydrationView.FULL, route="external-provider"),
        vault=vault,
        root_config={"enterprise": {"enabled": False}},
        audit_store=audit,
    )

    assert result.allowed is True
    assert result.content == "raw local content"
    assert audit.count() == 0
