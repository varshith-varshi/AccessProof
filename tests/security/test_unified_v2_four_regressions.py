"""Adversarial reproductions for the four 2026-10-22 V2 security findings.

All fixtures are local, disposable SQLite or in-memory HTTP clients.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, Organization, Project, SourceConnection,
    GuardResource, ProviderSyncCursor, GuardSubject, GuardGroup,
    GuardGroupMembership, GuardPermissionGrant, GuardPermissionEvent,
)
from packages.auth.microsoft_consent import authorization_url
from packages.rag_sdk import GuardClient, ProtectedRAG, RetrievedResource

TENANT = "11111111-2222-3333-4444-555555555555"


def test_microsoft_v2_admin_consent_requests_application_scopes():
    url = authorization_url(tenant_id=TENANT, client_id="synthetic-client", redirect_uri="https://test.invalid/approved-callback", state="synthetic-state")
    query = parse_qs(urlsplit(url).query)
    assert query["scope"] == ["https://graph.microsoft.com/.default"]


def test_protect_no_provenance_trace_cannot_silently_certify_cached_content():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={"decision_id": "d1", "mode": "protect", "decision": "allow", "allowed": [{"source_id": "drive", "resource_id": "approved"}], "denied": [], "unknown": []})
        return httpx.Response(200, json={"decision": "allow", "reason": "SOURCE_TRACE_CHECKED"})
    guard = GuardClient("https://guard.test", client=httpx.Client(transport=httpx.MockTransport(handler)))
    result = ProtectedRAG(guard).run(
        employee_token="synthetic-token", application_id="app", retrieved=[RetrievedResource("drive", "approved")],
        generate=lambda _: "SECRET_FROM_UNTRACED_CACHE", source_trace=None,
    )
    assert result.decision == "block"
    assert result.response is None


@pytest.mark.asyncio
async def test_reconciliation_rotates_through_all_resources(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    inspected: list[str] = []

    class FakeDrive:
        def __init__(self, **kwargs): self._client = self
        async def is_inside_boundary(self, file_id): return True
        async def permissions_snapshot(self, file_id):
            inspected.append(file_id)
            return []
        async def aclose(self): pass

    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", FakeDrive)
    with SessionLocal() as db:
        org = Organization(name="Fairness regression")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Fairness")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="Fairness", boundary="root")
        db.add(source)
        db.flush()
        db.add(ProviderSyncCursor(organization_id=org.id, source_id=source.id, provider="google-drive", sync_kind="acl", last_success_at=datetime.now(timezone.utc), last_provider_revision="1", status="connected"))
        for idx in range(4):
            db.add(GuardResource(organization_id=org.id, source_id=source.id, provider_resource_id=f"file-{idx}", last_synced_at=datetime.now(timezone.utc)))
        db.commit()
        for _ in range(3):
            await acl_sync.reconcile_known_acls(db, source, {"access_token": "synthetic", "test_root_folder_id": "root"}, limit=2)
            db.commit()
    assert set(inspected) == {"file-0", "file-1", "file-2", "file-3"}


@pytest.mark.asyncio
async def test_reassigned_permission_revokes_prior_group_subject(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    class ReassignedDrive:
        def __init__(self, **kwargs): self._client = self
        async def is_inside_boundary(self, file_id): return True
        async def permissions_snapshot(self, file_id):
            return [{"id": "permission-1", "type": "user", "emailAddress": "new@example.test", "role": "reader"}]
        async def aclose(self): pass

    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", ReassignedDrive)
    with SessionLocal() as db:
        org = Organization(name="Permission reassignment")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Reassign")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="Drive", boundary="root")
        db.add(source)
        db.flush()
        old = GuardSubject(organization_id=org.id, provider="google-drive", provider_subject_id="old-id", primary_email="old@example.test", status="active")
        new = GuardSubject(organization_id=org.id, provider="google-drive", provider_subject_id="new-id", primary_email="new@example.test", status="active")
        group = GuardGroup(organization_id=org.id, provider="google-drive", provider_group_id="old-group", provider_email="old-group@example.test", status="active")
        db.add_all([old, new, group])
        db.flush()
        db.add(GuardGroupMembership(organization_id=org.id, subject_id=old.id, group_id=group.id, active=True))
        resource = GuardResource(organization_id=org.id, source_id=source.id, provider_resource_id="file-1", last_synced_at=datetime.now(timezone.utc))
        db.add(resource)
        db.flush()
        db.add(GuardPermissionGrant(organization_id=org.id, source_id=source.id, resource_id=resource.id, grant_key="google-drive:file-1:permission-1", principal_type="group", principal_id=group.id, active=True, provider_revision=1))
        db.add(ProviderSyncCursor(organization_id=org.id, source_id=source.id, provider="google-drive", sync_kind="acl", last_success_at=datetime.now(timezone.utc), last_provider_revision="1", status="connected"))
        db.commit()
        await acl_sync.reconcile_known_acls(db, source, {"access_token": "synthetic", "test_root_folder_id": "root"}, limit=10)
        db.flush()
        events = list(db.scalars(select(GuardPermissionEvent)))
        assert any(e.change_type == "grant_revoke" and e.subject_id == old.id for e in events)
        assert any(e.change_type == "grant_upsert" and e.subject_id == new.id for e in events)
