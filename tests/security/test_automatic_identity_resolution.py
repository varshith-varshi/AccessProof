"""Automatic, directory-verified Microsoft identity resolution (no manual mappings).

Graph is mocked here (unit/integration level); live certification uses real
Entra identities. Every test asserts a fail-closed property as well as the
positive path.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api import directory_sync
from apps.api.accessproof_api.db import (
    AIApplication, Base, GuardIdentityMapping, GuardSubject, Organization, Project,
    SessionLocal, SourceConnection, engine,
)
from apps.api.accessproof_api.directory_sync import DirectorySyncError, synchronize_directory
from apps.api.accessproof_api.identity_resolution import (
    AUTOMATIC_METHOD, entra_issuer, identity_version, reconcile_microsoft_bindings, resolution_summary,
)
from connectors.directory import DirectoryUser

T = "6479e7ca-b256-4ebc-a408-871b9046547c"
OTHER_T = "11111111-2222-3333-4444-555555555555"
ALICE = "67b731fb-c51c-4344-bbd2-63d5bf77a5d5"
BOB = "b7989860-d1bc-4cc3-a96c-35117a3ef9c4"
GUEST = "0d6a6d2e-0000-4000-8000-00000000aa01"
DISABLED = "0d6a6d2e-0000-4000-8000-00000000aa02"
UNKNOWN = "0d6a6d2e-0000-4000-8000-00000000aa03"


class FakeEntra:
    users_data: list[DirectoryUser] = []

    def __init__(self, token: str) -> None:
        assert token == "synthetic-token"

    async def users(self):
        return list(self.users_data)

    async def groups(self):
        return []

    async def members(self, group):
        return []

    async def close(self):
        pass


def _users(**override):
    base = {
        ALICE: DirectoryUser(ALICE, "alice", "alice@lab.example", "active", "member"),
        BOB: DirectoryUser(BOB, "bob", "bob@lab.example", "active", "member"),
        GUEST: DirectoryUser(GUEST, "guest", "g_ext#@lab.example", "active", "guest"),
        DISABLED: DirectoryUser(DISABLED, "gone", "gone@lab.example", "disabled", "member"),
        UNKNOWN: DirectoryUser(UNKNOWN, "odd", None, "active", "unknown"),
    }
    base.update(override)
    return [u for u in base.values() if u is not None]


@pytest.fixture
def lab(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(directory_sync, "MicrosoftEntraDirectoryAdapter", FakeEntra)
    db = SessionLocal()
    org = Organization(name="Lab")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="p")
    db.add(project)
    db.flush()
    source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint",
                              name="SP", boundary="root", status="connected")
    db.add(source)
    db.commit()
    yield db, org, source
    db.close()


def _sync(db, source, tenant=T, users=None):
    FakeEntra.users_data = users if users is not None else _users()
    import asyncio
    result = asyncio.run(synchronize_directory(db, source, {"access_token": "synthetic-token", "tenant_id": tenant}))
    db.commit()
    return result


def _bindings(db, org):
    return {m.oidc_subject: m for m in db.scalars(select(GuardIdentityMapping).where(
        GuardIdentityMapping.organization_id == org.id))}


def test_members_are_bound_automatically_with_zero_manual_mappings(lab):
    db, org, source = lab
    result = _sync(db, source)
    rows = _bindings(db, org)
    verified = {oid for oid, m in rows.items() if m.status == "VERIFIED"}
    assert verified == {ALICE, BOB}
    for oid in (ALICE, BOB):
        m = rows[oid]
        assert m.method == AUTOMATIC_METHOD and m.verified_by_user_id is None
        assert m.oidc_issuer == entra_issuer(T) and m.oidc_tenant_id == T and m.source_id == source.id
        subject = db.get(GuardSubject, m.source_subject_id)
        assert subject.provider_subject_id == oid and subject.provider_tenant_id == T
    # guests, disabled and unclassifiable accounts are never bound
    assert GUEST not in rows and DISABLED not in rows and UNKNOWN not in rows
    assert result["automatic_identity_resolution"]["created"] == 2


def test_reconciliation_is_idempotent(lab):
    db, org, source = lab
    _sync(db, source)
    second = _sync(db, source)
    assert second["automatic_identity_resolution"]["created"] == 0
    assert len(_bindings(db, org)) == 2


def test_lifecycle_disable_remove_guest_and_restore(lab):
    db, org, source = lab
    _sync(db, source)
    _sync(db, source, users=_users(**{ALICE: DirectoryUser(ALICE, "alice", "a", "disabled", "member")}))
    assert _bindings(db, org)[ALICE].status == "SUSPENDED"
    _sync(db, source)  # re-enabled
    assert _bindings(db, org)[ALICE].status == "VERIFIED"
    _sync(db, source, users=_users(**{ALICE: None}))  # left the organization
    assert _bindings(db, org)[ALICE].status == "SUSPENDED"
    _sync(db, source, users=_users(**{BOB: DirectoryUser(BOB, "bob", "b", "active", "guest")}))
    assert _bindings(db, org)[BOB].status == "SUSPENDED"


def test_manual_contradiction_becomes_conflict_and_is_never_replaced(lab):
    db, org, source = lab
    _sync(db, source)
    rows = _bindings(db, org)
    bob_subject = rows[BOB].source_subject_id
    # Replace Alice's automatic row with a manual (admin) mapping to BOB's principal.
    db.delete(rows[ALICE])
    db.flush()
    db.add(GuardIdentityMapping(organization_id=org.id, source_id=source.id, oidc_issuer=entra_issuer(T),
                                oidc_subject=ALICE, oidc_tenant_id=T, source_subject_id=bob_subject,
                                status="VERIFIED", method="admin_verified", verified_by_user_id=None,
                                verified_at=datetime.now(timezone.utc)))
    db.commit()
    result = _sync(db, source)
    alice = _bindings(db, org)[ALICE]
    assert alice.status == "CONFLICT" and alice.method == "admin_verified"
    assert alice.source_subject_id == bob_subject  # not silently rewritten
    assert result["automatic_identity_resolution"]["conflicts"] == 1


def test_admin_decision_on_automatic_binding_is_sticky(lab):
    db, org, source = lab
    _sync(db, source)
    from apps.api.accessproof_api.db import User
    admin = User(email="admin@lab.example", password_hash="x", email_verified=True)
    db.add(admin)
    db.flush()
    row = _bindings(db, org)[BOB]
    row.status, row.revoked_at, row.verified_by_user_id = "REVOKED", datetime.now(timezone.utc), admin.id
    db.commit()
    _sync(db, source)
    assert _bindings(db, org)[BOB].status == "REVOKED"


def test_unknown_tenant_binds_nobody(lab):
    db, org, source = lab
    result = _sync(db, source, tenant="not-a-guid")
    assert result["automatic_identity_resolution"] == "TENANT_UNKNOWN"
    assert _bindings(db, org) == {}


def test_principal_cannot_move_between_tenants(lab):
    db, org, source = lab
    _sync(db, source)
    with pytest.raises(DirectorySyncError, match="DIRECTORY_TENANT_CONFLICT"):
        _sync(db, source, tenant=OTHER_T)
    db.rollback()
    # Even a direct reconcile for the other tenant binds nobody from tenant T.
    reconcile_microsoft_bindings(db, source, OTHER_T)
    assert all(m.oidc_tenant_id == T for m in _bindings(db, org).values())


def test_reconcile_query_count_is_constant_in_directory_size(lab):
    db, org, source = lab
    users = [DirectoryUser(f"0d6a6d2e-0000-4000-8000-{i:012x}", f"u{i}", None, "active", "member") for i in range(2000)]
    _sync(db, source, users=users)
    statements = []

    def count(conn, cursor, statement, *args):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)
    event.listen(engine, "before_cursor_execute", count)
    try:
        reconcile_microsoft_bindings(db, source, T)
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert len(statements) <= 4, len(statements)
    assert resolution_summary(db, org.id)["automatic"]["verified"] == 2000


def test_identity_version_changes_on_every_binding_change(lab):
    db, org, source = lab
    _sync(db, source)
    v1 = identity_version(db, org.id)
    assert identity_version(db, org.id) == v1
    _sync(db, source, users=_users(**{ALICE: DirectoryUser(ALICE, "alice", "a", "disabled", "member")}))
    assert identity_version(db, org.id) != v1


def test_guard_envelope_carries_only_verified_automatic_bindings(lab, monkeypatch):
    """End to end inside one customer organization: connect, sync, Guard receives bindings."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        account = client.post("/api/v1/auth/signup", json={"email": "idres@example.com",
                              "password": "correct horse battery staple", "organization_name": "Identity Lab"}).json()
        org_id = account["organization_id"]
        owner = {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": org_id}
        with SessionLocal() as s2:
            project = s2.scalar(select(Project).where(Project.organization_id == org_id))
            if project is None:
                project = Project(organization_id=org_id, name="p")
                s2.add(project)
                s2.flush()
            src = SourceConnection(organization_id=org_id, project_id=project.id, provider="sharepoint",
                                   name="SP", boundary="root", status="connected")
            s2.add(src)
            s2.commit()
            _sync(s2, src)
            source_id = src.id
        guard_id = client.post("/api/v1/guards", headers=owner, json={"name": "g"}).json()["id"]
        r = client.post("/api/v1/current/ai-applications", headers=owner, json={
            "application_id": "sp-rag", "name": "SP RAG", "guard_id": guard_id,
            "source_id": source_id, "adapter_type": "accessproof-gateway"})
        assert r.status_code == 201, r.text
        token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=owner, json={}).json()["enrollment_token"]
        cred = client.post("/api/v1/guards/exchange", json={"enrollment_token": token,
                           "version": "1.0.0"}).json()["guard_credential"]
        body = client.get(f"/api/v1/guards/{guard_id}/policies", headers={"Authorization": f"Bearer {cred}"}).json()
        # No administrator ever called the identity-mappings API.
        listed = client.get("/api/v1/current/identity-mappings", headers=owner).json()
    subjects = {m["subject"] for m in body["identity_mappings"]}
    assert subjects == {ALICE, BOB}
    assert all(m["issuer"] == entra_issuer(T) and m["tenant_id"] == T for m in body["identity_mappings"])
    assert all(m["source_subject_id"] == m["subject"] for m in body["identity_mappings"])
    rows = listed if isinstance(listed, list) else listed.get("mappings", listed.get("items", []))
    assert {r.get("method") for r in rows} == {AUTOMATIC_METHOD}


def test_policy_endpoint_omits_unchanged_identity_set_and_old_guards_get_full(lab):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        account = client.post("/api/v1/auth/signup", json={"email": "idver@example.com",
                              "password": "correct horse battery staple", "organization_name": "Version Lab"}).json()
        org_id = account["organization_id"]
        owner = {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": org_id}
        with SessionLocal() as s2:
            project = s2.scalar(select(Project).where(Project.organization_id == org_id)) or Project(organization_id=org_id, name="p")
            s2.add(project)
            s2.flush()
            src = SourceConnection(organization_id=org_id, project_id=project.id, provider="sharepoint",
                                   name="SP", boundary="root", status="connected")
            s2.add(src)
            s2.commit()
            _sync(s2, src)
            source_id = src.id
        guard_id = client.post("/api/v1/guards", headers=owner, json={"name": "g"}).json()["id"]
        client.post("/api/v1/current/ai-applications", headers=owner, json={
            "application_id": "sp-rag", "name": "SP RAG", "guard_id": guard_id,
            "source_id": source_id, "adapter_type": "accessproof-gateway"})
        token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=owner, json={}).json()["enrollment_token"]
        cred = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1.0.0"}).json()["guard_credential"]
        machine = {"Authorization": f"Bearer {cred}"}
        url = f"/api/v1/guards/{guard_id}/policies"
        first = client.get(url, headers=machine).json()
        assert len(first["identity_mappings"]) == 2 and first["identity_version"]
        same = client.get(url, headers=machine, params={"identity_version": first["identity_version"]}).json()
        assert same.get("identity_mappings_unchanged") is True and "identity_mappings" not in same
        legacy = client.get(url, headers=machine).json()          # an older Guard sends no version
        assert len(legacy["identity_mappings"]) == 2
        with SessionLocal() as s3:
            src = s3.get(SourceConnection, source_id)
            _sync(s3, src, users=_users(**{ALICE: DirectoryUser(ALICE, "alice", "a", "disabled", "member")}))
        changed = client.get(url, headers=machine, params={"identity_version": first["identity_version"]}).json()
        assert changed["identity_version"] != first["identity_version"]
        assert {m["subject"] for m in changed["identity_mappings"]} == {BOB}


def test_identity_resolution_endpoint_is_truthful(lab):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        account = client.post("/api/v1/auth/signup", json={"email": "idview@example.com",
                              "password": "correct horse battery staple", "organization_name": "View Lab"}).json()
        org_id = account["organization_id"]
        owner = {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": org_id}
        with SessionLocal() as s2:
            project = s2.scalar(select(Project).where(Project.organization_id == org_id)) or Project(organization_id=org_id, name="p")
            s2.add(project)
            s2.flush()
            src = SourceConnection(organization_id=org_id, project_id=project.id, provider="sharepoint",
                                   name="SP", boundary="root", status="connected")
            s2.add(src)
            s2.commit()
            source_id = src.id
        before = client.get("/api/v1/current/identity-resolution", headers=owner).json()
        assert before["sources"][0]["state"] == "DIRECTORY_NOT_SYNCHRONIZED"
        with SessionLocal() as s3:
            _sync(s3, s3.get(SourceConnection, source_id))
        after = client.get("/api/v1/current/identity-resolution", headers=owner).json()
        assert after["sources"][0]["state"] == "ACTIVE" and after["sources"][0]["automatic_verified"] == 2
        assert after["guests_not_bound"] == 1 and after["manual_mapping_required_for_members"] is False
        page = client.get("/api/v1/current/identity-mappings", headers=owner, params={"limit": 1}).json()
        assert len(page) == 1


def test_large_identity_envelope_is_gzipped_and_intact(lab):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    many = [DirectoryUser(f"0d6a6d2e-0000-4000-8000-{i:012x}", f"u{i}", None, "active", "member") for i in range(1000)]
    with TestClient(api_module.app) as client:
        account = client.post("/api/v1/auth/signup", json={"email": "idgz@example.com",
                              "password": "correct horse battery staple", "organization_name": "Gzip Lab"}).json()
        org_id = account["organization_id"]
        owner = {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": org_id}
        with SessionLocal() as s2:
            project = s2.scalar(select(Project).where(Project.organization_id == org_id)) or Project(organization_id=org_id, name="p")
            s2.add(project)
            s2.flush()
            src = SourceConnection(organization_id=org_id, project_id=project.id, provider="sharepoint",
                                   name="SP", boundary="root", status="connected")
            s2.add(src)
            s2.commit()
            _sync(s2, src, users=many)
            source_id = src.id
        guard_id = client.post("/api/v1/guards", headers=owner, json={"name": "g"}).json()["id"]
        client.post("/api/v1/current/ai-applications", headers=owner, json={
            "application_id": "sp-rag", "name": "SP RAG", "guard_id": guard_id,
            "source_id": source_id, "adapter_type": "accessproof-gateway"})
        token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=owner, json={}).json()["enrollment_token"]
        cred = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1.0.0"}).json()["guard_credential"]
        machine = {"Authorization": f"Bearer {cred}"}
        zipped = client.get(f"/api/v1/guards/{guard_id}/policies", headers={**machine, "Accept-Encoding": "gzip"})
        plain = client.get(f"/api/v1/guards/{guard_id}/policies", headers={**machine, "Accept-Encoding": "identity"})
        # A normal (non-policy) API route is never compressed by this middleware.
        other = client.get("/api/v1/current/identity-resolution", headers={**owner, "Accept-Encoding": "gzip"})
    assert zipped.headers.get("content-encoding") == "gzip"
    assert plain.headers.get("content-encoding") is None
    assert len(zipped.json()["identity_mappings"]) == 1000 == len(plain.json()["identity_mappings"])
    assert other.headers.get("content-encoding") is None


def test_reconciliation_is_audited_without_personal_data(lab):
    from apps.api.accessproof_api.db import AuditEvent
    db, org, source = lab
    _sync(db, source)
    _sync(db, source)                       # unchanged: no new audit row
    events = list(db.scalars(select(AuditEvent).where(AuditEvent.organization_id == org.id,
                                                       AuditEvent.action == "identity_resolution.reconciled")))
    assert len(events) == 1
    meta = events[0].metadata_json
    assert '"created": 2' in meta and ALICE not in meta and "alice" not in meta and T not in meta
