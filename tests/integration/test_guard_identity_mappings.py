from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, GuardIdentityMapping, GuardSubject, SessionLocal, engine


def _signup(client: TestClient, email: str = "mapping@example.com") -> tuple[dict[str, str], dict[str, str]]:
    account = client.post("/api/v1/auth/signup", json={"email": email, "password": "correct horse battery staple", "organization_name": "Mapping Org"}).json()
    return account, {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": account["organization_id"]}


def test_mapping_is_org_scoped_synced_to_guard_and_revocation_removes_it():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account, headers = _signup(client)
        source = client.post("/api/v1/current/sources", headers=headers, json={"provider": "google-drive", "name": "Drive", "boundary": "folder", "credentials": {"access_token": "synthetic"}}).json()
        with SessionLocal() as db:
            subject = GuardSubject(organization_id=account["organization_id"], provider="google-drive", provider_subject_id="google-immutable-1", primary_email="employee@example.test", status="active")
            db.add(subject)
            db.commit()
            subject_id = subject.id
        created = client.post("/api/v1/current/identity-mappings", headers=headers, json={"source_id": source["id"], "oidc_issuer": "https://issuer.example.test/", "oidc_subject": "employee-oidc-1", "oidc_tenant_id": "tenant-1", "source_subject_id": subject_id})
        assert created.status_code == 201, created.text
        assert created.json()["source_subject"]["stable_id"] == "google-immutable-1"
        # An exact issuer match is preserved in the Guard policy envelope.
        guard = client.post("/api/v1/guards", headers=headers, json={"name": "guard"}).json()
        token = client.post(f"/api/v1/guards/{guard['id']}/enrollments", headers=headers, json={}).json()["enrollment_token"]
        credential = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1"}).json()["guard_credential"]
        synced = client.get(f"/api/v1/guards/{guard['id']}/policies", headers={"Authorization": f"Bearer {credential}"}).json()
        assert synced["identity_mappings"] == [{"source_id": source["id"], "issuer": "https://issuer.example.test/", "subject": "employee-oidc-1", "tenant_id": "tenant-1", "source_subject_id": "google-immutable-1"}]
        revoked = client.patch(f"/api/v1/current/identity-mappings/{created.json()['id']}", headers=headers, json={"status": "REVOKED"})
        assert revoked.status_code == 200
        assert client.get(f"/api/v1/guards/{guard['id']}/policies", headers={"Authorization": f"Bearer {credential}"}).json()["identity_mappings"] == []
        with SessionLocal() as db:
            assert db.scalar(select(GuardIdentityMapping.status)) == "REVOKED"


def test_mapping_rejects_cross_tenant_source_or_subject():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _first, headers = _signup(client, "first@example.com")
        source = client.post("/api/v1/current/sources", headers=headers, json={"provider": "google-drive", "name": "Drive", "boundary": "folder"}).json()
        second, _second_headers = _signup(client, "second@example.com")
        with SessionLocal() as db:
            subject = GuardSubject(organization_id=second["organization_id"], provider="google-drive", provider_subject_id="second", status="active")
            db.add(subject)
            db.commit()
            second_subject_id = subject.id
        response = client.post("/api/v1/current/identity-mappings", headers=headers, json={"source_id": source["id"], "oidc_issuer": "https://issuer.example.test/", "oidc_subject": "employee", "source_subject_id": second_subject_id})
        assert response.status_code == 404


def test_mapping_for_microsoft_source_requires_microsoft_directory_subject():
    """Google identities may not be used as Microsoft source policy subjects."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account, headers = _signup(client, "microsoft-mapping@example.com")
        source_response = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "microsoft365", "name": "Test SharePoint",
            "boundary": "root", "credentials": {
                "access_token": "synthetic", "drive_id": "drive-1", "test_root_item_id": "root", "tenant_id": "11111111-2222-3333-4444-555555555555"
            },
        })
        assert source_response.status_code == 201, source_response.text
        source_id = source_response.json()["id"]
        with SessionLocal() as db:
            google_user = GuardSubject(
                organization_id=account["organization_id"], provider="google-drive",
                provider_subject_id="same-id", status="active",
            )
            microsoft_user = GuardSubject(
                organization_id=account["organization_id"], provider="microsoft365",
                provider_subject_id="ms-immutable", status="active",
            )
            db.add_all([google_user, microsoft_user])
            db.commit()
            google_id, microsoft_id = google_user.id, microsoft_user.id
        body = {
            "source_id": source_id,
            "oidc_issuer": "https://login.example.test",
            "oidc_subject": "employee",
            "source_subject_id": google_id,
        }
        rejected = client.post("/api/v1/current/identity-mappings", headers=headers, json=body)
        assert rejected.status_code == 422
        body["source_subject_id"] = microsoft_id
        accepted = client.post("/api/v1/current/identity-mappings", headers=headers, json=body)
        assert accepted.status_code == 201, accepted.text
