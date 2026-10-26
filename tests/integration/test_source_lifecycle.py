from fastapi.testclient import TestClient
from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.config import Settings
from apps.api.accessproof_api.db import Base, GuardGroup, GuardGroupMembership, GuardSubject, SessionLocal, User, engine


def test_source_validate_refresh_rotate_and_disconnect_lifecycle():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        signup = client.post(
            "/api/v1/auth/signup",
            json={
                "email": "source-life@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Source Org",
            },
        ).json()
        headers = {
            "Authorization": f"Bearer {signup['session_token']}",
            "X-Organization-ID": signup["organization_id"],
        }
        project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Source Project"}
        ).json()
        source = client.post(
            "/api/v1/sources",
            headers=headers,
            json={
                "project_id": project["id"],
                "provider": "mock",
                "name": "Mock source",
                "boundary": "mock-root",
                "credentials": {},
                "mutation_acknowledged": True,
            },
        ).json()
        validated = client.post(f"/api/v1/sources/{source['id']}/validate", headers=headers)
        assert validated.status_code == 200
        body = validated.json()
        assert body["status"] == "connected"
        assert body["provider_identity"]["boundary"] == "mock-root"
        assert body["capabilities"]["DIRECT_USER_REVOKE"] == "SUPPORTED"
        assert body["last_validated_at"] is not None

        refreshed = client.post(
            f"/api/v1/sources/{source['id']}/refresh-capabilities", headers=headers
        ).json()
        assert refreshed["last_capability_refresh_at"] is not None

        rotated = client.post(
            f"/api/v1/sources/{source['id']}/rotate-credential",
            headers=headers,
            json={"credentials": {}},
        )
        assert rotated.status_code == 200
        assert rotated.json()["status"] == "not_configured"
        assert rotated.json()["capabilities"] == {}

        disconnected = client.post(f"/api/v1/sources/{source['id']}/disconnect", headers=headers)
        assert disconnected.status_code == 200
        assert disconnected.json()["status"] == "disconnected"


def test_current_source_flow_hides_legacy_project_and_is_tenant_scoped():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        first = client.post("/api/v1/auth/signup", json={
            "email": "current-source@example.com", "password": "correct horse battery staple",
            "organization_name": "Current source org",
        }).json()
        first_headers = {
            "Authorization": f"Bearer {first['session_token']}",
            "X-Organization-ID": first["organization_id"],
        }
        created = client.post("/api/v1/current/sources", headers=first_headers, json={
            "provider": "mock", "name": "Current directory", "boundary": "directory-root",
            "credentials": {"access_token": "never-return-this"},
        })
        assert created.status_code == 201
        assert "project_id" not in created.json()
        listed = client.get("/api/v1/current/sources", headers=first_headers)
        assert [source["id"] for source in listed.json()] == [created.json()["id"]]
        assert client.get("/api/v1/projects", headers=first_headers).json()[0]["name"] == "__accessproof_current_product__"

        second = client.post("/api/v1/auth/signup", json={
            "email": "other-current-source@example.com", "password": "correct horse battery staple",
            "organization_name": "Other current source org",
        }).json()
        second_headers = {
            "Authorization": f"Bearer {second['session_token']}",
            "X-Organization-ID": second["organization_id"],
        }
        assert client.get("/api/v1/current/sources", headers=second_headers).json() == []


def test_production_v1_rejects_unsupported_source_creation_server_side(monkeypatch):
    """Hiding a connector in web-v2 must not leave a direct API bypass."""
    monkeypatch.setattr(api_module, "settings", Settings(env="production", v1_provider="google-workspace-drive"))
    monkeypatch.setattr(api_module, "validate_production_settings", lambda _: None)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": "v1-scope@example.com", "password": "correct horse battery staple",
            "organization_name": "V1 scope",
        })
        assert signup.status_code == 201
        organization_id = signup.json()["organization_id"]
        with SessionLocal() as db:
            user = db.query(User).filter(User.email == "v1-scope@example.com").one()
            user.email_verified = True
            token = api_module.create_session(db, user.id)
            db.commit()
        headers = {"Authorization": f"Bearer {token}", "X-Organization-ID": organization_id}
        rejected = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "sharepoint", "name": "Unsupported", "boundary": "root", "credentials": {},
        })
        assert rejected.status_code == 422
        assert rejected.json()["detail"]["code"] == "V1_PROVIDER_NOT_SUPPORTED"
        credentials_rejected = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "google-drive", "name": "Leaky credentials", "boundary": "approved-root",
            "credentials": {"access_token": "must-not-be-accepted-from-browser"},
        })
        assert credentials_rejected.status_code == 422
        assert credentials_rejected.json()["detail"]["code"] == "V1_BROWSER_CREDENTIALS_NOT_ALLOWED"
        accepted = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "google-drive", "name": "Workspace", "boundary": "approved-root", "credentials": {},
        })
        assert accepted.status_code == 201, accepted.text
        source_id = accepted.json()["id"]
        # Direct API calls must not bypass consent by rotating or replacing
        # the per-source credential record, even for a tenant owner.
        for path in (
            f"/api/v1/sources/{source_id}/rotate-credential",
            f"/api/v1/sources/{source_id}/reauthorize",
        ):
            bypass = client.post(path, headers=headers, json={
                "credentials": {"access_token": "browser-submitted-token", "client_secret": "browser-secret"},
            })
            assert bypass.status_code == 422, bypass.text
            assert bypass.json()["detail"]["code"] == "V1_BROWSER_CREDENTIALS_NOT_ALLOWED"


def test_current_directory_sync_and_employee_list_are_tenant_scoped(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    async def fake_synchronize(db, source, credentials):
        assert credentials["access_token"] == "encrypted-source-token"
        subject = GuardSubject(
            organization_id=source.organization_id, provider="google-drive", provider_subject_id="provider-user-1",
            display_name="Directory Alice", primary_email="alice@example.com", status="active",
        )
        group = GuardGroup(
            organization_id=source.organization_id, provider="google-drive", provider_group_id="provider-group-1",
            display_name="Engineering", status="active",
        )
        db.add_all([subject, group])
        db.flush()
        db.add(GuardGroupMembership(organization_id=source.organization_id, group_id=group.id, subject_id=subject.id, active=True))
        return {"users": 1, "groups": 1, "memberships": 1}

    monkeypatch.setattr("apps.api.accessproof_api.app.synchronize_directory", fake_synchronize)
    with TestClient(app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": "directory@example.com", "password": "correct horse battery staple", "organization_name": "Directory Org",
        }).json()
        headers = {"Authorization": f"Bearer {signup['session_token']}", "X-Organization-ID": signup["organization_id"]}
        source = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "google-drive", "name": "Workspace", "boundary": "folder-id", "credentials": {"access_token": "encrypted-source-token"},
        }).json()
        synced = client.post(f"/api/v1/current/sources/{source['id']}/sync-directory", headers=headers)
        assert synced.status_code == 200
        assert synced.json()["synchronized"] == {"users": 1, "groups": 1, "memberships": 1}
        employees = client.get("/api/v1/current/employees", headers=headers).json()
        assert employees[0]["stable_id"] == "provider-user-1"
        assert employees[0]["groups"][0]["name"] == "Engineering"

        other = client.post("/api/v1/auth/signup", json={
            "email": "other-directory@example.com", "password": "correct horse battery staple", "organization_name": "Other directory org",
        }).json()
        other_headers = {"Authorization": f"Bearer {other['session_token']}", "X-Organization-ID": other["organization_id"]}
        assert client.get("/api/v1/current/employees", headers=other_headers).json() == []
