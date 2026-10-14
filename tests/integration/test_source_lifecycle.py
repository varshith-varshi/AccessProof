from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


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
