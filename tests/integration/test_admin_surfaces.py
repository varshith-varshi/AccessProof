from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def _reset_db() -> None:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def _signup(client: TestClient):
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "owner@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Admin Surface Org",
        },
    )
    assert response.status_code == 201, response.text
    return response


def test_signup_sets_browser_session_and_organization_controls_roundtrip():
    _reset_db()
    with TestClient(app) as client:
        signup = _signup(client)
        body = signup.json()
        assert signup.cookies.get("accessproof_session")
        assert signup.cookies.get("accessproof_csrf")
        headers = {"X-Organization-ID": body["organization_id"]}

        org = client.get("/api/v1/organization", headers=headers)
        assert org.status_code == 200, org.text
        assert org.json()["name"] == "Admin Surface Org"
        assert org.json()["mutations_disabled"] is False

        csrf = client.cookies.get("accessproof_csrf")
        mutation_headers = {**headers, "X-CSRF-Token": csrf}
        disabled = client.post("/api/v1/organization/disable-mutations", headers=mutation_headers)
        assert disabled.status_code == 200
        assert disabled.json()["mutations_disabled"] is True
        enabled = client.post("/api/v1/organization/enable-mutations", headers=mutation_headers)
        assert enabled.status_code == 200
        assert enabled.json()["mutations_disabled"] is False


def test_webhook_admin_list_and_delete():
    _reset_db()
    with TestClient(app) as client:
        signup = _signup(client).json()
        headers = {
            "Authorization": f"Bearer {signup['session_token']}",
            "X-Organization-ID": signup["organization_id"],
        }
        created = client.post(
            "/api/v1/webhooks",
            headers=headers,
            json={"url": "https://1.1.1.1/accessproof-webhook", "project_id": None},
        )
        assert created.status_code == 201, created.text
        webhook_id = created.json()["id"]
        listed = client.get("/api/v1/webhooks", headers=headers)
        assert listed.status_code == 200, listed.text
        assert [row["id"] for row in listed.json()] == [webhook_id]
        deleted = client.delete(f"/api/v1/webhooks/{webhook_id}", headers=headers)
        assert deleted.status_code == 204, deleted.text
        assert client.get("/api/v1/webhooks", headers=headers).json() == []
