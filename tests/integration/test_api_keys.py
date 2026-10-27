from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def test_api_key_shown_once_and_authenticates():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        s = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "ci@example.com",
                "password": "correct horse battery staple",
                "organization_name": "CI Org",
            },
        ).json()
        h = {
            "Authorization": f"Bearer {s['session_token']}",
            "X-Organization-ID": s["organization_id"],
        }
        k = c.post("/api/v1/api-keys", headers=h, json={"label": "github", "expires_in_days": 30})
        assert k.status_code == 201
        raw = k.json()["api_key"]
        assert raw.startswith("ap_")
        kh = {"Authorization": f"Bearer {raw}", "X-Organization-ID": s["organization_id"]}
        assert c.get("/api/v1/projects", headers=kh).status_code == 200
        listing = c.get("/api/v1/api-keys", headers=h).json()
        assert "api_key" not in listing[0]
        assert c.delete(f"/api/v1/api-keys/{k.json()['id']}", headers=h).status_code == 204
        assert c.get("/api/v1/projects", headers=kh).status_code == 401


def test_read_only_api_key_cannot_escalate_to_mutating_routes():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        s = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "scoped@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Scoped Org",
            },
        ).json()
        h = {
            "Authorization": f"Bearer {s['session_token']}",
            "X-Organization-ID": s["organization_id"],
        }
        key = c.post(
            "/api/v1/api-keys",
            headers=h,
            json={"label": "reader", "scopes": ["projects:read", "runs:read", "reports:read"]},
        ).json()
        kh = {
            "Authorization": f"Bearer {key['api_key']}",
            "X-Organization-ID": s["organization_id"],
        }
        assert c.get("/api/v1/projects", headers=kh).status_code == 200
        denied = c.post("/api/v1/projects", headers=kh, json={"name": "must-not-create"})
        assert denied.status_code == 403
        denied_keys = c.get("/api/v1/api-keys", headers=kh)
        assert denied_keys.status_code == 403
