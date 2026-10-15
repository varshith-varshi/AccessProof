from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def _signup(client, email):
    return client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": "correct horse battery staple",
        "organization_name": "Guard organization",
    }).json()


def _headers(account):
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def test_guard_enrollment_is_single_use_and_machine_credentials_are_separate():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client, "guard-admin@example.com")
        created = client.post("/api/v1/guards", headers=_headers(account), json={"name": "customer-rag"})
        assert created.status_code == 201
        guard_id = created.json()["id"]
        enrollment = client.post(
            f"/api/v1/guards/{guard_id}/enrollments",
            headers=_headers(account), json={"expires_in_minutes": 5},
        )
        assert enrollment.status_code == 201
        token = enrollment.json()["enrollment_token"]
        exchanged = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1.0.0"})
        assert exchanged.status_code == 201
        credential = exchanged.json()["guard_credential"]
        assert client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1.0.0"}).status_code == 401
        # A web session is never accepted as a Guard machine credential.
        assert client.post("/api/v1/guards/heartbeat", headers={"Authorization": f"Bearer {account['session_token']}"}, json={"guard_id": guard_id, "version": "1.0.0"}).status_code == 401
        heartbeat = client.post("/api/v1/guards/heartbeat", headers={"Authorization": f"Bearer {credential}"}, json={"guard_id": guard_id, "version": "1.0.0", "active_policy_version": 7})
        assert heartbeat.status_code == 200
        listed = client.get("/api/v1/guards", headers=_headers(account)).json()
        assert listed[0]["status"] == "enrolled"
        assert listed[0]["active_policy_version"] == 7
