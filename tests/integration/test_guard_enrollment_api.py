from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, GuardAuditEvent, GuardPolicy, GuardResource, GuardSubject, SessionLocal, engine


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
        other_guard = client.post("/api/v1/guards", headers=_headers(account), json={"name": "other"}).json()["id"]
        assert client.post("/api/v1/guards/heartbeat", headers={"Authorization": f"Bearer {credential}"}, json={"guard_id": other_guard, "version": "1.0.0"}).status_code == 401
        assert client.post(f"/api/v1/guards/{guard_id}/revoke", headers=_headers(account)).status_code == 200
        assert client.post("/api/v1/guards/heartbeat", headers={"Authorization": f"Bearer {credential}"}, json={"guard_id": guard_id, "version": "1.0.0"}).status_code == 401


def test_guard_policy_sync_and_ack_are_machine_and_tenant_bound():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client, "sync-admin@example.com")
        guard_id = client.post("/api/v1/guards", headers=_headers(account), json={"name": "g"}).json()["id"]
        token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=_headers(account), json={}).json()["enrollment_token"]
        credential = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1"}).json()["guard_credential"]
        with SessionLocal() as db:
            subject = GuardSubject(
                organization_id=account["organization_id"],
                provider="google-drive",
                provider_subject_id="alice",
            )
            db.add(subject)
            db.flush()
            resource = GuardResource(
                organization_id=account["organization_id"], source_id="drive", provider_resource_id="finance"
            )
            db.add(resource)
            db.flush()
            db.add(GuardPolicy(organization_id=account["organization_id"], policy_key="k", version=1, decision="deny", subject_id=subject.id, resource_id=resource.id, source_id="drive", scope="read", reason="DENY"))
            db.commit()
        headers = {"Authorization": f"Bearer {credential}"}
        sync = client.get(f"/api/v1/guards/{guard_id}/policies", headers=headers)
        assert sync.status_code == 200 and sync.json()["policies"][0]["decision"] == "deny"
        assert sync.json()["policies"][0]["subject_id"] == "alice"
        assert sync.json()["policies"][0]["resource_id"] == "finance"
        assert client.post("/api/v1/guards/policies/ack", headers=headers, json={"guard_id": guard_id, "policy_version": 1, "status": "received"}).status_code == 200
        assert client.post("/api/v1/guards/policies/ack", headers=headers, json={"guard_id": guard_id, "policy_version": 1, "status": "installed"}).status_code == 200
        assert client.get(f"/api/v1/guards/{guard_id}/policies", headers={"Authorization": f"Bearer {account['session_token']}"}).status_code == 401


def test_guard_audit_upload_is_machine_only_and_idempotent():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client, "guard-audit@example.com")
        guard_id = client.post("/api/v1/guards", headers=_headers(account), json={"name": "g"}).json()["id"]
        token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=_headers(account), json={}).json()["enrollment_token"]
        credential = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1"}).json()["guard_credential"]
        payload = {"guard_id": guard_id, "events": [{"event_id": "event-1", "application_id": "app-1", "subject_id": "alice", "request_id": "request-1", "result": "block", "reason": "DENY", "policy_version": 1}]}
        headers = {"Authorization": f"Bearer {credential}"}
        assert client.post("/api/v1/guards/audit-events", headers=headers, json=payload).json() == {"accepted": 1}
        assert client.post("/api/v1/guards/audit-events", headers=headers, json=payload).json() == {"accepted": 0}
        assert client.post("/api/v1/guards/audit-events", headers={"Authorization": f"Bearer {account['session_token']}"}, json=payload).status_code == 401
        with SessionLocal() as db:
            assert len(list(db.scalars(select(GuardAuditEvent)))) == 1
