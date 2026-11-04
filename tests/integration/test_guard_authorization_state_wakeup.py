"""Guard wake-up on authorization-state change (not only policy version).

Live r30/r34 measurements: the revoking policy reached the Guard ~8 s after
commit and the new revision ~12 s later, because the Guard long-polled for
only 1 s then slept 10 s, and health/revision changes never woke it.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AIApplication, Base, GuardPermissionEvent, GuardResource, GuardSubject, Project, SessionLocal,
    SourceConnection, engine,
)
from tests.integration.test_guard_enrollment_api import _headers, _signup


def _enrolled(client):
    account = _signup(client, "wake-admin@example.com")
    guard_id = client.post("/api/v1/guards", headers=_headers(account), json={"name": "g"}).json()["id"]
    token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=_headers(account), json={}).json()["enrollment_token"]
    credential = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1"}).json()["guard_credential"]
    org = account["organization_id"]
    with SessionLocal() as db:
        project = Project(organization_id=org, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org, project_id=project.id, provider="sharepoint", boundary="root", name="sp")
        db.add(source)
        db.flush()
        db.add(AIApplication(organization_id=org, application_id="rag", name="RAG", guard_id=guard_id, source_id=source.id,
                             adapter_type="accessproof-gateway"))
        db.commit()
        source_id = source.id
    return org, guard_id, {"Authorization": f"Bearer {credential}"}, source_id


def _notify(client, guard_id, headers, **params):
    return client.get(f"/api/v1/guards/{guard_id}/policy-notifications", headers=headers,
                      params={"after_version": 0, "wait_seconds": 0, **params}).json()


def test_unchanged_state_is_keepalive_and_changed_state_wakes_the_guard():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        org, guard_id, headers, source_id = _enrolled(client)
        envelope = client.get(f"/api/v1/guards/{guard_id}/policies", headers=headers).json()
        token = envelope["authorization_state_token"]
        assert isinstance(token, str) and len(token) == 32
        assert _notify(client, guard_id, headers, state_token=token)["event_type"] == "KEEPALIVE"
        # A permission change becomes pending (source health changes) WITHOUT a
        # new policy version: the Guard must be woken immediately.
        with SessionLocal() as db:
            subject = GuardSubject(organization_id=org, provider="microsoft365", provider_subject_id="alice")
            resource = GuardResource(organization_id=org, source_id=source_id, provider_resource_id="doc")
            db.add_all([subject, resource])
            db.flush()
            db.add(GuardPermissionEvent(organization_id=org, source_id=source_id, provider="microsoft365",
                                        resource_id=resource.id, subject_id=subject.id, change_type="grant_revoke",
                                        provider_revision=2, dedupe_key="wake-1", mutation_json="{}"))
            db.commit()
        woke = _notify(client, guard_id, headers, state_token=token)
        assert woke["event_type"] == "AUTHORIZATION_STATE_CHANGED"
        # The refreshed envelope carries the new token; with it the Guard idles again.
        fresh = client.get(f"/api/v1/guards/{guard_id}/policies", headers=headers).json()["authorization_state_token"]
        assert fresh != token
        assert _notify(client, guard_id, headers, state_token=fresh)["event_type"] == "KEEPALIVE"


def test_state_token_is_bounded_and_machine_authenticated():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _org, guard_id, headers, _source = _enrolled(client)
        assert client.get(f"/api/v1/guards/{guard_id}/policy-notifications", headers=headers,
                          params={"wait_seconds": 0, "state_token": "x" * 65}).status_code == 422
        assert client.get(f"/api/v1/guards/{guard_id}/policy-notifications",
                          params={"wait_seconds": 0, "state_token": "abc"}).status_code == 401
        # Older Guards that send no token keep the previous (version-only) behaviour.
        assert _notify(client, guard_id, headers)["event_type"] == "KEEPALIVE"
