"""Signed authorization revisions bind Guard decisions to exact observed state."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AIApplication, AuthorizationRevision, Base, GuardAuditEvent, Project,
    ProviderSyncCursor, SessionLocal, SourceConnection, engine,
)
from packages.crypto.signing import verify_manifest


def _signup(client: TestClient, email: str) -> dict:
    return client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": "correct horse battery staple",
        "organization_name": email,
    }).json()


def _headers(account: dict) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def _guard_credential(client: TestClient, account: dict) -> tuple[str, str]:
    guard_id = client.post(
        "/api/v1/guards", headers=_headers(account), json={"name": "revision-guard"},
    ).json()["id"]
    token = client.post(
        f"/api/v1/guards/{guard_id}/enrollments", headers=_headers(account), json={},
    ).json()["enrollment_token"]
    credential = client.post(
        "/api/v1/guards/exchange",
        json={"enrollment_token": token, "version": "1.0.0"},
    ).json()["guard_credential"]
    return guard_id, credential


def _bound_application(account: dict, guard_id: str) -> tuple[str, str]:
    with SessionLocal() as db:
        project = Project(organization_id=account["organization_id"], name="revision-project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=account["organization_id"], project_id=project.id,
            provider="google-drive", name="synthetic Drive", boundary="root",
        )
        db.add(source)
        db.flush()
        db.add(AIApplication(
            organization_id=account["organization_id"], application_id="revision-app",
            name="Revision app", mode="protect", guard_id=guard_id, source_id=source.id,
        ))
        db.add(ProviderSyncCursor(
            organization_id=account["organization_id"], source_id=source.id,
            provider="google-drive", sync_kind="acl", last_provider_revision="7",
            status="healthy", last_success_at=datetime.now(timezone.utc),
        ))
        db.commit()
        return source.id, "revision-app"


def test_guard_sync_issues_monotonic_signed_revisions_and_reuses_unchanged_state():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client, "revision-owner@example.com")
        guard_id, credential = _guard_credential(client, account)
        _source_id, application_id = _bound_application(account, guard_id)
        headers = {"Authorization": f"Bearer {credential}"}

        first = client.get(
            f"/api/v1/guards/{guard_id}/policies", headers=headers,
            params={"full_snapshot": True},
        )
        assert first.status_code == 200, first.text
        revisions = first.json()["authorization_revisions"]
        assert len(revisions) == 1
        revision = revisions[0]
        assert revision["application_id"] == application_id
        assert revision["revision"] == 1
        assert revision["previous_revision_hash"] is None
        assert revision["payload"]["content_snapshot_revision"] is None
        assert verify_manifest(revision["payload"], revision["signature"])
        assert revision["payload"]["acl_revision"] == "7"
        assert revision["payload"]["limitations"]

        repeated = client.get(
            f"/api/v1/guards/{guard_id}/policies", headers=headers,
            params={"full_snapshot": True},
        ).json()["authorization_revisions"]
        assert repeated[0]["revision"] == revision["revision"]
        assert repeated[0]["revision_hash"] == revision["revision_hash"]

        with SessionLocal() as db:
            assert len(list(db.scalars(select(AuthorizationRevision)))) == 1
            cursor = db.scalar(select(ProviderSyncCursor))
            cursor.last_provider_revision = "8"
            cursor.last_success_at = datetime.now(timezone.utc)
            db.commit()

        advanced = client.get(
            f"/api/v1/guards/{guard_id}/policies", headers=headers,
            params={"full_snapshot": True},
        ).json()["authorization_revisions"][0]
        assert advanced["revision"] == 2
        assert advanced["previous_revision_hash"] == revision["revision_hash"]
        assert advanced["payload"]["acl_revision"] == "8"
        assert verify_manifest(advanced["payload"], advanced["signature"])

        ledger = client.get(
            "/api/v1/current/authorization-revisions", headers=_headers(account),
            params={"application_id": application_id},
        )
        assert ledger.status_code == 200, ledger.text
        body = ledger.json()
        assert [row["revision"] for row in body["revisions"]] == [2, 1]
        assert all(row["verification"]["signature_valid"] for row in body["revisions"])
        assert all(row["verification"]["chain_linked"] for row in body["revisions"])
        assert body["limitations"]

        other = _signup(client, "revision-other@example.com")
        foreign = client.get(
            "/api/v1/current/authorization-revisions", headers=_headers(other),
            params={"application_id": application_id},
        )
        assert foreign.status_code == 200
        assert foreign.json()["revisions"] == []


def test_guard_audit_requires_a_known_complete_revision_binding_with_bounded_time():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client, "revision-audit@example.com")
        guard_id, credential = _guard_credential(client, account)
        _bound_application(account, guard_id)
        headers = {"Authorization": f"Bearer {credential}"}
        revision = client.get(
            f"/api/v1/guards/{guard_id}/policies", headers=headers,
            params={"full_snapshot": True},
        ).json()["authorization_revisions"][0]
        occurred_at = (datetime.now(timezone.utc) - timedelta(seconds=4)).isoformat()
        event = {
            "event_id": "revision-event-1", "application_id": "revision-app",
            "subject_id": "alice", "request_id": "request-1", "result": "allow",
            "reason": "LAYER1_EFFECTIVE_ACCESS", "policy_version": 0,
            "authorization_revision": revision["revision"],
            "authorization_revision_hash": revision["revision_hash"],
            "occurred_at": occurred_at,
        }
        accepted = client.post(
            "/api/v1/guards/audit-events", headers=headers,
            json={"guard_id": guard_id, "events": [event]},
        )
        assert accepted.status_code == 202 and accepted.json() == {"accepted": 1}
        with SessionLocal() as db:
            stored = db.scalar(select(GuardAuditEvent))
            assert stored.authorization_revision == revision["revision"]
            assert stored.authorization_revision_hash == revision["revision_hash"]
            assert stored.occurred_at is not None

        unknown = {**event, "event_id": "revision-event-2", "authorization_revision": 99}
        assert client.post(
            "/api/v1/guards/audit-events", headers=headers,
            json={"guard_id": guard_id, "events": [unknown]},
        ).status_code == 422
        complete = {**event, "event_id": "revision-event-3"}
        complete.pop("authorization_revision_hash")
        assert client.post(
            "/api/v1/guards/audit-events", headers=headers,
            json={"guard_id": guard_id, "events": [complete]},
        ).status_code == 422
        future = {
            **event, "event_id": "revision-event-4",
            "occurred_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }
        assert client.post(
            "/api/v1/guards/audit-events", headers=headers,
            json={"guard_id": guard_id, "events": [future]},
        ).status_code == 422
