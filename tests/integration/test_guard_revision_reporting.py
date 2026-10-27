"""Guard-reported authorization revisions must be bound, issued and measured."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AuthorizationRevision, Base, GuardRegistration, SessionLocal, engine,
)


def _signup(client) -> dict:
    response = client.post("/api/v1/auth/signup", json={
        "email": "revision-report@example.com",
        "password": "correct horse battery staple",
        "organization_name": "Revision Org",
    })
    assert response.status_code == 201, response.text
    return response.json()


def _headers(account: dict) -> dict:
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def test_heartbeat_revisions_are_tenant_bound_issued_and_visible_in_metrics():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client)
        org = account["organization_id"]
        guard_id = client.post(
            "/api/v1/guards", headers=_headers(account), json={"name": "revision-guard"},
        ).json()["id"]
        token = client.post(
            f"/api/v1/guards/{guard_id}/enrollments", headers=_headers(account), json={},
        ).json()["enrollment_token"]
        credential = client.post(
            "/api/v1/guards/exchange",
            json={"enrollment_token": token, "version": "1"},
        ).json()["guard_credential"]
        machine = {"Authorization": f"Bearer {credential}"}

        created = client.post("/api/v1/current/ai-applications", headers=_headers(account), json={
            "application_id": "rag", "name": "RAG", "guard_id": guard_id,
        })
        assert created.status_code == 201, created.text
        row_id = created.json()["id"]

        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            for revision, generated, marker in (
                (1, now - timedelta(minutes=3), "1"),
                (2, now - timedelta(seconds=90), "2"),
            ):
                db.add(AuthorizationRevision(
                    organization_id=org, application_row_id=row_id, application_id="rag",
                    guard_id=guard_id, revision=revision,
                    state_hash=marker * 64, revision_hash=marker * 64,
                    payload_json="{}", signing_key_id="test-key", signature="sig",
                    signing_public_key="pub", signed_manifest_json="{}",
                    generated_at=generated,
                ))
            db.commit()

        def heartbeat(revisions=None):
            body = {
                "guard_id": guard_id, "version": "1.0.0",
                "active_policy_version": 0,
            }
            if revisions is not None:
                body["active_authorization_revisions"] = revisions
            return client.post("/api/v1/guards/heartbeat", headers=machine, json=body)

        unbound = heartbeat({"not-bound": {"revision": 1, "revision_hash": "1" * 64}})
        assert unbound.status_code == 403
        assert unbound.json()["detail"] == "AUTHORIZATION_REVISION_APPLICATION_NOT_BOUND"

        unissued = heartbeat({"rag": {"revision": 3, "revision_hash": "3" * 64}})
        assert unissued.status_code == 409
        assert unissued.json()["detail"] == "AUTHORIZATION_REVISION_NOT_ISSUED"

        forked = heartbeat({"rag": {"revision": 2, "revision_hash": "f" * 64}})
        assert forked.status_code == 409
        assert forked.json()["detail"] == "AUTHORIZATION_REVISION_NOT_ISSUED"

        accepted = heartbeat({"rag": {"revision": 1, "revision_hash": "1" * 64}})
        assert accepted.status_code == 200, accepted.text
        with SessionLocal() as db:
            stored = json.loads(
                db.get(GuardRegistration, guard_id).active_authorization_revisions_json
            )
        assert stored == {"rag": {"revision": 1, "revision_hash": "1" * 64}}

        text = client.get("/metrics").text
        match = re.search(r"^accessproof_guard_revision_lag_seconds (\S+)$", text, re.MULTILINE)
        assert match is not None, text
        lag = float(match.group(1))
        assert 60 <= lag <= 300, lag

        # Once the Guard reports the newest issued revision the lag sample is
        # no longer refreshed; the stale gauge is never presented as current.
        latest = heartbeat({"rag": {"revision": 2, "revision_hash": "2" * 64}})
        assert latest.status_code == 200, latest.text
