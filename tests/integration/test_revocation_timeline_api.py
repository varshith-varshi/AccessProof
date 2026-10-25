"""Revocation timeline must come from retained evidence, never inference."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AuthorizationRevision, Base, GuardAuditEvent, GuardPermissionEvent,
    GuardRegistration, GuardResource, GuardSubject, SessionLocal, engine,
)


def _signup(client, email: str, organization_name: str) -> dict:
    response = client.post("/api/v1/auth/signup", json={
        "email": email, "password": "correct horse battery staple",
        "organization_name": organization_name,
    })
    assert response.status_code == 201, response.text
    return response.json()


def _headers(account: dict) -> dict:
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def _create_application(client, account: dict, *, with_source: bool, application_id: str = "rag"):
    source_id = None
    if with_source:
        source = client.post("/api/v1/current/sources", headers=_headers(account), json={
            "provider": "google-drive", "name": "Synthetic Drive",
            "boundary": "root", "credentials": {"test_root_folder_id": "root"},
        })
        assert source.status_code == 201, source.text
        source_id = source.json()["id"]
    created = client.post("/api/v1/current/ai-applications", headers=_headers(account), json={
        "application_id": application_id, "name": "RAG",
        **({"source_id": source_id} if source_id else {}),
    })
    assert created.status_code == 201, created.text
    return created.json()["id"], source_id


def test_timeline_reports_observed_six_timestamps_and_explicit_gaps():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _signup(client, "timeline@example.com", "Timeline Org")
        org = account["organization_id"]
        row_id, source_id = _create_application(client, account, with_source=True)

        t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
        observed, committed = t0 + timedelta(seconds=2), t0 + timedelta(seconds=5)
        revision_at, guard_use = t0 + timedelta(seconds=8), t0 + timedelta(seconds=12)
        alice_denial = t0 + timedelta(seconds=20)
        with SessionLocal() as db:
            guard = GuardRegistration(organization_id=org, name="guard", status="enrolled")
            subject = GuardSubject(
                organization_id=org, provider="google-drive",
                provider_subject_id="alice", display_name="Alice",
            )
            resource = GuardResource(
                organization_id=org, source_id=source_id,
                provider_resource_id="doc-1",
            )
            db.add_all([guard, subject, resource])
            db.flush()
            db.add(GuardPermissionEvent(
                organization_id=org, source_id=source_id, provider="google-drive",
                provider_revision=4, subject_id=subject.id, resource_id=resource.id,
                change_type="grant_revoke", dedupe_key="revoke-1",
                processing_status="completed", observed_at=observed,
                received_at=observed + timedelta(seconds=1), completed_at=committed,
                mutation_json=json.dumps({
                    "provider_mutated_at": t0.isoformat(), "resource_ids": ["doc-1"],
                }),
            ))
            db.add(GuardPermissionEvent(
                organization_id=org, source_id=source_id, provider="google-drive",
                provider_revision=5, subject_id=subject.id, resource_id=resource.id,
                change_type="grant_revoke", dedupe_key="revoke-2",
                processing_status="pending", observed_at=observed + timedelta(minutes=1),
                received_at=observed + timedelta(minutes=1),
            ))
            db.add(GuardPermissionEvent(
                organization_id=org, source_id=source_id, provider="google-drive",
                provider_revision=6, subject_id=subject.id, resource_id=resource.id,
                change_type="grant_add", dedupe_key="grant-1",
                processing_status="completed", observed_at=observed,
                received_at=observed,
            ))
            db.add(AuthorizationRevision(
                organization_id=org, application_row_id=row_id, application_id="rag",
                source_id=source_id, guard_id=guard.id, revision=4,
                state_hash="a" * 64, revision_hash="b" * 64,
                payload_json="{}", signing_key_id="test-key", signature="sig",
                signing_public_key="pub", signed_manifest_json="{}",
                generated_at=revision_at,
            ))
            db.add_all([
                GuardAuditEvent(
                    organization_id=org, guard_id=guard.id, event_id="allow-1",
                    application_id="rag", subject_id="alice", request_id="request-1",
                    layer="layer1", result="allow", reason="LAYER1_EFFECTIVE_ACCESS",
                    authorization_revision=4, authorization_revision_hash="b" * 64,
                    occurred_at=guard_use,
                ),
                GuardAuditEvent(
                    organization_id=org, guard_id=guard.id, event_id="block-other",
                    application_id="rag", subject_id="bob", request_id="request-2",
                    layer="layer1", result="block", reason="LAYER1_EFFECTIVE_ACCESS",
                    occurred_at=t0 + timedelta(seconds=15),
                ),
                GuardAuditEvent(
                    organization_id=org, guard_id=guard.id, event_id="block-alice",
                    application_id="rag", subject_id="alice", request_id="request-3",
                    layer="layer1", result="block", reason="LAYER1_EFFECTIVE_ACCESS",
                    occurred_at=alice_denial,
                ),
            ])
            db.commit()

        response = client.get(
            "/api/v1/current/revocation-timeline",
            headers=_headers(account), params={"application_id": "rag"},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["schema"] == "accessproof.revocation_timeline/v1"
        assert payload["reason"] == "RETAINED_EVIDENCE"
        assert payload["counts"] == {
            "revocations": 2, "complete_timelines": 1, "end_to_end_observed": 1,
        }
        complete = next(event for event in payload["events"] if event["complete"])
        assert complete["sequence"] == 1
        assert complete["provider"] == "google-drive"
        assert complete["change_type"] == "grant_revoke"
        timestamps = complete["timestamps"]
        for key in (
            "provider_permission_mutation_at", "provider_change_observed_at",
            "acl_state_committed_at", "authorization_revision_created_at",
            "guard_revision_applied_at", "first_verified_denial_at",
        ):
            assert timestamps[key]["status"] == "OBSERVED", (key, timestamps[key])
        assert timestamps["provider_permission_mutation_at"]["evidence_level"] == "PROVIDER_REPORTED"
        assert timestamps["authorization_revision_created_at"]["revision"] == 4
        assert complete["durations"]["provider_mutation_to_denial_seconds"] > 0
        assert complete["durations"]["acl_commit_to_revision_created_seconds"] == 3.0
        assert complete["durations"]["revision_created_to_guard_first_use_seconds"] == 4.0

        incomplete = next(event for event in payload["events"] if not event["complete"])
        assert incomplete["timestamps"]["acl_state_committed_at"]["status"] == "NOT_OBSERVED"
        assert incomplete["timestamps"]["authorization_revision_created_at"]["status"] == "NOT_OBSERVED"
        assert incomplete["timestamps"]["first_verified_denial_at"]["status"] == "NOT_OBSERVED"
        assert incomplete["durations"]["provider_observation_to_first_denial_seconds"] is None

        # Provider subject/resource identifiers are matching inputs only.
        assert "alice" not in response.text
        assert "doc-1" not in response.text
        assert "grant_add" not in response.text


def test_timeline_is_tenant_bound_and_handles_missing_source():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner = _signup(client, "owner-timeline@example.com", "Owner Org")
        other = _signup(client, "other-timeline@example.com", "Other Org")
        _create_application(client, owner, with_source=True)
        _create_application(client, owner, with_source=False, application_id="unbound")

        cross_tenant = client.get(
            "/api/v1/current/revocation-timeline",
            headers=_headers(other), params={"application_id": "rag"},
        )
        assert cross_tenant.status_code == 404

        empty = client.get(
            "/api/v1/current/revocation-timeline",
            headers=_headers(owner), params={"application_id": "rag"},
        )
        assert empty.status_code == 200
        assert empty.json()["reason"] == "NO_RETAINED_REVOCATION_EVENTS"
        assert empty.json()["events"] == []
        assert empty.json()["counts"]["revocations"] == 0

        unbound = client.get(
            "/api/v1/current/revocation-timeline",
            headers=_headers(owner), params={"application_id": "unbound"},
        )
        assert unbound.status_code == 200
        assert unbound.json()["reason"] == "APPLICATION_HAS_NO_PERMISSION_SOURCE"
        assert unbound.json()["events"] == []
