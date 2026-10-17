"""Six independently executable local production Golden scenarios.

These tests intentionally exercise the Guard cache/enforcement contract and,
for revocation/overlapping grants, the durable permission-event resolver.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.db import (
    Base,
    GuardPermissionEvent,
    GuardPermissionGrant,
    GuardResource,
    GuardSubject,
    Organization,
    Project,
    SessionLocal,
    SourceConnection,
    engine,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient


def _token(subject: str = "bob") -> str:
    return jwt.encode(
        {
            "sub": subject,
            "oid": subject,
            "tid": "tenant-a",
            "iss": "https://issuer",
            "aud": "rag",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        "test-key-with-at-least-thirty-two-bytes",
        algorithm="HS256",
    )


def _guard(cache: PolicyCache, mode: str = "protect") -> TestClient:
    guard_app.cache = cache
    guard_app.issuer = "https://issuer"
    guard_app.audience = "rag"
    guard_app.verification_key = "test-key-with-at-least-thirty-two-bytes"
    guard_app.identity_mode = "static"
    guard_app.expected_tenant = "tenant-a"
    guard_app.subject_claim = "oid"
    guard_app.mode = mode
    guard_app.fail_mode = "fail_closed"
    return TestClient(guard_app.app)


def test_golden_never_authorized(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.install(
        1,
        [
            {
                "subject_id": "bob",
                "source_id": "drive",
                "resource_id": "G100",
                "decision": "allow",
                "reason": "ACTIVE_GRANT_PATH",
            },
            {
                "subject_id": "bob",
                "source_id": "drive",
                "resource_id": "F123",
                "decision": "deny",
                "reason": "NO_ACTIVE_GRANT_PATH",
            },
        ],
    )
    with _guard(cache) as client:
        response = client.post(
            "/guard/v1/filter-resources",
            headers={"Authorization": f"Bearer {_token()}"},
            json={
                "application_id": "rag",
                "request_id": "never-1",
                "resources": [
                    {"source_id": "drive", "resource_id": "F123"},
                    {"source_id": "drive", "resource_id": "G100"},
                ],
            },
        )
    body = response.json()
    assert [(item["source_id"], item["resource_id"]) for item in body["allowed"]] == [
        ("drive", "G100")
    ]


def _db_graph():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    org = Organization(name="Golden")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="Golden")
    db.add(project)
    db.flush()
    source = SourceConnection(
        organization_id=org.id,
        project_id=project.id,
        provider="google-drive",
        name="Drive",
        boundary="root",
    )
    db.add(source)
    subject = GuardSubject(
        organization_id=org.id, provider="google-drive", provider_subject_id="alice"
    )
    db.add(subject)
    db.flush()
    resource = GuardResource(
        organization_id=org.id, source_id=source.id, provider_resource_id="F123"
    )
    db.add(resource)
    db.flush()
    return db, org, source, subject, resource


def _event(db, source, subject, resource, key, change, revision):
    row = GuardPermissionEvent(
        organization_id=source.organization_id,
        source_id=source.id,
        provider="google-drive",
        provider_revision=revision,
        subject_id=subject.id,
        resource_id=resource.id,
        change_type=change,
        dedupe_key=f"golden-{key}-{revision}",
        processing_status="queued",
        mutation_json=json.dumps(
            {
                "grant_key": key,
                "principal_type": "subject",
                "principal_id": subject.id,
                "scope": "read",
                "grant_effect": "allow",
                "snapshot_complete": True,
            }
        ),
    )
    db.add(row)
    db.commit()
    return row


def test_golden_revoked_access(tmp_path):
    db, _, source, subject, resource = _db_graph()
    grant = _event(db, source, subject, resource, "google-drive:p1", "grant_upsert", 1)
    process_guard_event(db, grant.id)
    revoke = _event(db, source, subject, resource, "google-drive:p1", "grant_revoke", 2)
    revoke.mutation_json = json.dumps(
        {"grant_key": "google-drive:p1", "scope": "read", "snapshot_complete": True}
    )
    db.commit()
    process_guard_event(db, revoke.id)
    assert (
        db.scalar(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True))) is None
    )
    db.close()


def test_golden_overlapping_grants(tmp_path):
    db, _, source, subject, resource = _db_graph()
    for key, rev in (("google-drive:readers", 1), ("google-drive:managers", 2)):
        event = _event(db, source, subject, resource, key, "grant_upsert", rev)
        process_guard_event(db, event.id)
    first = _event(db, source, subject, resource, "google-drive:readers", "grant_revoke", 3)
    first.mutation_json = json.dumps(
        {"grant_key": "google-drive:readers", "scope": "read", "snapshot_complete": True}
    )
    db.commit()
    process_guard_event(db, first.id)
    assert (
        db.scalar(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True)))
        is not None
    )
    second = _event(db, source, subject, resource, "google-drive:managers", "grant_revoke", 4)
    second.mutation_json = json.dumps(
        {"grant_key": "google-drive:managers", "scope": "read", "snapshot_complete": True}
    )
    db.commit()
    process_guard_event(db, second.id)
    assert (
        db.scalar(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True))) is None
    )
    db.close()


def test_golden_derived_provenance(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.install(
        1,
        [
            {
                "subject_id": "bob",
                "source_id": "drive",
                "resource_id": "F123",
                "decision": "deny",
                "reason": "NO_ACTIVE_GRANT_PATH",
            }
        ],
    )
    with _guard(cache) as client:
        filtered = client.post(
            "/guard/v1/filter-resources",
            headers={"Authorization": f"Bearer {_token()}"},
            json={"application_id": "rag", "request_id": "derived-1", "resources": []},
        ).json()
        result = client.post(
            "/guard/v1/check-output",
            headers={"Authorization": f"Bearer {_token()}"},
            json={
                "decision_id": filtered["decision_id"],
                "application_id": "rag",
                "request_id": "derived-1",
                "used_resource_ids": ["M1"],
                "provenance": [{"source_resource_ids": ["F123"]}],
            },
        ).json()
    assert result["decision"] == "block"


def test_golden_guard_restart(tmp_path):
    path = tmp_path / "guard.db"
    cache = PolicyCache(str(path))
    cache.install(
        7,
        [
            {
                "subject_id": "bob",
                "source_id": "drive",
                "resource_id": "F123",
                "decision": "deny",
                "reason": "REVOKED",
            }
        ],
    )
    restarted = PolicyCache(str(path))
    assert (
        restarted.version() == 7 and restarted.decide("bob", "drive", "F123", "read")[0] == "deny"
    )


def test_golden_control_plane_outage(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.install(
        3,
        [
            {
                "subject_id": "bob",
                "source_id": "drive",
                "resource_id": "F123",
                "decision": "deny",
                "reason": "REVOKED",
            },
            {
                "subject_id": "bob",
                "source_id": "drive",
                "resource_id": "G100",
                "decision": "allow",
                "reason": "ACTIVE_GRANT_PATH",
            },
        ],
    )
    client = GuardSyncClient(
        cache,
        GuardMachineCredentials("https://control.example", "guard-1", "secret", "1"),
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: (_ for _ in ()).throw(httpx.ConnectError("offline"))
            )
        ),
    )
    try:
        client.sync_once()
    except httpx.ConnectError:
        pass
    assert (
        cache.decide("bob", "drive", "F123", "read")[0] == "deny"
        and cache.decide("bob", "drive", "G100", "read")[0] == "allow"
    )
