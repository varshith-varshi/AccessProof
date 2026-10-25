"""Google watch notifications are hints, never authorization decisions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import _secret_box, app
from apps.api.accessproof_api.db import (
    Base, Organization, Project, ProviderEventJournal, ProviderEventSubscription,
    SessionLocal, SourceConnection, engine,
)


def _source_with_subscription(*, expired: bool = False):
    with SessionLocal() as db:
        org = Organization(name="event-org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="event-project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id, provider="google-drive",
            name="drive", boundary="folder", encrypted_credentials=_secret_box.encrypt("{}"),
        )
        db.add(source)
        db.flush()
        subscription = ProviderEventSubscription(
            organization_id=org.id, source_id=source.id, provider="google-drive", channel_type="acl",
            channel_id="channel-1", provider_resource_id="resource-1",
            encrypted_channel_token=_secret_box.encrypt("channel-secret"), state="active",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=(-1 if expired else 5)),
        )
        db.add(subscription)
        db.commit()
        return org.id, subscription.id


def _headers(**changes: str) -> dict[str, str]:
    values = {
        "X-Goog-Channel-ID": "channel-1", "X-Goog-Channel-Token": "channel-secret",
        "X-Goog-Resource-ID": "resource-1", "X-Goog-Resource-State": "change",
        "X-Goog-Message-Number": "101",
    }
    values.update(changes)
    return values


def test_google_webhook_binds_channel_and_deduplicates_before_worker_processing():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    org_id, _ = _source_with_subscription()
    with TestClient(app) as client:
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers()).status_code == 204
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers()).status_code == 204
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers(**{"X-Goog-Channel-Token": "wrong"})).status_code == 401
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers(**{"X-Goog-Resource-ID": "attacker"})).status_code == 401
    with SessionLocal() as db:
        events = list(db.query(ProviderEventJournal).filter_by(organization_id=org_id))
        assert len(events) == 1
        assert events[0].status == "received"
        # A notification itself contains no grant or permission decision.
        assert events[0].event_type == "change"


def test_expired_or_malformed_google_webhook_is_not_enqueued():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    _source_with_subscription(expired=True)
    with TestClient(app) as client:
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers()).status_code == 401
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers(**{"X-Goog-Message-Number": "not-a-number"})).status_code == 401
        assert client.post("/api/v1/provider-events/google-drive", headers=_headers(), content=b"unexpected").status_code == 400
    with SessionLocal() as db:
        assert db.query(ProviderEventJournal).count() == 0


def test_chunked_google_webhook_body_is_bounded_before_accumulation():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    _source_with_subscription()
    with TestClient(app) as client:
        # Deliberately pass an iterator to avoid a conventional Content-Length.
        oversized = client.post(
            "/api/v1/provider-events/google-drive", headers=_headers(),
            content=iter((b" " * 4096, b" " * 4096, b" " * 1024)),
        )
        assert oversized.status_code == 413
        assert oversized.json()["detail"] == "NOTIFICATION_TOO_LARGE"
    with SessionLocal() as db:
        assert db.query(ProviderEventJournal).count() == 0
