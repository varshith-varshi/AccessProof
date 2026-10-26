from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from apps.api.accessproof_api.db import (
    Base, Organization, Project, ProviderEventJournal, ProviderEventSubscription,
    SessionLocal, SourceConnection, engine,
)
from apps.worker.accessproof_worker import main as worker


def test_provider_event_worker_fetches_authoritative_sync_and_marks_complete(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="event-worker-org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="drive", boundary="root")
        db.add(source)
        db.flush()
        subscription = ProviderEventSubscription(
            organization_id=org.id, source_id=source.id, provider="google-drive", channel_type="acl",
            channel_id="channel-worker", provider_resource_id="resource", encrypted_channel_token="unused",
            state="active", expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        db.add(subscription)
        db.flush()
        event = ProviderEventJournal(
            organization_id=org.id, source_id=source.id, subscription_id=subscription.id, provider="google-drive",
            event_type="change", provider_message_number="2", dedupe_key="a" * 64, status="processing",
        )
        db.add(event)
        db.commit()
        event_id = event.id
        subscription_id = subscription.id

    observed = []
    async def authoritative_sync(db, source, credentials, *, max_pages):
        observed.append((source.id, max_pages))
        return {"changes": 1}
    monkeypatch.setattr(worker, "synchronize_acls", authoritative_sync)
    asyncio.run(worker.process_provider_event(event_id))
    with SessionLocal() as db:
        event = db.get(ProviderEventJournal, event_id)
        subscription = db.get(ProviderEventSubscription, subscription_id)
        assert event.status == "completed"
        assert event.completed_at is not None
        assert subscription.last_successful_processing_at is not None
    assert observed and observed[0][1] == 50


def test_provider_event_claim_is_atomic_and_at_most_once():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="claim-org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="drive", boundary="root")
        db.add(source)
        db.flush()
        sub = ProviderEventSubscription(
            organization_id=org.id, source_id=source.id, provider="google-drive", channel_type="acl",
            channel_id="claim-channel", provider_resource_id="resource", encrypted_channel_token="unused",
            state="active", expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        db.add(sub)
        db.flush()
        event = ProviderEventJournal(
            organization_id=org.id, source_id=source.id, subscription_id=sub.id,
            provider="google-drive", event_type="change", provider_message_number="1",
            dedupe_key="b" * 64, status="received",
        )
        db.add(event)
        db.commit()
        expected_id = event.id
    assert worker.claim_one_provider_event() == expected_id
    assert worker.claim_one_provider_event() is None
    with SessionLocal() as db:
        claimed = db.get(ProviderEventJournal, expected_id)
        assert claimed.status == "processing"
        assert claimed.attempts == 1
