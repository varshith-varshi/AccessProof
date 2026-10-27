"""Lifecycle of durable, secret-bound, renewable Drive watch subscriptions."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from apps.api.accessproof_api.db import (
    Base, Organization, Project, ProviderEventSubscription, ProviderSyncCursor,
    SessionLocal, SourceConnection, engine,
)
from apps.worker.accessproof_worker import watch_lifecycle
from apps.worker.accessproof_worker import main as worker


def test_google_watch_registration_renewal_and_existing_channel_retirement(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="watch-org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="google-drive", name="drive", boundary="root",
            encrypted_credentials=worker.box.encrypt(json.dumps({
                "access_token": "fake-provider-token", "test_root_folder_id": "root",
            })),
        )
        db.add(source)
        db.flush()
        db.add(ProviderSyncCursor(
            organization_id=org.id, source_id=source.id, provider="google-drive",
            sync_kind="acl", cursor="cursor-123", status="connected",
            last_success_at=datetime.now(timezone.utc),
        ))
        db.commit()
        source_id = source.id
    calls = []

    class Close:
        async def aclose(self):
            pass

    class FakeAdapter:
        def __init__(self, **kwargs):
            assert kwargs["test_root_folder_id"] == "root"
            self._client = Close()

        async def watch_changes(self, **kwargs):
            calls.append(("watch", kwargs))
            return {"id": kwargs["channel_id"], "resourceId": "provider-rsc",
                    "expiration": str(int((datetime.now(timezone.utc)
                       + timedelta(days=3)).timestamp() * 1000))}

        async def stop_watch_channel(self, **kwargs):
            calls.append(("stop", kwargs))

    monkeypatch.setattr(watch_lifecycle, "GoogleDriveAdapter", FakeAdapter)

    async def refresh(db, source, creds):
        return creds

    async def run():
        opts = dict(source_id=source_id,
                    callback_url="https://api.example.com/api/v1/provider-events/google-drive",
                    box=worker.box, refresh_credentials=refresh)
        assert await watch_lifecycle.ensure_google_watch(**opts)
        assert not await watch_lifecycle.ensure_google_watch(**opts)
        with SessionLocal() as db:
            active = db.scalar(select(ProviderEventSubscription))
            assert active.state == "active"
            assert worker.box.decrypt(active.encrypted_channel_token)
            active.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
            db.commit()
        assert await watch_lifecycle.ensure_google_watch(**opts)
        assert [kind for kind, _ in calls] == ["watch", "watch", "stop"]
        with SessionLocal() as db:
            rows = list(db.scalars(select(ProviderEventSubscription)))
            assert sorted(sub.state for sub in rows) == ["active", "stopped"]
            assert len({sub.channel_id for sub in rows}) == 2

    asyncio.run(run())


def test_google_watch_rejects_untrusted_callback_urls():
    assert watch_lifecycle.validate_callback_url(
        "https://api.example.com/api/v1/provider-events/google-drive"
    )
    for candidate in (
        "http://api.example.com/api/v1/provider-events/google-drive",
        "https://api.example.com/redirect",
        "https://user:pass@api.example.com/api/v1/provider-events/google-drive",
        "https://api.example.com/api/v1/provider-events/google-drive?token=stolen",
    ):
        assert not watch_lifecycle.validate_callback_url(candidate)
