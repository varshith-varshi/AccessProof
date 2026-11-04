"""Microsoft Graph change notifications: authenticated wake-up hints only."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import _secret_box, app
from apps.api.accessproof_api.db import (
    Base, GuardPolicy, Organization, Project, ProviderEventJournal, ProviderEventSubscription, SessionLocal,
    SourceConnection, engine,
)
from apps.api.accessproof_api.event_sync import microsoft_binding

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"
OTHER_TENANT = "11111111-2222-3333-4444-555555555555"
DRIVE = "b!drive-one"
URL = "/api/v1/provider-events/microsoft"


def _world(*, expires_in=timedelta(days=5), state="active"):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="Graph notifications")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint",
                                  boundary="root", name="SP", status="connected")
        db.add(source)
        db.flush()
        for channel, sub_id, resource, secret in (("acl", "sub-drive", f"drives/{DRIVE}/root", "s" * 64),
                                                  ("directory", "sub-group", "groups/g1/members", "t" * 64)):
            db.add(ProviderEventSubscription(
                organization_id=org.id, source_id=source.id, provider="microsoft365", channel_type=channel,
                channel_id=sub_id, provider_resource_id=microsoft_binding(TENANT, resource),
                encrypted_channel_token=_secret_box.encrypt(secret), state=state,
                expires_at=datetime.now(timezone.utc) + expires_in))
        db.commit()
        return org.id, source.id


def _note(**overrides):
    item = {"subscriptionId": "sub-drive", "clientState": "s" * 64, "tenantId": TENANT,
            "changeType": "updated", "resource": f"drives/{DRIVE}/root",
            "subscriptionExpirationDateTime": "2026-12-01T00:00:00Z"}
    item.update(overrides)
    return item


def _events():
    with SessionLocal() as db:
        return list(db.scalars(select(ProviderEventJournal)))


def _post(client, *items):
    return client.post(URL, json={"value": list(items)})


def test_subscription_validation_echoes_token_as_plain_text():
    _world()
    with TestClient(app) as client:
        r = client.post(URL + "?validationToken=Validation%3A+Testing+client+application")
        assert r.status_code == 200 and r.text == "Validation: Testing client application"
        assert r.headers["content-type"].startswith("text/plain")


def test_valid_notification_is_journaled_as_a_hint_only():
    _world()
    with TestClient(app) as client:
        # A forged "resourceData" claiming a permission must never become data.
        r = _post(client, _note(resourceData={"permission": "grant alice read"}))
    assert r.status_code == 202
    events = _events()
    assert len(events) == 1 and events[0].event_type == "acl:updated" and events[0].status == "received"
    with SessionLocal() as db:
        assert db.scalar(select(GuardPolicy.id)) is None       # nothing authorizes from the payload


@pytest.mark.parametrize("bad, code", [
    ({"clientState": "x" * 64}, "CLIENT_STATE_MISMATCH"),
    ({"subscriptionId": "unknown"}, "UNKNOWN_OR_INACTIVE_SUBSCRIPTION"),
    ({"tenantId": OTHER_TENANT}, "TENANT_BINDING_MISMATCH"),
    ({"resource": "drives/b!another-drive/root"}, "RESOURCE_BINDING_MISMATCH"),
    ({"changeType": "exfiltrate"}, "UNSUPPORTED_CHANGE_TYPE"),
    ({"tenantId": "not a guid!"}, "MISSING_NOTIFICATION_FIELDS"),
    ({"clientState": ""}, "MISSING_NOTIFICATION_FIELDS"),
])
def test_forged_or_mis_scoped_notifications_are_rejected(bad, code, caplog):
    _world()
    with TestClient(app) as client, caplog.at_level("WARNING"):
        r = _post(client, _note(**bad))
    assert r.status_code == 401
    assert _events() == []
    assert code in caplog.text


def test_expired_or_retired_subscription_is_rejected():
    _world(expires_in=timedelta(seconds=-1))
    with TestClient(app) as client:
        assert _post(client, _note()).status_code == 401
    _world(state="retired")
    with TestClient(app) as client:
        assert _post(client, _note()).status_code == 401
    assert _events() == []


def test_duplicate_and_replayed_notifications_coalesce_into_one_pending_sync():
    _world()
    with TestClient(app) as client:
        for _ in range(5):
            assert _post(client, _note()).status_code == 202
    assert len(_events()) == 1
    # Once the pending sync is taken by a worker, a NEW hint must create a
    # follow-up (changes after the delta read started must not be lost).
    with SessionLocal() as db:
        event = db.scalar(select(ProviderEventJournal))
        event.status = "processing"
        db.commit()
    with TestClient(app) as client:
        assert _post(client, _note()).status_code == 202
    assert len(_events()) == 2


def test_mixed_batch_journals_only_authenticated_items():
    _world()
    with TestClient(app) as client:
        r = _post(client, _note(), _note(clientState="forged" * 10),
                  _note(subscriptionId="sub-group", clientState="t" * 64, resource="Groups/g1"))
    assert r.status_code == 202
    assert sorted(e.event_type for e in _events()) == ["acl:updated", "directory:updated"]


def test_group_notification_cannot_target_another_group():
    _world()
    with TestClient(app) as client:
        r = _post(client, _note(subscriptionId="sub-group", clientState="t" * 64, resource="Groups/g2"))
    assert r.status_code == 401 and _events() == []


def test_lifecycle_notifications_are_authenticated_and_journaled():
    _world()
    with TestClient(app) as client:
        ok = _post(client, {"subscriptionId": "sub-drive", "clientState": "s" * 64, "tenantId": TENANT,
                            "lifecycleEvent": "reauthorizationRequired"})
        forged = _post(client, {"subscriptionId": "sub-drive", "clientState": "z" * 64, "tenantId": TENANT,
                                "lifecycleEvent": "subscriptionRemoved"})
        unknown = _post(client, {"subscriptionId": "sub-drive", "clientState": "s" * 64, "tenantId": TENANT,
                                 "lifecycleEvent": "deleteEverything"})
    assert ok.status_code == 202 and forged.status_code == 401 and unknown.status_code == 401
    assert [e.event_type for e in _events()] == ["lifecycle:reauthorizationRequired"]


def test_oversized_or_malformed_bodies_are_refused():
    _world()
    with TestClient(app) as client:
        assert client.post(URL, content=b"{" * 10, headers={"Content-Type": "application/json"}).status_code == 400
        assert client.post(URL, json={"value": []}).status_code == 400
        assert client.post(URL, content=b"x" * 1_000_001, headers={"Content-Length": "1000001"}).status_code == 413


# ---------------------------------------------------------------- manager


class FakeGraph:
    def __init__(self, fail_create: set[str] | None = None):
        self.created, self.renewed, self.deleted = [], [], []
        self.fail_create = fail_create or set()

    async def create(self, want, *, callback_url, client_state, expires):
        if want.resource in self.fail_create:
            req = httpx.Request("POST", "https://graph.microsoft.com/v1.0/subscriptions")
            raise httpx.HTTPStatusError("403", request=req, response=httpx.Response(403, request=req))
        self.created.append((want.resource, want.security_webhooks, len(client_state)))
        return {"id": f"graph-{len(self.created)}", "_preference_applied": "includesecuritywebhooks" if want.security_webhooks else ""}

    async def renew(self, subscription_id, expires):
        self.renewed.append(subscription_id)
        return {}

    async def delete(self, subscription_id):
        self.deleted.append(subscription_id)

    async def aclose(self):
        pass


def _manager_world():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="Graph manager")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        import json
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint", boundary="root",
                                  name="SP", status="connected", encrypted_credentials=_secret_box.encrypt(json.dumps(
                                      {"tenant_id": TENANT, "drive_id": DRIVE, "access_token": "synthetic"})))
        db.add(source)
        db.commit()
        return source.id


async def _no_refresh(db, source, credentials):
    return credentials


def test_manager_creates_bounded_subscriptions_with_secret_client_state_and_renews_and_retires():
    from apps.worker.accessproof_worker import graph_subscriptions as gs
    source_id = _manager_world()
    fake = FakeGraph()
    url = "https://api.example.test/api/v1/provider-events/microsoft"
    stats = asyncio.run(gs.ensure_microsoft_subscriptions(source_id, callback_url=url, box=_secret_box,
                                                          refresh_credentials=_no_refresh, client_factory=lambda t: fake))
    assert stats["created"] == 2
    assert (f"drives/{DRIVE}/root", True, 64) in fake.created          # security webhooks requested on drive root
    assert ("users", False, 64) in fake.created
    with SessionLocal() as db:
        rows = list(db.scalars(select(ProviderEventSubscription)))
        assert {r.channel_type for r in rows} == {"acl", "directory"}
        assert all(r.encrypted_channel_token and len(_secret_box.decrypt(r.encrypted_channel_token)) == 64 for r in rows)
        # Near expiry -> renewed; unwanted -> retired and deleted at Graph.
        rows[0].expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        db.add(ProviderEventSubscription(organization_id=rows[0].organization_id, source_id=source_id, provider="microsoft365",
                                         channel_type="directory", channel_id="graph-stale",
                                         provider_resource_id=microsoft_binding(TENANT, "groups/old/members"),
                                         encrypted_channel_token=_secret_box.encrypt("u" * 64), state="active",
                                         expires_at=datetime.now(timezone.utc) + timedelta(days=10)))
        db.commit()
        renew_id = rows[0].channel_id
    stats = asyncio.run(gs.ensure_microsoft_subscriptions(source_id, callback_url=url, box=_secret_box,
                                                          refresh_credentials=_no_refresh, client_factory=lambda t: fake))
    assert renew_id in fake.renewed and "graph-stale" in fake.deleted
    assert stats["renewed"] == 1 and stats["retired"] == 1 and stats["created"] == 0


def test_manager_failure_is_recorded_and_never_raises_or_authorizes():
    from apps.worker.accessproof_worker import graph_subscriptions as gs
    source_id = _manager_world()
    fake = FakeGraph(fail_create={f"drives/{DRIVE}/root"})
    stats = asyncio.run(gs.ensure_microsoft_subscriptions(source_id, callback_url="https://api.example.test/api/v1/provider-events/microsoft",
                                                          box=_secret_box, refresh_credentials=_no_refresh,
                                                          client_factory=lambda t: fake))
    assert stats["failed"] == 1 and stats["created"] == 1


@pytest.mark.parametrize("url", ["http://api.example.test/api/v1/provider-events/microsoft",
                                 "https://api.example.test/other", "https://u:p@api.example.test/api/v1/provider-events/microsoft",
                                 "https://api.example.test/api/v1/provider-events/microsoft?x=1"])
def test_manager_refuses_unsafe_callback_urls(url):
    from apps.worker.accessproof_worker import graph_subscriptions as gs
    with pytest.raises(ValueError):
        asyncio.run(gs.ensure_microsoft_subscriptions("any", callback_url=url, box=_secret_box,
                                                      refresh_credentials=_no_refresh, client_factory=lambda t: FakeGraph()))


# ---------------------------------------------------------------- worker routing


@pytest.mark.parametrize("subscription_id, item, expect_sync, expect_lifecycle", [
    ("sub-drive", {}, "acl", None),
    ("sub-group", {"clientState": "t" * 64, "resource": "Groups/g1"}, "directory", None),
    ("sub-drive", {"lifecycleEvent": "reauthorizationRequired"}, "acl", "reauthorizationRequired"),
])
def test_worker_routes_each_channel_to_an_authoritative_resync(monkeypatch, subscription_id, item, expect_sync, expect_lifecycle):
    import json
    from apps.worker.accessproof_worker import graph_subscriptions as gs
    from apps.worker.accessproof_worker import main as worker
    _org, source_id = _world()
    with SessionLocal() as db:
        src = db.get(SourceConnection, source_id)
        src.encrypted_credentials = _secret_box.encrypt(json.dumps({"tenant_id": TENANT, "drive_id": DRIVE, "access_token": "x"}))
        db.commit()
    calls = []

    async def fake_acls(db, source, credentials, **kw):
        calls.append("acl")

    async def fake_directory(db, source, credentials):
        calls.append("directory")

    async def fake_refresh(db, source, credentials):
        return credentials

    async def fake_lifecycle(sub_row_id, lifecycle, **kw):
        calls.append(f"lifecycle:{lifecycle}")
        return "REAUTHORIZED"
    monkeypatch.setattr(worker, "synchronize_acls", fake_acls)
    monkeypatch.setattr(worker, "synchronize_directory", fake_directory)
    monkeypatch.setattr(worker, "refresh_source_credentials_if_needed", fake_refresh)
    monkeypatch.setattr(gs, "handle_lifecycle", fake_lifecycle)
    with TestClient(app) as client:
        note = _note(subscriptionId=subscription_id, **item)
        if "lifecycleEvent" in item:
            note = {k: note[k] for k in ("subscriptionId", "clientState", "tenantId", "lifecycleEvent")}
        assert _post(client, note).status_code == 202
    event_id = worker.claim_one_provider_event()
    asyncio.run(worker.process_provider_event(event_id))
    expected = ([f"lifecycle:{expect_lifecycle}"] if expect_lifecycle else []) + [expect_sync]
    assert calls == expected
    with SessionLocal() as db:
        assert db.get(ProviderEventJournal, event_id).status == "completed"


def test_failed_authoritative_resync_retries_and_never_completes(monkeypatch):
    import json
    from apps.worker.accessproof_worker import main as worker
    _org, source_id = _world()
    with SessionLocal() as db:
        db.get(SourceConnection, source_id).encrypted_credentials = _secret_box.encrypt(json.dumps({"access_token": "x"}))
        db.commit()

    async def failing(db, source, credentials, **kw):
        raise worker.ACLSyncError("DEGRADED")

    async def fake_refresh(db, source, credentials):
        return credentials
    monkeypatch.setattr(worker, "synchronize_acls", failing)
    monkeypatch.setattr(worker, "refresh_source_credentials_if_needed", fake_refresh)
    with TestClient(app) as client:
        assert _post(client, _note()).status_code == 202
    event_id = worker.claim_one_provider_event()
    asyncio.run(worker.process_provider_event(event_id))
    with SessionLocal() as db:
        event = db.get(ProviderEventJournal, event_id)
        assert event.status == "retry" and event.error_code == "DEGRADED"
        assert db.scalar(select(GuardPolicy.id)) is None
