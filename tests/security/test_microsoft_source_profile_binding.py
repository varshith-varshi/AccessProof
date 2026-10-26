"""Provider-scoped Microsoft source bindings must fail closed before Protect."""

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine
from connectors.factory import create_source_adapter
from packages.connector_sdk.base import UnsafeBoundaryError


TENANT = "11111111-2222-3333-4444-555555555555"
SITE_GUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
SITE = f"contoso.sharepoint.com,{TENANT},{SITE_GUID}"
LIST = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OWNER = "22222222-3333-4444-5555-666666666666"


def test_ms_create_requires_distinct_site_library_or_owner_identity():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": "ms-provider-binding@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Profile binding",
        })
        assert signup.status_code == 201
        data = signup.json()
        headers = {"Authorization": f"Bearer {data['session_token']}",
                   "X-Organization-ID": data["organization_id"]}
        base = {"tenant_id": TENANT, "drive_id": "drive-1",
                "test_root_item_id": "root", "access_token": "synthetic"}
        def create(provider, fields):
            return client.post("/api/v1/current/sources", headers=headers, json={
                "provider": provider, "name": "Test source", "boundary": "root",
                "credentials": {**base, **fields},
            })
        assert create("sharepoint", {}).status_code == 422
        assert create("sharepoint", {"site_id": SITE, "list_id": "bad"}).status_code == 422
        assert create("onedrive", {}).status_code == 422
        assert create("onedrive", {"owner_object_id": "bad"}).status_code == 422
        assert create("sharepoint", {"site_id": SITE, "list_id": LIST}).status_code == 201
        assert create("onedrive", {"owner_object_id": OWNER}).status_code == 201


@pytest.mark.asyncio
async def test_sharepoint_profile_rejects_graph_site_or_library_mismatch():
    def handler(request: httpx.Request):
        assert request.url.path == "/v1.0/drives/drive-1/items/root"
        assert "sharepointIds" in request.url.params["$select"]
        return httpx.Response(200, json={
            "id": "root", "name": "Documents", "folder": {},
            "sharepointIds": {"siteId": TENANT, "webId": SITE_GUID, "listId": LIST,
                               "siteUrl": "https://contoso.sharepoint.com/sites/Finance"},
        })

    adapter = create_source_adapter("sharepoint", {
        "access_token": "synthetic", "drive_id": "drive-1",
        "test_root_item_id": "root", "tenant_hint": TENANT,
        "site_id": SITE, "list_id": LIST,
    })
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        assert (await adapter.validate_connection()).boundary == "root"
        adapter.sharepoint_list_id = "aaaaaaaa-0000-0000-0000-000000000000"
        with pytest.raises(UnsafeBoundaryError, match="does not match"):
            await adapter.validate_connection()
        adapter.sharepoint_list_id = LIST
        adapter.sharepoint_site_id = f"contoso.sharepoint.com,{TENANT},00000000-0000-0000-0000-000000000009"
        with pytest.raises(UnsafeBoundaryError, match="does not match"):
            await adapter.validate_connection()
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_onedrive_profile_rejects_wrong_owner_or_non_business_drive():
    actual_owner = OWNER
    drive_type = "business"
    def handler(request: httpx.Request):
        if request.url.path == "/v1.0/drives/drive-1/items/root":
            return httpx.Response(200, json={"id": "root", "name": "Folder", "folder": {}})
        if request.url.path == "/v1.0/drives/drive-1":
            return httpx.Response(200, json={
                "id": "drive-1", "driveType": drive_type,
                "owner": {"user": {"id": actual_owner}},
            })
        return httpx.Response(404)

    adapter = create_source_adapter("onedrive", {
        "access_token": "synthetic", "drive_id": "drive-1",
        "test_root_item_id": "root", "tenant_hint": TENANT,
        "owner_object_id": OWNER,
    })
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        assert (await adapter.validate_connection()).boundary == "root"
        adapter.onedrive_owner_object_id = "aaaaaaaa-0000-0000-0000-000000000000"
        with pytest.raises(UnsafeBoundaryError, match="could not be verified"):
            await adapter.validate_connection()
    finally:
        await adapter._client.aclose()


@pytest.mark.parametrize(("provider", "profile"), [
    ("sharepoint", {"site_id": SITE, "list_id": LIST}),
    ("onedrive", {"owner_object_id": OWNER}),
])
def test_uncertified_provider_profile_cannot_enable_protect(provider, profile):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        registered = client.post("/api/v1/auth/signup", json={
            "email": f"uncertified-{provider}@example.com",
            "password": "correct horse battery staple",
            "organization_name": f"Uncertified {provider}",
        })
        assert registered.status_code == 201, registered.text
        account = registered.json()
        headers = {"Authorization": f"Bearer {account['session_token']}",
                   "X-Organization-ID": account["organization_id"]}
        source = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": provider, "name": provider, "boundary": "root",
            "credentials": {
                "tenant_id": TENANT, "drive_id": "drive-1",
                "test_root_item_id": "root", "access_token": "synthetic",
                **profile,
            },
        })
        assert source.status_code == 201, source.text
        guard = client.post("/api/v1/guards", headers=headers, json={"name": "test-guard"})
        assert guard.status_code == 201, guard.text
        app_id = f"{provider}-rag"
        registered_app = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": app_id, "name": app_id,
            "guard_id": guard.json()["id"], "source_id": source.json()["id"],
            "adapter_type": "generic-python",
            "adapter_contract_version": "accessproof.rag/v1",
        })
        assert registered_app.status_code == 201, registered_app.text
        status = client.get(f"/api/v1/current/ai-applications/{app_id}/protect-readiness", headers=headers)
        assert status.status_code == 200
        codes = {row["code"]: row["ok"] for row in status.json()["checks"]}
        assert codes["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"] is False
        mode = client.patch(f"/api/v1/current/ai-applications/{app_id}/mode",
                            headers=headers, json={"mode": "protect"})
        assert mode.status_code == 409
