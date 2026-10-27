from __future__ import annotations

import httpx
import pytest

from connectors.google_drive.adapter import GoogleDriveAdapter
from packages.connector_sdk.base import UnsafeBoundaryError


@pytest.mark.asyncio
async def test_drive_changes_watch_binds_returned_channel_and_resource(monkeypatch):
    adapter = GoogleDriveAdapter(access_token="token", test_root_folder_id="root")
    async def request(method, url, **kwargs):
        assert method == "POST" and url.endswith("/changes/watch")
        assert kwargs["params"]["pageToken"] == "cursor-1"
        assert kwargs["json"]["token"] == "secret"
        return httpx.Response(200, json={"id": "channel-1", "resourceId": "resource-1", "expiration": "9999999999999"})
    monkeypatch.setattr(adapter, "_request", request)
    result = await adapter.watch_changes(
        page_token="cursor-1", channel_id="channel-1", callback_url="https://events.example.test/google",
        channel_token="secret", expiration_millis=9999999999999,
    )
    assert result["resourceId"] == "resource-1"
    await adapter._client.aclose()


@pytest.mark.asyncio
async def test_drive_changes_watch_rejects_non_https_callback():
    adapter = GoogleDriveAdapter(access_token="token", test_root_folder_id="root")
    with pytest.raises(UnsafeBoundaryError):
        await adapter.watch_changes(page_token="cursor", channel_id="id", callback_url="http://localhost/callback", channel_token="token")
    await adapter._client.aclose()


@pytest.mark.asyncio
async def test_drive_changes_accepts_shared_drive_membership_event(monkeypatch):
    adapter = GoogleDriveAdapter(access_token="token", test_root_folder_id="root")
    async def request(method, url, **kwargs):
        assert method == "GET" and url.endswith("/changes")
        assert "changeType" in kwargs["params"]["fields"]
        assert "driveId" in kwargs["params"]["fields"]
        return httpx.Response(200, json={
            "changes": [{"changeType": "drive", "driveId": "shared-drive-1", "removed": True}],
            "newStartPageToken": "next",
        })
    monkeypatch.setattr(adapter, "_request", request)
    try:
        result = await adapter.acl_change_page("cursor")
        assert result["changes"][0]["driveId"] == "shared-drive-1"
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_drive_changes_rejects_shared_drive_without_identifier(monkeypatch):
    adapter = GoogleDriveAdapter(access_token="token", test_root_folder_id="root")
    async def request(method, url, **kwargs):
        return httpx.Response(200, json={
            "changes": [{"changeType": "drive", "removed": True}],
            "newStartPageToken": "next",
        })
    monkeypatch.setattr(adapter, "_request", request)
    try:
        with pytest.raises(ValueError, match="DRIVE_CHANGES_PAGE_INCOMPLETE"):
            await adapter.acl_change_page("cursor")
    finally:
        await adapter._client.aclose()
