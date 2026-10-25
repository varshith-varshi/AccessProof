"""Mocked customer Google Drive API corruption must never look like success."""
import httpx
import pytest

from connectors.google_drive.adapter import GoogleDriveAdapter


async def _adapter(handler):
    source = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await source._client.aclose()
    source._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return source


@pytest.mark.asyncio
async def test_empty_invalid_changes_page_does_not_mark_poll_completed():
    source = await _adapter(lambda _: httpx.Response(
        200, json={"changes": []}  # No continuation OR newStartPageToken.
    ))
    try:
        with pytest.raises(ValueError, match="DRIVE_CHANGES_PAGE_INCOMPLETE"):
            await source.acl_change_page("cursor")
    finally:
        await source._client.aclose()


@pytest.mark.asyncio
async def test_missing_permission_collection_does_not_revoke_every_employee():
    source = await _adapter(lambda _: httpx.Response(200, json={"kind": "invalid"}))
    try:
        with pytest.raises(ValueError, match="DRIVE_PERMISSION_SNAPSHOT_INCOMPLETE"):
            await source.permissions_snapshot("protected-file")
    finally:
        await source._client.aclose()


@pytest.mark.asyncio
async def test_missing_boundary_file_collection_does_not_mark_inventory_complete():
    source = await _adapter(lambda _: httpx.Response(200, json={"kind": "invalid"}))
    try:
        with pytest.raises(ValueError, match="DRIVE_BOUNDARY_INVENTORY_INCOMPLETE"):
            await source.list_boundary_resources()
    finally:
        await source._client.aclose()
