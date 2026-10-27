"""A stale or forged durable resource record must never confer mutation ownership."""
import httpx
import pytest

from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import UnsafeBoundaryError
from packages.domain.models import SourceResource


@pytest.mark.asyncio
async def test_drive_recovery_rejects_unrelated_provider_file_without_mutation():
    adapter = GoogleDriveAdapter(
        access_token="synthetic-token", test_root_folder_id="approved-root",
    )
    resource = SourceResource(
        provider_id="unrelated-file", name="unrelated.txt",
        marker="accessproof-generated", canary="secret-test-marker",
        metadata={"test_root_folder_id": "approved-root"},
    )
    actions = []

    async def fake_request(method, url, **kwargs):
        actions.append(method)
        return httpx.Response(200, json={
            "id": "unrelated-file", "name": "unrelated.txt",
            "parents": ["someone-elses-folder"],
            "description": "Unrelated customer document", "trashed": False,
        })
    adapter._request = fake_request
    with pytest.raises(UnsafeBoundaryError):
        await adapter.adopt_tracked_resource(resource)
    assert "DELETE" not in actions


@pytest.mark.asyncio
async def test_microsoft_recovery_rejects_unrelated_provider_file_without_mutation():
    adapter = Microsoft365Adapter(
        access_token="synthetic-token", drive_id="test-drive",
        test_root_item_id="approved-root",
    )
    resource = SourceResource(
        provider_id="unrelated-file", name="unrelated.txt",
        marker="accessproof-generated", canary="secret-test-marker",
        metadata={"drive_id": "test-drive", "test_root_item_id": "approved-root"},
    )
    actions = []

    async def fake_request(method, path, **kwargs):
        actions.append(method)
        return httpx.Response(200, json={
            "id": "unrelated-file", "name": "unrelated.txt",
            "parentReference": {"id": "someone-elses-folder", "driveId": "test-drive"},
        })
    adapter._request = fake_request
    with pytest.raises(UnsafeBoundaryError):
        await adapter.adopt_tracked_resource(resource)
    assert "DELETE" not in actions


@pytest.mark.asyncio
async def test_drive_recovery_accepts_only_matching_test_marker_and_provider_boundary():
    import hashlib
    marker = "synthetic-generated-marker-1"
    tag = hashlib.sha256(marker.encode()).hexdigest()[:24]
    name = f"generated-{tag}.txt"
    adapter = GoogleDriveAdapter(access_token="synthetic", test_root_folder_id="root")
    resource = SourceResource("test-file", name, "accessproof-generated", marker,
                              {"test_root_folder_id": "root"})
    calls = []
    async def fake_request(method, url, **kwargs):
        calls.append(method)
        return httpx.Response(200, json={
            "id": "test-file", "name": name,
            "description": f"accessproof-generated {marker}",
            "parents": ["root"], "trashed": False,
        })
    adapter._request = fake_request
    await adapter.adopt_tracked_resource(resource)
    assert calls == ["GET"]
    assert "test-file" in adapter._created


@pytest.mark.asyncio
async def test_microsoft_recovery_accepts_only_matching_test_marker_and_drive_boundary():
    import hashlib
    marker = "synthetic-generated-marker-2"
    tag = hashlib.sha256(marker.encode()).hexdigest()[:24]
    name = f"generated-{tag}.txt"
    adapter = Microsoft365Adapter(
        access_token="synthetic", drive_id="drive", test_root_item_id="root",
    )
    resource = SourceResource("test-file", name, "accessproof-generated", marker,
                              {"drive_id": "drive", "test_root_item_id": "root"})
    calls = []
    async def fake_request(method, path, **kwargs):
        calls.append(method)
        return httpx.Response(200, json={
            "id": "test-file", "name": name,
            "parentReference": {"id": "root", "driveId": "drive"},
        })
    adapter._request = fake_request
    await adapter.adopt_tracked_resource(resource)
    assert calls == ["GET"]
    assert "test-file" in adapter._created


@pytest.mark.parametrize("bad_id", ["../file", "abc?x=1", "abc#item", "abc%2Fdef"])
@pytest.mark.asyncio
async def test_microsoft_recovery_rejects_provider_id_path_delimiters(bad_id):
    adapter = Microsoft365Adapter(
        access_token="synthetic", drive_id="drive", test_root_item_id="root",
    )
    resource = SourceResource(
        bad_id, "created.txt", "accessproof-generated", "marker",
        {"drive_id": "drive", "test_root_item_id": "root"},
    )
    async def unexpected_request(method, path, **kwargs):
        raise AssertionError("An invalid resource identifier must not reach Graph")
    adapter._request = unexpected_request
    with pytest.raises(UnsafeBoundaryError):
        await adapter.adopt_tracked_resource(resource)
