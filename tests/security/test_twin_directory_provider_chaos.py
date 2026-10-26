"""Malicious and malformed synthetic Directory API replies never leak tokens or hang."""
from __future__ import annotations

import httpx
import pytest

from connectors.directory import GoogleWorkspaceDirectoryAdapter, DirectorySyncError


@pytest.mark.asyncio
async def test_google_directory_must_never_follow_external_nextlink_with_admin_bearer():
    seen = []

    def handler(request: httpx.Request):
        seen.append((str(request.url), request.headers.get("authorization")))
        if request.url.host == "admin.googleapis.com":
            return httpx.Response(200, json={
                "users": [{"id": "alice", "primaryEmail": "alice@example.test"}],
                "@odata.nextLink": "https://attacker.example.test/steal-admin-token",
            })
        return httpx.Response(200, json={"users": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = GoogleWorkspaceDirectoryAdapter("fake-admin-token", client)
    try:
        with pytest.raises(DirectorySyncError):
            await adapter.users()
        assert len(seen) == 1, f"Bearer token sent to unexpected host: {seen!r}"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_google_directory_rejects_repeated_page_tokens_without_unbounded_loop():
    calls = []
    def handler(request: httpx.Request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"users": [], "nextPageToken": "repeat"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = GoogleWorkspaceDirectoryAdapter("fake-admin-token", client)
    try:
        with pytest.raises(DirectorySyncError):
            await adapter.users()
        assert len(calls) <= 3, f"Provider pagination loop made {len(calls)} calls"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_directory_empty_malformed_success_cannot_be_trusted_as_full_snapshot():
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"arbitrary_response": True})
    ))
    adapter = GoogleWorkspaceDirectoryAdapter("fake-admin-token", client)
    try:
        with pytest.raises(DirectorySyncError):
            await adapter.users()
    finally:
        await client.aclose()
