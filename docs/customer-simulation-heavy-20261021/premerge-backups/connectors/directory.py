"""Provider directory readers used to synchronize stable enterprise identities.

They intentionally return provider IDs and metadata only.  Authorization is
resolved later by the Guard pipeline; a failed or incomplete directory read is
never interpreted as a denial.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncIterator

import httpx


class DirectorySyncError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _error_code(response: httpx.Response) -> str:
    if response.status_code == 401:
        return "REAUTHORIZATION_REQUIRED"
    if response.status_code == 403:
        return "INSUFFICIENT_DIRECTORY_PERMISSION"
    return "DIRECTORY_SYNC_INCOMPLETE"


@dataclass(frozen=True)
class DirectoryUser:
    provider_id: str
    display_name: str | None
    email: str | None
    status: str


@dataclass(frozen=True)
class DirectoryGroup:
    provider_id: str
    display_name: str | None
    email: str | None


class _DirectoryClient:
    def __init__(self, token: str, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(
            timeout=30, headers={"Authorization": f"Bearer {token}"}, trust_env=False
        )
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _pages(self, url: str, *, params: dict[str, str] | None = None) -> AsyncIterator[dict[str, Any]]:
        next_url: str | None = url
        next_params = params
        while next_url:
            response = await self._client.get(next_url, params=next_params)
            if response.is_error:
                raise DirectorySyncError(_error_code(response))
            payload = response.json()
            if not isinstance(payload, dict):
                raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
            yield payload
            page_token = payload.get("nextPageToken")
            if page_token:
                next_url = url
                next_params = {**(params or {}), "pageToken": str(page_token)}
            else:
                next_url = payload.get("@odata.nextLink")
                next_params = None


class GoogleWorkspaceDirectoryAdapter(_DirectoryClient):
    """Google Admin SDK Directory API reader with provider pagination."""

    API = "https://admin.googleapis.com/admin/directory/v1"

    async def users(self) -> list[DirectoryUser]:
        result: list[DirectoryUser] = []
        async for page in self._pages(f"{self.API}/users", params={"customer": "my_customer", "maxResults": "100", "orderBy": "email"}):
            for user in page.get("users", []):
                identifier = user.get("id")
                if isinstance(identifier, str) and identifier:
                    result.append(DirectoryUser(identifier, user.get("name", {}).get("fullName"), user.get("primaryEmail"), "suspended" if user.get("suspended") else "active"))
        return result

    async def groups(self) -> list[DirectoryGroup]:
        result: list[DirectoryGroup] = []
        async for page in self._pages(f"{self.API}/groups", params={"customer": "my_customer", "maxResults": "200"}):
            for group in page.get("groups", []):
                identifier = group.get("id")
                if isinstance(identifier, str) and identifier:
                    result.append(DirectoryGroup(identifier, group.get("name"), group.get("email")))
        return result

    async def members(self, group_id: str) -> list[str]:
        """Return effective user members, recursively expanding nested groups.

        The Directory Members endpoint returns direct members.  Treating an
        undocumented request parameter as a promise of transitive membership
        could leave a user authorized through a nested group out of the policy
        graph.  We therefore walk GROUP members explicitly, preserve provider
        pagination at every level, and terminate cycles deterministically.
        A provider failure on any nested group propagates and keeps the source
        health degraded rather than publishing a partial group expansion.
        """
        result: set[str] = set()
        pending = [group_id]
        visited: set[str] = set()
        while pending:
            current_group = pending.pop()
            if current_group in visited:
                continue
            visited.add(current_group)
            async for page in self._pages(
                f"{self.API}/groups/{current_group}/members",
                params={"maxResults": "200"},
            ):
                members = page.get("members")
                if not isinstance(members, list):
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                for member in members:
                    if not isinstance(member, dict):
                        raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                    identifier = member.get("id")
                    if not isinstance(identifier, str) or not identifier:
                        raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                    member_type = member.get("type")
                    if member_type == "USER":
                        result.add(identifier)
                    elif member_type == "GROUP":
                        pending.append(identifier)
        return sorted(result)


class MicrosoftEntraDirectoryAdapter(_DirectoryClient):
    """Microsoft Graph reader using Entra object IDs as stable identifiers."""

    API = "https://graph.microsoft.com/v1.0"

    async def users(self) -> list[DirectoryUser]:
        result: list[DirectoryUser] = []
        async for page in self._pages(f"{self.API}/users", params={"$select": "id,displayName,mail,userPrincipalName,accountEnabled", "$top": "999"}):
            for user in page.get("value", []):
                identifier = user.get("id")
                if isinstance(identifier, str) and identifier:
                    result.append(DirectoryUser(identifier, user.get("displayName"), user.get("mail") or user.get("userPrincipalName"), "active" if user.get("accountEnabled", True) else "disabled"))
        return result

    async def groups(self) -> list[DirectoryGroup]:
        result: list[DirectoryGroup] = []
        async for page in self._pages(f"{self.API}/groups", params={"$select": "id,displayName,mail", "$top": "999"}):
            for group in page.get("value", []):
                identifier = group.get("id")
                if isinstance(identifier, str) and identifier:
                    result.append(DirectoryGroup(identifier, group.get("displayName"), group.get("mail")))
        return result

    async def members(self, group_id: str) -> list[str]:
        result: list[str] = []
        async for page in self._pages(f"{self.API}/groups/{group_id}/members/microsoft.graph.user", params={"$select": "id", "$top": "999"}):
            for member in page.get("value", []):
                identifier = member.get("id")
                if isinstance(identifier, str) and identifier:
                    result.append(identifier)
        return result
