"""Provider directory readers used to synchronize stable enterprise identities.

They intentionally return provider IDs and metadata only.  Authorization is
resolved later by the Guard pipeline; a failed or incomplete directory read is
never interpreted as a denial.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncIterator

import httpx
from urllib.parse import quote


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
    # "member" | "guest" | "unknown". Only Microsoft classifies accounts; an
    # unclassifiable account is never eligible for automatic identity binding.
    account_kind: str = "member"


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
        # Google/Graph reply bodies must not control where the credential
        # bearing client sends its *next* request. Only the initial official
        # endpoint may be paginated, regardless of returned nextLink.
        original = httpx.URL(url)
        if original.scheme != "https" or original.host not in {
            "admin.googleapis.com", "graph.microsoft.com",
        }:
            raise DirectorySyncError("DIRECTORY_UNTRUSTED_PAGINATION_URL")
        next_url: str | None = url
        next_params = params
        seen_urls: set[str] = set()
        seen_tokens: set[str] = set()
        pages = 0
        while next_url:
            candidate = httpx.URL(next_url)
            if (candidate.scheme != "https" or candidate.host != original.host
                    or candidate.path != original.path or pages >= 2000):
                raise DirectorySyncError("DIRECTORY_UNTRUSTED_PAGINATION_URL")
            request_key = f"{str(candidate)}?{sorted((next_params or {}).items())}"
            if request_key in seen_urls:
                raise DirectorySyncError("DIRECTORY_PAGINATION_LOOP")
            seen_urls.add(request_key)
            pages += 1
            response = await self._client.get(next_url, params=next_params)
            if response.is_error:
                raise DirectorySyncError(_error_code(response))
            payload = response.json()
            if not isinstance(payload, dict):
                raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
            yield payload
            page_token = payload.get("nextPageToken")
            if page_token:
                if not isinstance(page_token, str) or page_token in seen_tokens:
                    raise DirectorySyncError("DIRECTORY_PAGINATION_LOOP")
                seen_tokens.add(page_token)
                next_url = url
                next_params = {**(params or {}), "pageToken": page_token}
            else:
                next_url = payload.get("@odata.nextLink")
                next_params = None


class GoogleWorkspaceDirectoryAdapter(_DirectoryClient):
    """Google Admin SDK Directory API reader with provider pagination."""

    API = "https://admin.googleapis.com/admin/directory/v1"

    async def drive_permission_id(self, email: str) -> str:
        """Resolve Drive's opaque grantee ID, not a mutable email alias.

        Official Drive v2 permissions.getIdForEmail with fixed Google host,
        using the same read-only OAuth credential as the Drive v3 connector.
        An incomplete/error response never certifies an employee identity.
        """
        if (not isinstance(email, str) or not 3 <= len(email) <= 320
                or "@" not in email or any(ord(ch) < 33 for ch in email)):
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_EMAIL_INVALID")
        url = f"https://www.googleapis.com/drive/v2/permissionIds/{quote(email, safe='')}"
        try:
            response = await self._client.get(url, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_UNAVAILABLE") from exc
        if response.status_code == 401:
            raise DirectorySyncError("REAUTHORIZATION_REQUIRED")
        if response.status_code == 403:
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_FORBIDDEN")
        if response.status_code in {429, 500, 502, 503, 504}:
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_UNAVAILABLE")
        if response.status_code != 200:
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED")
        try:
            body = response.json()
        except ValueError as exc:
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_INVALID") from exc
        if (not isinstance(body, dict) or body.get("kind") != "drive#permissionId"
                or not isinstance(body.get("id"), str) or not body["id"]
                or len(body["id"]) > 255):
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_INVALID")
        return str(body["id"])

    async def users(self) -> list[DirectoryUser]:
        result: list[DirectoryUser] = []
        async for page in self._pages(f"{self.API}/users", params={"customer": "my_customer", "maxResults": "100", "orderBy": "email"}):
            entries = page.get("users")
            if entries is None and page.get("kind") == "admin#directory#users" and not page.get("nextPageToken"):
                entries = []
            if not isinstance(entries, list):
                raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
            for user in entries:
                if not isinstance(user, dict) or not isinstance(user.get("id"), str) or not user["id"]:
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                name = user.get("name")
                if name is not None and not isinstance(name, dict):
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                if not isinstance(user.get("suspended", False), bool):
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                result.append(DirectoryUser(user["id"], (name or {}).get("fullName"), user.get("primaryEmail"), "suspended" if user.get("suspended") else "active"))
        return result

    async def groups(self) -> list[DirectoryGroup]:
        result: list[DirectoryGroup] = []
        async for page in self._pages(f"{self.API}/groups", params={"customer": "my_customer", "maxResults": "200"}):
            entries = page.get("groups")
            if entries is None and page.get("kind") == "admin#directory#groups" and not page.get("nextPageToken"):
                entries = []
            if not isinstance(entries, list):
                raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
            for group in entries:
                if not isinstance(group, dict) or not isinstance(group.get("id"), str) or not group["id"]:
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                result.append(DirectoryGroup(group["id"], group.get("name"), group.get("email")))
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
    """Strict Microsoft Graph directory reader with stable Entra object IDs.

    A successful but truncated Graph response is never a complete directory
    snapshot. Transitive user membership includes nested Entra security groups.
    """

    API = "https://graph.microsoft.com/v1.0"

    @staticmethod
    def _entries(page: dict[str, Any]) -> list[dict[str, Any]]:
        entries = page.get("value")
        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
        return entries

    async def users(self) -> list[DirectoryUser]:
        result: list[DirectoryUser] = []
        async for page in self._pages(
            f"{self.API}/users",
            params={"$select": "id,displayName,mail,userPrincipalName,accountEnabled,userType", "$top": "999"},
        ):
            for user in self._entries(page):
                identifier = user.get("id")
                enabled = user.get("accountEnabled")
                if not isinstance(identifier, str) or not identifier or not isinstance(enabled, bool):
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                result.append(DirectoryUser(
                    identifier, user.get("displayName"), user.get("mail") or user.get("userPrincipalName"),
                    "active" if enabled else "disabled",
                    self._account_kind(user),
                ))
        return result

    @staticmethod
    def _account_kind(user: dict[str, Any]) -> str:
        """Member vs B2B guest. A guest's object in this tenant is not its home
        identity, so guests are never automatically bound (deny; admin exception).
        userType is null only for some legacy member accounts; a guest UPN
        always carries #EXT#, so null + no #EXT# is a member."""
        kind = user.get("userType")
        upn = str(user.get("userPrincipalName") or "")
        if kind == "Guest" or "#EXT#" in upn.upper():
            return "guest"
        if kind == "Member" or (kind is None and upn):
            return "member"
        return "unknown"

    async def groups(self) -> list[DirectoryGroup]:
        result: list[DirectoryGroup] = []
        async for page in self._pages(
            f"{self.API}/groups", params={"$select": "id,displayName,mail", "$top": "999"}
        ):
            for group in self._entries(page):
                identifier = group.get("id")
                if not isinstance(identifier, str) or not identifier:
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                result.append(DirectoryGroup(identifier, group.get("displayName"), group.get("mail")))
        return result

    async def members(self, group_id: str) -> list[str]:
        # The direct members/microsoft.graph.user API omits employees reached
        # through nested security groups. Read the *transitive* collection and
        # filter the returned object types without relying on email equality.
        if (not isinstance(group_id, str) or not group_id
                or not all(ch.isalnum() or ch in "_-" for ch in group_id)):
            raise DirectorySyncError("DIRECTORY_INVALID_GROUP_ID")
        result: set[str] = set()
        async for page in self._pages(f"{self.API}/groups/{group_id}/transitiveMembers"):
            for member in self._entries(page):
                identifier = member.get("id")
                kind = member.get("@odata.type")
                if not isinstance(identifier, str) or not identifier or not isinstance(kind, str):
                    raise DirectorySyncError("DIRECTORY_SYNC_INCOMPLETE")
                if kind == "#microsoft.graph.user":
                    result.add(identifier)
        return sorted(result)
