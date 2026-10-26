"""Read-only SharePoint effective-access probe for controlled customer validation.

The Graph DriveItem /permissions collection is NOT a complete SharePoint
effective ACL oracle for sites, libraries, inheritance, SharePoint groups and
some link access. SharePoint REST ListItem.GetUserEffectivePermissions can
evaluate a specifically identified employee at a particular list item.

This probe never constructs trusted user login names from mutable emails; the
caller must provide a separately verified SharePoint LoginName. A SharePoint-
audience token is required, not the Microsoft Graph access token. This module
does NOT publish Guard ALLOW policy, and does not certify SharePoint Protect.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import httpx


class SharePointPermissionError(RuntimeError):
    pass


def _trusted_site_url(site_url: str) -> str:
    try:
        url = urlsplit(site_url)
    except (ValueError, TypeError) as exc:
        raise SharePointPermissionError("SHAREPOINT_SITE_URL_INVALID") from exc
    host = (url.hostname or "").lower()
    if (url.scheme != "https" or not host.endswith(".sharepoint.com")
            or host in {".sharepoint.com", "sharepoint.com"}
            or url.port not in (None, 443) or url.username or url.password
            or url.query or url.fragment or "//" in url.path
            or any(segment in (".", "..") for segment in url.path.split("/"))):
        raise SharePointPermissionError("SHAREPOINT_SITE_URL_UNTRUSTED")
    return urlunsplit(("https", host, url.path.rstrip("/"), "", ""))


def _parse_effective_permissions(payload: object) -> bool:
    """An explicit ViewListItems permission is the minimum for item reading."""
    if not isinstance(payload, dict):
        raise SharePointPermissionError("SHAREPOINT_EFFECTIVE_PERMISSION_INCOMPLETE")
    inner = payload.get("d", payload)
    if isinstance(inner, dict):
        inner = inner.get("GetUserEffectivePermissions", inner)
    if not isinstance(inner, dict):
        raise SharePointPermissionError("SHAREPOINT_EFFECTIVE_PERMISSION_INCOMPLETE")
    try:
        low, high = inner["Low"], inner["High"]
        if (not isinstance(low, (str, int)) or isinstance(low, bool)
                or not isinstance(high, (str, int)) or isinstance(high, bool)):
            raise ValueError("invalid permission mask")
        low_int, high_int = int(low), int(high)
        if not (0 <= low_int <= 0xFFFFFFFF and 0 <= high_int <= 0xFFFFFFFF):
            raise ValueError("permission mask out of range")
    except (ValueError, TypeError, KeyError) as exc:
        raise SharePointPermissionError("SHAREPOINT_EFFECTIVE_PERMISSION_INCOMPLETE") from exc
    # SP.PermissionKind.ViewListItems = 1; bit position is enum ordinal minus 1.
    return bool(low_int & 1)


class SharePointEffectiveAccessProbe:
    """Read-only, list-item-level check with explicit SharePoint tenant/site URL."""

    def __init__(
        self, *, site_url: str, sharepoint_access_token: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.site_url = _trusted_site_url(site_url)
        if not isinstance(sharepoint_access_token, str) or not sharepoint_access_token:
            raise SharePointPermissionError("SHAREPOINT_TOKEN_REQUIRED")
        self._owned = client is None
        self.client = client or httpx.AsyncClient(
            timeout=15, follow_redirects=False, trust_env=False,
        )
        self._authorization = f"Bearer {sharepoint_access_token}"

    async def close(self) -> None:
        if self._owned:
            await self.client.aclose()

    async def can_view_item(
        self, *, list_id: str, item_id: int, verified_login_name: str,
    ) -> bool:
        try:
            list_guid = str(UUID(list_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise SharePointPermissionError("SHAREPOINT_LIST_ID_INVALID") from exc
        if not isinstance(item_id, int) or isinstance(item_id, bool) or not 0 < item_id < 2**31:
            raise SharePointPermissionError("SHAREPOINT_ITEM_ID_INVALID")
        if (not isinstance(verified_login_name, str) or not verified_login_name
                or len(verified_login_name) > 500 or any(
                    char in verified_login_name for char in "\r\n\x00"
                )):
            raise SharePointPermissionError("SHAREPOINT_VERIFIED_LOGIN_REQUIRED")
        # Microsoft REST's @u parameter is an OData string literal; double
        # single quotes inside login names to prevent expression injection.
        user_literal = "'" + verified_login_name.replace("'", "''") + "'"
        path = (
            f"{self.site_url}/_api/web/lists(guid'{list_guid}')/"
            f"items({item_id})/getusereffectivepermissions(@u)"
        )
        try:
            response = await self.client.get(
                path, params={"@u": user_literal},
                headers={
                    "Authorization": self._authorization,
                    "Accept": "application/json;odata=nometadata",
                },
            )
        except httpx.HTTPError as exc:
            raise SharePointPermissionError("SHAREPOINT_PERMISSION_ENDPOINT_UNAVAILABLE") from exc
        if response.status_code in {401, 403}:
            raise SharePointPermissionError("SHAREPOINT_PERMISSION_SCOPE_UNAVAILABLE")
        if response.status_code != 200:
            raise SharePointPermissionError("SHAREPOINT_PERMISSION_ENDPOINT_UNAVAILABLE")
        try:
            return _parse_effective_permissions(response.json())
        except ValueError as exc:
            raise SharePointPermissionError("SHAREPOINT_PERMISSION_RESPONSE_INVALID") from exc
