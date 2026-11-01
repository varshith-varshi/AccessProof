"""Resolve immutable Entra user object IDs to SharePoint login names.

Never trust an email address or a caller-supplied SharePoint LoginName as
the employee's identity. This is only one input to live permission checks;
it is NOT by itself a complete effective-access certification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

import httpx


class MicrosoftIdentityResolutionError(RuntimeError):
    """Does not include raw identities, Graph provider data, or credentials."""


@dataclass(frozen=True)
class VerifiedEmployee:
    tenant_id: str
    object_id: str
    user_principal_name: str
    sharepoint_login_name: str


class GraphEmployeeIdentityResolver:
    def __init__(
        self, *, tenant_id: str, graph_access_token: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        try:
            self.tenant_id = str(UUID(tenant_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise MicrosoftIdentityResolutionError("MICROSOFT_TENANT_ID_INVALID") from exc
        if not isinstance(graph_access_token, str) or not graph_access_token:
            raise MicrosoftIdentityResolutionError("MICROSOFT_GRAPH_ACCESS_TOKEN_REQUIRED")
        self._authorization = f"Bearer {graph_access_token}"
        self._owned = client is None
        self.client = client or httpx.AsyncClient(
            timeout=15, follow_redirects=False, trust_env=False,
        )

    async def close(self) -> None:
        if self._owned:
            await self.client.aclose()

    async def verify_employee(self, *, object_id: str) -> VerifiedEmployee:
        try:
            immutable_id = str(UUID(object_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise MicrosoftIdentityResolutionError("MICROSOFT_EMPLOYEE_OBJECT_ID_INVALID") from exc
        try:
            response = await self.client.get(
                f"https://graph.microsoft.com/v1.0/users/{immutable_id}",
                params={"$select": "id,userPrincipalName,accountEnabled,userType"},
                headers={"Authorization": self._authorization, "Accept": "application/json"},
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise MicrosoftIdentityResolutionError("MICROSOFT_GRAPH_DIRECTORY_UNAVAILABLE") from exc
        if response.status_code in (401, 403):
            raise MicrosoftIdentityResolutionError("MICROSOFT_GRAPH_USER_READ_PERMISSION_REQUIRED")
        if response.status_code != 200:
            raise MicrosoftIdentityResolutionError("MICROSOFT_GRAPH_DIRECTORY_UNAVAILABLE")
        try:
            record = response.json()
            if not isinstance(record, dict):
                raise ValueError("unexpected response")
            identity = str(UUID(record["id"]))
            upn = record["userPrincipalName"]
            if (identity != immutable_id or record.get("accountEnabled") is not True
                    or record.get("userType") != "Member"
                    or not isinstance(upn, str)
                    or len(upn) > 255
                    or not re.fullmatch(r"[a-zA-Z0-9._%+'-]+@[a-zA-Z0-9.-]+", upn)
                    or "#EXT#" in upn.upper()):
                raise ValueError("not a matching active member")
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise MicrosoftIdentityResolutionError("MICROSOFT_EMPLOYEE_IDENTITY_UNVERIFIED") from exc
        return VerifiedEmployee(
            tenant_id=self.tenant_id, object_id=immutable_id,
            user_principal_name=upn.casefold(),
            sharepoint_login_name="i:0#.f|membership|" + upn.casefold(),
        )
