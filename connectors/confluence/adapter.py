from __future__ import annotations
from typing import Any

import httpx
from packages.connector_sdk.base import (
    CapabilityReport,
    ConnectionIdentity,
    SourceAdapter,
    UnsafeBoundaryError,
)
from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource
from connectors.http_utils import normalize_http_error


class ConfluenceAdapter(SourceAdapter):
    provider = "confluence"

    def __init__(
        self,
        *,
        base_url: str,
        access_token: str,
        test_space_key: str,
        enable_restriction_tests: bool = False,
        restriction_guard_account_id: str | None = None,
    ):
        if not base_url.startswith("https://") or not test_space_key:
            raise UnsafeBoundaryError(
                "Confluence Cloud base URL and explicit test_space_key are required"
            )
        if enable_restriction_tests and not restriction_guard_account_id:
            raise UnsafeBoundaryError(
                "Confluence restriction tests require a dedicated restriction_guard_account_id so revocation cannot remove the final read restriction"
            )
        self.base_url = base_url.rstrip("/")
        self.space = test_space_key
        self.enable_restriction_tests = enable_restriction_tests
        self.restriction_guard_account_id = restriction_guard_account_id
        self._client = httpx.AsyncClient(
            timeout=30,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        self._created: set[str] = set()
        self._restricted_users: dict[str, set[str]] = {}

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        r = await self._client.request(method, f"{self.base_url}{path}", **kwargs)
        self._last_provider_request_id = (
            r.headers.get("x-arequestid")
            or r.headers.get("x-request-id")
            or r.headers.get("request-id")
        )
        normalize_http_error(r)
        return r

    async def validate_connection(self) -> ConnectionIdentity:
        r = await self._request(
            "GET", "/wiki/rest/api/space", params={"spaceKey": self.space, "limit": 1}
        )
        results = r.json().get("results", [])
        if not results:
            raise UnsafeBoundaryError("Configured Confluence test space not found")
        space = results[0]
        return ConnectionIdentity(
            provider=self.provider,
            tenant=None,
            account=None,
            boundary=space.get("key", self.space),
            metadata={"name": space.get("name")},
        )

    async def discover_capabilities(self) -> CapabilityReport:
        supported = {Capability.RESOURCE_CREATE, Capability.RESOURCE_DELETE}
        if self.enable_restriction_tests and self.restriction_guard_account_id:
            supported.update(
                {
                    Capability.DIRECT_USER_GRANT,
                    Capability.DIRECT_USER_REVOKE,
                    Capability.EFFECTIVE_ACCESS_QUERY,
                }
            )
        capabilities = {
            cap: (
                CapabilityStatus.SUPPORTED if cap in supported else CapabilityStatus.NOT_IMPLEMENTED
            )
            for cap in Capability
        }
        if not self.enable_restriction_tests:
            # The implementation exists but must be explicitly enabled only for a dedicated
            # test space with the administrator scopes required by permission/check.
            for cap in (
                Capability.DIRECT_USER_GRANT,
                Capability.DIRECT_USER_REVOKE,
                Capability.EFFECTIVE_ACCESS_QUERY,
            ):
                capabilities[cap] = CapabilityStatus.EXPERIMENTAL
        return CapabilityReport(capabilities)

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        r = await self._request(
            "POST",
            "/wiki/rest/api/content",
            json={
                "type": "page",
                "title": name,
                "space": {"key": self.space},
                "body": {
                    "storage": {
                        "value": f"<p>{content}</p><p>{marker}</p>",
                        "representation": "storage",
                    }
                },
            },
            headers={"Content-Type": "application/json"},
        )
        data = r.json()
        self._created.add(str(data["id"]))
        return SourceResource(
            provider_id=str(data["id"]),
            name=data.get("title", name),
            marker="accessproof-generated",
            canary=marker,
            metadata={"space_key": self.space},
        )

    def _ensure_owned(self, resource: SourceResource) -> None:
        if resource.provider_id not in self._created:
            raise UnsafeBoundaryError("Refusing mutation of untracked Confluence page")

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if (
            resource.marker != "accessproof-generated"
            or resource.metadata.get("space_key") != self.space
        ):
            raise UnsafeBoundaryError(
                "Tracked Confluence resource does not match the authorized test space"
            )
        self._created.add(resource.provider_id)

    async def delete_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        await self._request("DELETE", f"/wiki/rest/api/content/{resource.provider_id}")
        self._created.discard(resource.provider_id)
        self._restricted_users.pop(resource.provider_id, None)

    def _ensure_restriction_mode(self) -> str:
        if not self.enable_restriction_tests or not self.restriction_guard_account_id:
            raise UnsafeBoundaryError(
                "Confluence restriction testing is not enabled for this connection"
            )
        return self.restriction_guard_account_id

    async def _add_read_restriction(self, resource: SourceResource, account_id: str) -> None:
        self._ensure_owned(resource)
        await self._request(
            "PUT",
            f"/wiki/rest/api/content/{resource.provider_id}/restriction/byOperation/read/user",
            params={"accountId": account_id},
            headers={"Content-Type": "application/json"},
        )
        self._restricted_users.setdefault(resource.provider_id, set()).add(account_id)

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        guard = self._ensure_restriction_mode()
        # Confluence pages become unrestricted when the final read restriction disappears.
        # Keep a dedicated AccessProof guard principal restricted alongside the tested user.
        await self._add_read_restriction(resource, guard)
        if principal.external_id == guard:
            raise UnsafeBoundaryError(
                "Test principal must differ from the Confluence restriction guard account"
            )
        await self._add_read_restriction(resource, principal.external_id)
        return principal.external_id

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        guard = self._ensure_restriction_mode()
        self._ensure_owned(resource)
        if principal.external_id == guard:
            raise UnsafeBoundaryError("Refusing to remove the Confluence restriction guard account")
        await self._request(
            "DELETE",
            f"/wiki/rest/api/content/{resource.provider_id}/restriction/byOperation/read/user",
            params={"accountId": principal.external_id},
        )
        self._restricted_users.setdefault(resource.provider_id, set()).discard(
            principal.external_id
        )

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        if self.enable_restriction_tests:
            # Atlassian's permission/check endpoint evaluates site permission, space permission,
            # and content restrictions together. It is therefore authoritative source ground truth
            # for the configured account, unlike reading a restriction record alone.
            r = await self._request(
                "POST",
                f"/wiki/rest/api/content/{resource.provider_id}/permission/check",
                json={
                    "subject": {"type": "user", "identifier": principal.external_id},
                    "operation": "read",
                },
                headers={"Content-Type": "application/json"},
            )
            return bool(r.json().get("hasPermission", False))

        # Safe read-only fallback for connections that have not enabled admin-level permission
        # checking. This is restriction-layer evidence only and is not advertised as EFFECTIVE_ACCESS_QUERY.
        r = await self._request(
            "GET", f"/wiki/rest/api/content/{resource.provider_id}/restriction/byOperation/read"
        )
        restrictions = r.json().get("restrictions", {})
        users = restrictions.get("user", {}).get("results", [])
        ids = {str(u.get("accountId")) for u in users}
        return principal.external_id in ids if ids else True
