from __future__ import annotations
from typing import Any

import httpx

from connectors.http_utils import bounded_idempotent_request, normalize_http_error
from packages.connector_sdk.base import (
    CapabilityReport,
    ConnectionIdentity,
    SourceAdapter,
    UnsafeBoundaryError,
)
from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource


class Microsoft365Adapter(SourceAdapter):
    provider = "microsoft365"
    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(
        self,
        *,
        access_token: str,
        drive_id: str,
        test_root_item_id: str,
        tenant_hint: str | None = None,
        test_group_id: str | None = None,
        test_group_email: str | None = None,
        advanced_directory_mode: bool = False,
        enable_share_link_tests: bool = False,
        move_target_parent_item_id: str | None = None,
        enable_parent_acl_tests: bool = False,
    ):
        if not drive_id or not test_root_item_id:
            raise UnsafeBoundaryError("Explicit drive_id and test_root_item_id are required")
        self.token = access_token
        self.drive_id = drive_id
        self.test_root_item_id = test_root_item_id
        self.tenant_hint = tenant_hint
        self.test_group_id = test_group_id
        self.test_group_email = test_group_email
        self.advanced_directory_mode = advanced_directory_mode
        self.enable_share_link_tests = enable_share_link_tests
        self.move_target_parent_item_id = move_target_parent_item_id
        self.enable_parent_acl_tests = enable_parent_acl_tests
        self._client = httpx.AsyncClient(
            timeout=30, headers={"Authorization": f"Bearer {access_token}"}
        )
        self._created: set[str] = set()
        self._permissions: dict[tuple[str, str], str] = {}
        self._group_permissions: dict[tuple[str, str], str] = {}
        self._share_links: dict[tuple[str, str], str] = {}
        self._parent_permissions: dict[str, tuple[str, str]] = {}
        self._added_group_members: set[tuple[str, str]] = set()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        async def send() -> httpx.Response:
            return await self._client.request(method, f"{self.GRAPH}{path}", **kwargs)

        if method.upper() in {"GET", "HEAD"}:
            return await bounded_idempotent_request(send, max_attempts=3)
        response = await send()
        self._last_provider_request_id = (
            response.headers.get("request-id")
            or response.headers.get("client-request-id")
            or response.headers.get("x-ms-request-id")
        )
        normalize_http_error(response)
        return response

    async def validate_connection(self) -> ConnectionIdentity:
        r = await self._request(
            "GET",
            f"/drives/{self.drive_id}/items/{self.test_root_item_id}?$select=id,name,parentReference",
        )
        item = r.json()
        metadata = {
            "name": item.get("name"),
            "advanced_directory_mode": self.advanced_directory_mode,
        }
        if self.advanced_directory_mode and self.test_group_id:
            metadata["test_group_id"] = self.test_group_id
        return ConnectionIdentity(
            provider=self.provider,
            tenant=self.tenant_hint,
            account=None,
            boundary=item["id"],
            metadata=metadata,
        )

    async def discover_capabilities(self) -> CapabilityReport:
        statuses = {cap: CapabilityStatus.NOT_IMPLEMENTED for cap in Capability}
        for cap in {
            Capability.RESOURCE_CREATE,
            Capability.RESOURCE_DELETE,
            Capability.DIRECT_USER_GRANT,
            Capability.DIRECT_USER_REVOKE,
            Capability.EFFECTIVE_ACCESS_QUERY,
        }:
            statuses[cap] = CapabilityStatus.SUPPORTED

        # AccessProof never creates arbitrary Entra groups. Advanced directory mode
        # uses an explicitly pre-provisioned dedicated test group supplied by the customer.
        if self.advanced_directory_mode and self.test_group_id and self.test_group_email:
            statuses[Capability.GROUP_CREATE] = CapabilityStatus.SUPPORTED
            statuses[Capability.GROUP_MEMBER_ADD] = CapabilityStatus.SUPPORTED
            statuses[Capability.GROUP_MEMBER_REMOVE] = CapabilityStatus.SUPPORTED
        else:
            statuses[Capability.GROUP_CREATE] = CapabilityStatus.MISSING_SCOPE
            statuses[Capability.GROUP_MEMBER_ADD] = CapabilityStatus.MISSING_SCOPE
            statuses[Capability.GROUP_MEMBER_REMOVE] = CapabilityStatus.MISSING_SCOPE

        # The Graph link API is implemented, but AccessProof only schedules it when the
        # customer explicitly enables the dedicated test-link mode. Identity semantics
        # vary by link scope and must not be silently assumed.
        if self.enable_share_link_tests:
            statuses[Capability.SHARE_LINK_CREATE] = CapabilityStatus.SUPPORTED
            statuses[Capability.SHARE_LINK_REVOKE] = CapabilityStatus.SUPPORTED
        else:
            statuses[Capability.SHARE_LINK_CREATE] = CapabilityStatus.NOT_IMPLEMENTED
            statuses[Capability.SHARE_LINK_REVOKE] = CapabilityStatus.NOT_IMPLEMENTED

        statuses[Capability.RESOURCE_MOVE] = (
            CapabilityStatus.SUPPORTED
            if self.move_target_parent_item_id
            else CapabilityStatus.NOT_IMPLEMENTED
        )
        statuses[Capability.PARENT_PERMISSION_MUTATION] = (
            CapabilityStatus.SUPPORTED
            if self.enable_parent_acl_tests
            else CapabilityStatus.NOT_IMPLEMENTED
        )

        return CapabilityReport(
            statuses,
            details={
                "group_mode": "pre-provisioned test group"
                if self.test_group_id
                else "not configured",
                "share_link_mode": "explicitly enabled"
                if self.enable_share_link_tests
                else "experimental/disabled",
                "parent_acl_mode": "explicit dedicated test-root mutation"
                if self.enable_parent_acl_tests
                else "disabled",
            },
        )

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        safe_name = name.replace("/", "_")
        path = f"/drives/{self.drive_id}/items/{self.test_root_item_id}:/{safe_name}.txt:/content"
        r = await self._request(
            "PUT", path, content=content.encode(), headers={"Content-Type": "text/plain"}
        )
        item = r.json()
        self._created.add(item["id"])
        return SourceResource(
            provider_id=item["id"],
            name=item.get("name", safe_name),
            marker="accessproof-generated",
            canary=marker,
            metadata={"drive_id": self.drive_id, "test_root_item_id": self.test_root_item_id},
        )

    def _ensure_owned(self, resource: SourceResource) -> None:
        if resource.provider_id not in self._created:
            raise UnsafeBoundaryError(
                "Refusing mutation of a resource not created by this adapter instance"
            )

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if (
            resource.marker != "accessproof-generated"
            or resource.metadata.get("drive_id") != self.drive_id
            or resource.metadata.get("test_root_item_id", self.test_root_item_id)
            != self.test_root_item_id
        ):
            raise UnsafeBoundaryError(
                "Tracked Microsoft resource does not match the authorized drive boundary"
            )
        self._created.add(resource.provider_id)
        parent_pid = resource.metadata.get("microsoft_parent_permission_id")
        parent_principal = resource.metadata.get("microsoft_parent_principal")
        if parent_pid and parent_principal:
            self._parent_permissions[resource.provider_id] = (
                str(parent_pid),
                str(parent_principal),
            )

    async def delete_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        await self._request("DELETE", f"/drives/{self.drive_id}/items/{resource.provider_id}")
        self._created.discard(resource.provider_id)

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        self._ensure_owned(resource)
        email = principal.email or principal.external_id
        r = await self._request(
            "POST",
            f"/drives/{self.drive_id}/items/{resource.provider_id}/invite",
            json={
                "recipients": [{"email": email}],
                "message": "AccessProof synthetic test",
                "requireSignIn": True,
                "sendInvitation": False,
                "roles": ["read"],
            },
        )
        permissions = r.json().get("value", [])
        if not permissions:
            raise RuntimeError("Microsoft Graph invite returned no permission")
        permission_id = permissions[0]["id"]
        if not isinstance(permission_id, str) or not permission_id:
            raise ValueError("Provider returned an invalid permission ID")
        self._permissions[(resource.provider_id, principal.external_id)] = permission_id
        return permission_id

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        permission_id = self._permissions.get((resource.provider_id, principal.external_id))
        if not permission_id:
            raise RuntimeError("No tracked direct permission for principal")
        await self._request(
            "DELETE",
            f"/drives/{self.drive_id}/items/{resource.provider_id}/permissions/{permission_id}",
        )
        self._permissions.pop((resource.provider_id, principal.external_id), None)

    async def create_group(self, *, name: str) -> str:
        if not (self.advanced_directory_mode and self.test_group_id and self.test_group_email):
            raise UnsafeBoundaryError(
                "Advanced directory test mode requires a pre-provisioned test_group_id and test_group_email"
            )
        # Intentionally do not create arbitrary directory groups. Return the explicitly
        # configured dedicated test group as the engine's normalized group resource.
        return self.test_group_id

    async def add_group_member(self, group_id: str, principal: Principal) -> None:
        if group_id != self.test_group_id:
            raise UnsafeBoundaryError(
                "Refusing to mutate a group outside the configured AccessProof test group"
            )
        if await self._is_member_of_test_group(principal, group_id):
            raise UnsafeBoundaryError(
                "Test principal is already a member of the configured test group"
            )
        await self._request(
            "POST",
            f"/groups/{group_id}/members/$ref",
            json={"@odata.id": f"{self.GRAPH}/directoryObjects/{principal.external_id}"},
        )
        self._added_group_members.add((group_id, principal.external_id))

    async def remove_group_member(self, group_id: str, principal: Principal) -> None:
        if group_id != self.test_group_id:
            raise UnsafeBoundaryError(
                "Refusing to mutate a group outside the configured AccessProof test group"
            )
        # The trailing /$ref is intentionally mandatory: without it, callers with
        # sufficiently powerful permissions could target the directory object itself.
        await self._request("DELETE", f"/groups/{group_id}/members/{principal.external_id}/$ref")
        self._added_group_members.discard((group_id, principal.external_id))

    async def grant_group_access(self, resource: SourceResource, group_id: str) -> None:
        self._ensure_owned(resource)
        if group_id != self.test_group_id or not self.test_group_email:
            raise UnsafeBoundaryError(
                "Group-mediated access requires the configured AccessProof test group"
            )
        r = await self._request(
            "POST",
            f"/drives/{self.drive_id}/items/{resource.provider_id}/invite",
            json={
                "recipients": [{"email": self.test_group_email}],
                "message": "AccessProof synthetic group test",
                "requireSignIn": True,
                "sendInvitation": False,
                "roles": ["read"],
            },
        )
        permissions = r.json().get("value", [])
        if not permissions:
            raise RuntimeError("Microsoft Graph group invite returned no permission")
        permission_id = permissions[0]["id"]
        if not isinstance(permission_id, str) or not permission_id:
            raise ValueError("Provider returned an invalid permission ID")
        self._group_permissions[(resource.provider_id, group_id)] = permission_id
        resource.metadata["microsoft_group_id"] = group_id
        resource.metadata["microsoft_group_permission_id"] = permission_id

    async def _is_member_of_test_group(self, principal: Principal, group_id: str) -> bool:
        # checkMemberGroups is transitive and provides authoritative directory membership
        # ground truth for the explicitly configured test group.
        r = await self._request(
            "POST",
            f"/directoryObjects/{principal.external_id}/checkMemberGroups",
            json={"groupIds": [group_id]},
        )
        return group_id in set(r.json().get("value", []))

    async def grant_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        if not self.enable_parent_acl_tests:
            raise UnsafeBoundaryError(
                "Microsoft parent ACL testing is disabled for this connection"
            )
        email = principal.email or principal.external_id
        r = await self._request(
            "POST",
            f"/drives/{self.drive_id}/items/{self.test_root_item_id}/invite",
            json={
                "recipients": [{"email": email}],
                "message": "AccessProof synthetic inherited-access test",
                "requireSignIn": True,
                "sendInvitation": False,
                "roles": ["read"],
            },
        )
        permissions = r.json().get("value", [])
        if not permissions:
            raise RuntimeError("Microsoft Graph parent invite returned no permission")
        permission_id = str(permissions[0]["id"])
        self._parent_permissions[resource.provider_id] = (permission_id, principal.external_id)
        resource.metadata["microsoft_parent_permission_id"] = permission_id
        resource.metadata["microsoft_parent_principal"] = principal.external_id

    async def revoke_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        tracked = self._parent_permissions.get(resource.provider_id)
        permission_id = (
            tracked[0] if tracked else resource.metadata.get("microsoft_parent_permission_id")
        )
        tracked_principal = (
            tracked[1] if tracked else resource.metadata.get("microsoft_parent_principal")
        )
        if not permission_id or tracked_principal != principal.external_id:
            raise UnsafeBoundaryError("No tracked AccessProof parent permission for this principal")
        await self._request(
            "DELETE",
            f"/drives/{self.drive_id}/items/{self.test_root_item_id}/permissions/{permission_id}",
        )
        self._parent_permissions.pop(resource.provider_id, None)
        resource.metadata["microsoft_parent_permission_revoked"] = True

    async def create_share_link(
        self, resource: SourceResource, principal: Principal | None = None
    ) -> str:
        self._ensure_owned(resource)
        if not self.enable_share_link_tests:
            raise UnsafeBoundaryError(
                "Share-link mutation is disabled unless explicitly enabled for the test connection"
            )
        r = await self._request(
            "POST",
            f"/drives/{self.drive_id}/items/{resource.provider_id}/createLink",
            json={"type": "view", "scope": "organization"},
        )
        permission_id = r.json().get("id")
        if not isinstance(permission_id, str) or not permission_id:
            raise RuntimeError("Microsoft Graph createLink returned no permission id")
        key = principal.external_id if principal else "organization"
        self._share_links[(resource.provider_id, key)] = permission_id
        resource.metadata["share_link_permission_id"] = permission_id
        return permission_id

    async def revoke_share_link(self, resource: SourceResource, link_id: str) -> None:
        self._ensure_owned(resource)
        if not self.enable_share_link_tests:
            raise UnsafeBoundaryError(
                "Share-link mutation is disabled unless explicitly enabled for the test connection"
            )
        await self._request(
            "DELETE", f"/drives/{self.drive_id}/items/{resource.provider_id}/permissions/{link_id}"
        )

    async def move_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        if not self.move_target_parent_item_id:
            raise UnsafeBoundaryError("No dedicated move_target_parent_item_id is configured")
        await self._request(
            "PATCH",
            f"/drives/{self.drive_id}/items/{resource.provider_id}",
            json={"parentReference": {"id": self.move_target_parent_item_id}},
        )
        resource.metadata["moved_to_parent_item_id"] = self.move_target_parent_item_id

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        # The mutation credential can prove that a permission object was changed, but it
        # cannot prove that the affected person has lost access.  When the runner has a
        # delegated Alice/Bob token, make the actual content request as that identity.
        # A Graph download redirect is also authorization success: Graph only issues the
        # pre-authenticated download URL after authorizing the driveItem request.
        if principal.access_token:
            async with httpx.AsyncClient(
                timeout=30,
                follow_redirects=False,
                headers={"Authorization": f"Bearer {principal.access_token}"},
            ) as delegated_client:
                response = await delegated_client.get(
                    f"{self.GRAPH}/drives/{self.drive_id}/items/{resource.provider_id}/content"
                )
            self._last_provider_request_id = (
                response.headers.get("request-id")
                or response.headers.get("client-request-id")
                or response.headers.get("x-ms-request-id")
            )
            if response.status_code in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
                return True
            # Microsoft Graph commonly returns either 403 or 404 after access is
            # removed, depending on the SharePoint/OneDrive sharing model.  Neither is
            # treated as a transient outage or as an administrator-side inference.
            if response.status_code in {401, 403, 404}:
                return False
            normalize_http_error(response)
            return False  # pragma: no cover - normalize_http_error always raises here

        # Direct permissions first. Inherited permissions are intentionally not flattened
        # into this list; advanced paths are represented explicitly.
        r = await self._request(
            "GET", f"/drives/{self.drive_id}/items/{resource.provider_id}/permissions"
        )
        email = (principal.email or principal.external_id).lower()
        for p in r.json().get("value", []):
            identities = list(p.get("grantedToIdentitiesV2") or [])
            if p.get("grantedToV2"):
                identities.append(p["grantedToV2"])
            for ident in identities:
                user = ident.get("user", {})
                if email in {
                    str(user.get("email", "")).lower(),
                    str(user.get("displayName", "")).lower(),
                }:
                    return True

        if (
            self.enable_parent_acl_tests
            and resource.metadata.get("microsoft_parent_principal") == principal.external_id
            and not resource.metadata.get("moved_to_parent_item_id")
        ):
            parent = await self._request(
                "GET", f"/drives/{self.drive_id}/items/{self.test_root_item_id}/permissions"
            )
            for permission in parent.json().get("value", []):
                identities = list(permission.get("grantedToIdentitiesV2") or [])
                if permission.get("grantedToV2"):
                    identities.append(permission["grantedToV2"])
                for ident in identities:
                    user = ident.get("user", {})
                    if email in {
                        str(user.get("email", "")).lower(),
                        str(user.get("displayName", "")).lower(),
                    }:
                        return True

        group_id = resource.metadata.get("microsoft_group_id")
        if group_id:
            # The resource was explicitly granted to the dedicated AccessProof test group;
            # effective user access is therefore determined by current directory membership.
            return await self._is_member_of_test_group(principal, str(group_id))
        return False

    async def cleanup(self) -> None:
        for resource_id, (permission_id, _principal) in list(self._parent_permissions.items()):
            try:
                await self._request(
                    "DELETE",
                    f"/drives/{self.drive_id}/items/{self.test_root_item_id}/permissions/{permission_id}",
                )
            finally:
                self._parent_permissions.pop(resource_id, None)
        for group_id, principal_id in list(self._added_group_members):
            try:
                await self._request("DELETE", f"/groups/{group_id}/members/{principal_id}/$ref")
            finally:
                self._added_group_members.discard((group_id, principal_id))
