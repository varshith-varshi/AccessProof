from __future__ import annotations
from typing import Any, cast

import httpx
from packages.connector_sdk.base import (
    CapabilityReport,
    ConnectionIdentity,
    SourceAdapter,
    UnsafeBoundaryError,
)
from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource
from connectors.http_utils import normalize_http_error


class GoogleDriveAdapter(SourceAdapter):
    provider = "google-drive"
    API = "https://www.googleapis.com/drive/v3"
    UPLOAD = "https://www.googleapis.com/upload/drive/v3"
    FOLDER_MIME = "application/vnd.google-apps.folder"
    SHORTCUT_MIME = "application/vnd.google-apps.shortcut"

    def __init__(
        self,
        *,
        access_token: str,
        test_root_folder_id: str,
        enable_parent_acl_tests: bool = False,
        move_target_folder_id: str | None = None,
    ):
        if not test_root_folder_id:
            raise UnsafeBoundaryError("Explicit test_root_folder_id is required")
        self.token = access_token
        self.root = test_root_folder_id
        self.enable_parent_acl_tests = enable_parent_acl_tests
        self.move_target_folder_id = move_target_folder_id
        self._client = httpx.AsyncClient(
            timeout=30, headers={"Authorization": f"Bearer {access_token}"}
        )
        self._created: set[str] = set()
        self._permissions: dict[tuple[str, str], str] = {}
        self._parent_permissions: dict[str, tuple[str, str]] = {}

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        r = await self._client.request(method, url, **kwargs)
        self._last_provider_request_id = (
            r.headers.get("x-guploader-uploadid")
            or r.headers.get("x-request-id")
            or r.headers.get("request-id")
        )
        normalize_http_error(r)
        return r

    async def acl_change_page(self, page_token: str | None = None) -> dict[str, Any]:
        """Read one durable Drive Changes page; callers persist nextPageToken."""
        if page_token is None:
            response = await self._request("GET", f"{self.API}/changes/startPageToken", params={"supportsAllDrives": "true"})
            return {"startPageToken": response.json().get("startPageToken"), "changes": [], "nextPageToken": None}
        response = await self._request("GET", f"{self.API}/changes", params={
            "pageToken": page_token, "includeItemsFromAllDrives": "true", "supportsAllDrives": "true",
            "includeRemoved": "true", "fields": "nextPageToken,newStartPageToken,changes(fileId,removed,file(id,name,mimeType,parents,permissions(id,type,emailAddress,domain,role,permissionDetails)))",
        })
        return cast(dict[str, Any], response.json())

    async def permissions_snapshot(self, file_id: str) -> list[dict[str, Any]]:
        """Return ALL permission pages or fail the sync; never trust a partial ACL."""
        result: list[dict[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        while True:
            params = {
                "supportsAllDrives": "true", "pageSize": 100,
                "fields": "permissions(id,type,emailAddress,domain,role,expirationTime,deleted,permissionDetails,displayName),nextPageToken",
            }
            if token:
                params["pageToken"] = token
            response = await self._request("GET", f"{self.API}/files/{file_id}/permissions", params=params)
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("permissions", []), list):
                raise ValueError("DRIVE_PERMISSION_SNAPSHOT_INCOMPLETE")
            result.extend(payload.get("permissions") or [])
            next_token = payload.get("nextPageToken")
            if not next_token:
                return result
            if not isinstance(next_token, str) or next_token in seen:
                raise ValueError("DRIVE_PERMISSION_PAGINATION_INVALID")
            seen.add(next_token)
            token = next_token

    async def list_boundary_resources(self, *, max_items: int = 20000, root_id: str | None = None) -> list[dict[str, Any]]:
        """Inventory existing descendants of the explicitly approved root folder.

        StartPageToken is obtained *before* this scan by the caller, so
        concurrent changes will subsequently be replayed from that token.
        An incomplete traversal raises rather than marking the ACL state ready.
        """
        queue = [root_id or self.root]
        visited: set[str] = set()
        resources: list[dict[str, Any]] = []
        while queue:
            folder = queue.pop(0)
            if folder in visited:
                continue
            visited.add(folder)
            token: str | None = None
            seen_tokens: set[str] = set()
            while True:
                params = {
                    "q": f"'{folder.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}' in parents and trashed = false",
                    "fields": "nextPageToken,incompleteSearch,files(id,name,mimeType,parents,driveId,shortcutDetails,trashed)",
                    "pageSize": 1000, "supportsAllDrives": "true",
                    "includeItemsFromAllDrives": "true",
                }
                if token:
                    params["pageToken"] = token
                response = await self._request("GET", f"{self.API}/files", params=params)
                payload = response.json()
                if not isinstance(payload, dict) or payload.get("incompleteSearch") or not isinstance(payload.get("files", []), list):
                    raise ValueError("DRIVE_BOUNDARY_INVENTORY_INCOMPLETE")
                for item in payload.get("files") or []:
                    if not isinstance(item, dict) or not item.get("id"):
                        raise ValueError("DRIVE_BOUNDARY_INVENTORY_INCOMPLETE")
                    # A shortcut is not a permission boundary: its target may
                    # live outside this approved root and carry a different
                    # ACL. V1 rejects it rather than accidentally mapping the
                    # shortcut ACL to target content.
                    if item.get("mimeType") == self.SHORTCUT_MIME:
                        continue
                    resources.append(item)
                    if len(resources) > max_items:
                        raise ValueError("DRIVE_BOUNDARY_INVENTORY_LIMIT")
                    if item.get("mimeType") == self.FOLDER_MIME:
                        queue.append(str(item["id"]))
                token_next = payload.get("nextPageToken")
                if not token_next:
                    break
                if not isinstance(token_next, str) or token_next in seen_tokens:
                    raise ValueError("DRIVE_BOUNDARY_PAGINATION_INVALID")
                seen_tokens.add(token_next)
                token = token_next
        return resources

    async def is_inside_boundary(self, file_id: str, *, max_depth: int = 100) -> bool:
        """Check whether a changed resource is still under the approved root.

        Unrelated changes from the user-wide Drive feed are ignored.
        Errors propagate to a degraded sync; never assume in-scope on errors.
        """
        if file_id == self.root:
            return True
        current = [file_id]
        visited: set[str] = set()
        for _ in range(max_depth):
            if not current:
                return False
            next_ids: list[str] = []
            for candidate in current:
                if candidate == self.root:
                    return True
                if candidate in visited:
                    continue
                visited.add(candidate)
                response = await self._request(
                    "GET", f"{self.API}/files/{candidate}",
                    params={"fields": "id,parents,trashed", "supportsAllDrives": "true"},
                )
                info = response.json()
                if info.get("trashed"):
                    return False
                next_ids.extend(str(parent) for parent in info.get("parents") or [])
            current = next_ids
        raise ValueError("DRIVE_BOUNDARY_DEPTH_EXCEEDED")

    async def validate_connection(self) -> ConnectionIdentity:
        r = await self._request(
            "GET",
            f"{self.API}/files/{self.root}",
            params={"fields": "id,name,driveId,mimeType", "supportsAllDrives": "true"},
        )
        data = r.json()
        if data.get("mimeType") != self.FOLDER_MIME:
            raise UnsafeBoundaryError("Configured Google Drive test root must be a folder")
        metadata = {
            "name": data.get("name"),
            "drive_id": data.get("driveId"),
            "parent_acl_tests": self.enable_parent_acl_tests,
            "move_target_folder_id": self.move_target_folder_id,
        }
        if self.move_target_folder_id:
            target = await self._request(
                "GET",
                f"{self.API}/files/{self.move_target_folder_id}",
                params={"fields": "id,name,driveId,mimeType", "supportsAllDrives": "true"},
            )
            target_data = target.json()
            if target_data.get("mimeType") not in {None, "application/vnd.google-apps.folder"}:
                raise UnsafeBoundaryError("Configured Google Drive move target is not a folder")
            # Moving between unrelated shared drives changes ownership/permission semantics
            # and is outside this dedicated test-boundary scenario.
            if data.get("driveId") != target_data.get("driveId"):
                raise UnsafeBoundaryError(
                    "Move target must belong to the same Shared Drive as the test root"
                )
        return ConnectionIdentity(
            provider=self.provider,
            tenant=data.get("driveId"),
            account=None,
            boundary=data["id"],
            metadata=metadata,
        )

    async def discover_capabilities(self) -> CapabilityReport:
        statuses = {cap: CapabilityStatus.NOT_IMPLEMENTED for cap in Capability}
        for cap in {
            Capability.RESOURCE_CREATE,
            Capability.RESOURCE_DELETE,
            Capability.DIRECT_USER_GRANT,
            Capability.DIRECT_USER_REVOKE,
        }:
            statuses[cap] = CapabilityStatus.SUPPORTED
        if self.enable_parent_acl_tests:
            statuses[Capability.PARENT_PERMISSION_MUTATION] = CapabilityStatus.SUPPORTED
        if self.enable_parent_acl_tests and self.move_target_folder_id:
            statuses[Capability.RESOURCE_MOVE] = CapabilityStatus.SUPPORTED
        return CapabilityReport(
            statuses,
            details={
                "parent_acl_mode": "explicit dedicated test-root mutation"
                if self.enable_parent_acl_tests
                else "disabled",
                "move_mode": "explicit second authorized folder"
                if self.move_target_folder_id
                else "not configured",
                "effective_access": "direct/item or AccessProof-created parent permission evidence; service-account impersonation is not assumed",
            },
        )

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        boundary = "accessproof_boundary"
        metadata = {
            "name": f"{name}.txt",
            "parents": [self.root],
            "description": f"accessproof-generated {marker}",
        }
        body = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            f"{__import__('json').dumps(metadata)}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\n"
            f"{content}\r\n--{boundary}--"
        ).encode()
        r = await self._request(
            "POST",
            f"{self.UPLOAD}/files",
            params={
                "uploadType": "multipart",
                "supportsAllDrives": "true",
                "fields": "id,name,parents",
            },
            content=body,
            headers={"Content-Type": f"multipart/related; boundary={boundary}"},
        )
        data = r.json()
        self._created.add(data["id"])
        return SourceResource(
            provider_id=data["id"],
            name=data.get("name", name),
            marker="accessproof-generated",
            canary=marker,
            metadata={"test_root_folder_id": self.root},
        )

    def _ensure_owned(self, resource: SourceResource) -> None:
        if resource.provider_id not in self._created:
            raise UnsafeBoundaryError("Refusing mutation of untracked resource")

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if (
            resource.marker != "accessproof-generated"
            or resource.metadata.get("test_root_folder_id") != self.root
        ):
            raise UnsafeBoundaryError(
                "Tracked Google Drive resource does not match the authorized test folder"
            )
        moved_to = resource.metadata.get("moved_to_folder_id")
        if moved_to and moved_to != self.move_target_folder_id:
            raise UnsafeBoundaryError(
                "Tracked Google Drive resource moved outside the authorized move target"
            )
        self._created.add(resource.provider_id)
        pid = resource.metadata.get("google_parent_permission_id")
        principal = resource.metadata.get("google_parent_principal")
        if pid and principal:
            self._parent_permissions[resource.provider_id] = (str(pid), str(principal))

    async def delete_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        await self._request(
            "DELETE",
            f"{self.API}/files/{resource.provider_id}",
            params={"supportsAllDrives": "true"},
        )
        self._created.discard(resource.provider_id)

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        self._ensure_owned(resource)
        r = await self._request(
            "POST",
            f"{self.API}/files/{resource.provider_id}/permissions",
            params={"supportsAllDrives": "true", "sendNotificationEmail": "false", "fields": "id"},
            json={
                "type": "user",
                "role": "reader",
                "emailAddress": principal.email or principal.external_id,
            },
        )
        pid = r.json()["id"]
        if not isinstance(pid, str) or not pid:
            raise ValueError("Provider returned an invalid permission ID")
        self._permissions[(resource.provider_id, principal.external_id)] = pid
        return pid

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        pid = self._permissions.get((resource.provider_id, principal.external_id))
        if not pid:
            raise RuntimeError("No tracked permission")
        await self._request(
            "DELETE",
            f"{self.API}/files/{resource.provider_id}/permissions/{pid}",
            params={"supportsAllDrives": "true"},
        )
        self._permissions.pop((resource.provider_id, principal.external_id), None)

    async def grant_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        if not self.enable_parent_acl_tests:
            raise UnsafeBoundaryError(
                "Google Drive parent ACL testing is disabled for this connection"
            )
        r = await self._request(
            "POST",
            f"{self.API}/files/{self.root}/permissions",
            params={"supportsAllDrives": "true", "sendNotificationEmail": "false", "fields": "id"},
            json={
                "type": "user",
                "role": "reader",
                "emailAddress": principal.email or principal.external_id,
            },
        )
        pid = str(r.json()["id"])
        self._parent_permissions[resource.provider_id] = (pid, principal.external_id)
        resource.metadata["google_parent_permission_id"] = pid
        resource.metadata["google_parent_principal"] = principal.external_id

    async def revoke_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        tracked = self._parent_permissions.get(resource.provider_id)
        pid = tracked[0] if tracked else resource.metadata.get("google_parent_permission_id")
        tracked_principal = (
            tracked[1] if tracked else resource.metadata.get("google_parent_principal")
        )
        if not pid or tracked_principal != principal.external_id:
            raise UnsafeBoundaryError("No tracked AccessProof parent permission for this principal")
        await self._request(
            "DELETE",
            f"{self.API}/files/{self.root}/permissions/{pid}",
            params={"supportsAllDrives": "true"},
        )
        self._parent_permissions.pop(resource.provider_id, None)
        resource.metadata["google_parent_permission_revoked"] = True

    async def move_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        if not (self.enable_parent_acl_tests and self.move_target_folder_id):
            raise UnsafeBoundaryError(
                "Google Drive move testing requires an explicit authorized move_target_folder_id and parent ACL mode"
            )
        current = await self._request(
            "GET",
            f"{self.API}/files/{resource.provider_id}",
            params={"fields": "id,parents", "supportsAllDrives": "true"},
        )
        parents = [str(x) for x in current.json().get("parents", [])]
        if self.root not in parents:
            raise UnsafeBoundaryError(
                "Synthetic resource is no longer under the configured test root before move"
            )
        await self._request(
            "PATCH",
            f"{self.API}/files/{resource.provider_id}",
            params={
                "addParents": self.move_target_folder_id,
                "removeParents": self.root,
                "supportsAllDrives": "true",
                "fields": "id,parents",
            },
        )
        resource.metadata["moved_to_folder_id"] = self.move_target_folder_id

    async def _permission_email_present(self, file_id: str, email: str) -> bool:
        r = await self._request(
            "GET",
            f"{self.API}/files/{file_id}/permissions",
            params={
                "supportsAllDrives": "true",
                "fields": "permissions(id,emailAddress,type,role,permissionDetails)",
            },
        )
        return any(
            (p.get("emailAddress") or "").lower() == email.lower()
            for p in r.json().get("permissions", [])
        )

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        email = principal.email or principal.external_id
        # Explicit item permission evidence.
        if await self._permission_email_present(resource.provider_id, email):
            return True
        # For AccessProof's opt-in parent scenario, inspect the exact parent permission
        # that AccessProof created. Once the file is moved away from that parent, this
        # parent path no longer establishes access.
        if self.enable_parent_acl_tests and not resource.metadata.get("moved_to_folder_id"):
            tracked_principal = resource.metadata.get("google_parent_principal")
            if tracked_principal == principal.external_id:
                return await self._permission_email_present(self.root, email)
        return False

    async def cleanup(self) -> None:
        # Best effort cleanup of AccessProof-created root permissions if a scenario aborts
        # between grant and revocation. Exact permission IDs are used; names are never used.
        for resource_id, (pid, _principal) in list(self._parent_permissions.items()):
            try:
                await self._request(
                    "DELETE",
                    f"{self.API}/files/{self.root}/permissions/{pid}",
                    params={"supportsAllDrives": "true"},
                )
            finally:
                self._parent_permissions.pop(resource_id, None)
