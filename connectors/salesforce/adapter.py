from __future__ import annotations
from typing import Any

import httpx
import re
from packages.connector_sdk.base import (
    CapabilityReport,
    ConnectionIdentity,
    SourceAdapter,
    UnsafeBoundaryError,
)
from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource
from connectors.http_utils import normalize_http_error


class SalesforceAdapter(SourceAdapter):
    provider = "salesforce"

    def __init__(
        self,
        *,
        instance_url: str,
        access_token: str,
        api_version: str = "v65.0",
        test_object: str = "AccessProof_Test__c",
        share_object: str | None = None,
        share_parent_field: str = "ParentId",
        share_principal_field: str = "UserOrGroupId",
        share_access_field: str = "AccessLevel",
        share_access_value: str = "Read",
        share_row_cause_field: str | None = "RowCause",
        share_row_cause_value: str | None = "Manual",
    ):
        if not instance_url.startswith("https://") or not test_object:
            raise UnsafeBoundaryError(
                "Salesforce sandbox instance and explicit test object are required"
            )
        self.instance = instance_url.rstrip("/")
        self.api_version = api_version
        self.test_object = self._identifier(test_object, "test_object")
        self.share_object = self._identifier(share_object, "share_object") if share_object else None
        self.share_parent_field = self._identifier(share_parent_field, "share_parent_field")
        self.share_principal_field = self._identifier(
            share_principal_field, "share_principal_field"
        )
        self.share_access_field = self._identifier(share_access_field, "share_access_field")
        self.share_access_value = share_access_value
        self.share_row_cause_field = (
            self._identifier(share_row_cause_field, "share_row_cause_field")
            if share_row_cause_field
            else None
        )
        self.share_row_cause_value = share_row_cause_value
        self._client = httpx.AsyncClient(
            timeout=30,
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        )
        self._created: set[str] = set()
        self._created_shares: set[str] = set()

    @staticmethod
    def _identifier(value: str, label: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", value):
            raise UnsafeBoundaryError(f"Invalid Salesforce {label}")
        return value

    @staticmethod
    def _record_id(value: str, label: str = "record ID") -> str:
        if not re.fullmatch(r"[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?", value):
            raise UnsafeBoundaryError(f"Invalid Salesforce {label}")
        return value

    def _url(self, path: str) -> str:
        return f"{self.instance}/services/data/{self.api_version}{path}"

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        r = await self._client.request(method, self._url(path), **kwargs)
        self._last_provider_request_id = r.headers.get("x-request-id") or r.headers.get(
            "request-id"
        )
        normalize_http_error(r)
        return r

    async def validate_connection(self) -> ConnectionIdentity:
        r = await self._request("GET", "/limits")
        return ConnectionIdentity(
            provider=self.provider,
            tenant=self.instance,
            account=None,
            boundary=self.test_object,
            metadata={"limits_visible": bool(r.json())},
        )

    async def discover_capabilities(self) -> CapabilityReport:
        supported = {
            Capability.RESOURCE_CREATE,
            Capability.RESOURCE_DELETE,
            Capability.EFFECTIVE_ACCESS_QUERY,
        }
        if self.share_object:
            supported.update({Capability.DIRECT_USER_GRANT, Capability.DIRECT_USER_REVOKE})
        capabilities = {
            cap: (CapabilityStatus.SUPPORTED if cap in supported else CapabilityStatus.UNSUPPORTED)
            for cap in Capability
        }
        if not self.share_object:
            capabilities[Capability.DIRECT_USER_GRANT] = CapabilityStatus.EXPERIMENTAL
            capabilities[Capability.DIRECT_USER_REVOKE] = CapabilityStatus.EXPERIMENTAL
        return CapabilityReport(
            capabilities,
            details={
                "sharing": "Direct record sharing is enabled only when a customer-authorized share object and field mapping are configured.",
                "share_object": self.share_object or "",
            },
        )

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        payload = {"Name": name, "Canary__c": marker, "Body__c": content}
        r = await self._request("POST", f"/sobjects/{self.test_object}/", json=payload)
        data = r.json()
        rid = self._record_id(str(data["id"]))
        self._created.add(rid)
        return SourceResource(
            provider_id=rid,
            name=name,
            marker="accessproof-generated",
            canary=marker,
            metadata={"test_object": self.test_object, "salesforce_share_ids": {}},
        )

    def _ensure_owned(self, resource: SourceResource) -> None:
        if resource.provider_id not in self._created:
            raise UnsafeBoundaryError("Refusing mutation of untracked Salesforce record")

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if (
            resource.marker != "accessproof-generated"
            or resource.metadata.get("test_object") != self.test_object
        ):
            raise UnsafeBoundaryError(
                "Tracked Salesforce record does not match the authorized test object"
            )
        self._record_id(resource.provider_id)
        self._created.add(resource.provider_id)
        for share_id in (resource.metadata.get("salesforce_share_ids") or {}).values():
            self._created_shares.add(self._record_id(str(share_id), "share record ID"))

    async def delete_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        if self.share_object:
            for share_id in list((resource.metadata.get("salesforce_share_ids") or {}).values()):
                if share_id in self._created_shares:
                    await self._request("DELETE", f"/sobjects/{self.share_object}/{share_id}")
                    self._created_shares.discard(share_id)
            resource.metadata["salesforce_share_ids"] = {}
        await self._request("DELETE", f"/sobjects/{self.test_object}/{resource.provider_id}")
        self._created.discard(resource.provider_id)

    def _ensure_share_mode(self) -> str:
        if not self.share_object:
            raise UnsafeBoundaryError(
                "Salesforce direct sharing is not configured for this sandbox connection"
            )
        return self.share_object

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        self._ensure_owned(resource)
        share_object = self._ensure_share_mode()
        principal_id = self._record_id(principal.external_id, "principal ID")
        payload = {
            self.share_parent_field: resource.provider_id,
            self.share_principal_field: principal_id,
            self.share_access_field: self.share_access_value,
        }
        if self.share_row_cause_field and self.share_row_cause_value:
            payload[self.share_row_cause_field] = self.share_row_cause_value
        r = await self._request("POST", f"/sobjects/{share_object}/", json=payload)
        share_id = self._record_id(str(r.json()["id"]), "share record ID")
        self._created_shares.add(share_id)
        resource.metadata.setdefault("salesforce_share_ids", {})[principal_id] = share_id
        return share_id

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        share_object = self._ensure_share_mode()
        principal_id = self._record_id(principal.external_id, "principal ID")
        share_id = (resource.metadata.get("salesforce_share_ids") or {}).get(principal_id)
        if not share_id or share_id not in self._created_shares:
            raise UnsafeBoundaryError("Refusing to revoke an untracked Salesforce share record")
        await self._request("DELETE", f"/sobjects/{share_object}/{share_id}")
        self._created_shares.discard(share_id)
        resource.metadata.setdefault("salesforce_share_ids", {}).pop(principal_id, None)

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        user_id = self._record_id(principal.external_id, "principal ID")
        record_id = self._record_id(resource.provider_id)
        soql = f"SELECT RecordId,HasReadAccess FROM UserRecordAccess WHERE UserId='{user_id}' AND RecordId='{record_id}'"
        r = await self._request("GET", "/query", params={"q": soql})
        records = r.json().get("records", [])
        return bool(records and records[0].get("HasReadAccess"))
