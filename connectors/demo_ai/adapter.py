"""Adapter for the isolated AccessProof external-AI demonstration service.

This is deliberately limited to synthetic documents created through this
adapter.  It is a test harness, not a production document repository.
"""
from __future__ import annotations

from typing import Any

import httpx

from packages.connector_sdk.base import CapabilityReport, ConnectionIdentity, ProviderUnavailableError, SourceAdapter, UnsafeBoundaryError
from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource


class DemoAiSourceAdapter(SourceAdapter):
    provider = "demo-ai"

    def __init__(self, *, base_url: str, service_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.client = httpx.AsyncClient(timeout=20)
        self._created: set[str] = set()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.service_token}"} if self.service_token else {}

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = await self.client.request(method, f"{self.base_url}{path}", headers=self._headers(), **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"Demo AI service request failed: {type(exc).__name__}") from exc

    async def validate_connection(self) -> ConnectionIdentity:
        payload = await self._request("GET", "/health")
        if payload.get("status") != "ok":
            raise ProviderUnavailableError("Demo AI service is not healthy")
        return ConnectionIdentity(provider=self.provider, tenant="demo", account="accessproof", boundary=self.base_url)

    async def discover_capabilities(self) -> CapabilityReport:
        supported = {Capability.RESOURCE_CREATE, Capability.RESOURCE_DELETE, Capability.DIRECT_USER_GRANT, Capability.DIRECT_USER_REVOKE, Capability.EFFECTIVE_ACCESS_QUERY}
        return CapabilityReport({cap: CapabilityStatus.SUPPORTED if cap in supported else CapabilityStatus.UNSUPPORTED for cap in Capability})

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        payload = await self._request("POST", "/v1/documents", json={"name": name, "content": content, "marker": marker})
        resource = SourceResource(provider_id=str(payload["id"]), name=name, marker="accessproof-generated", canary=marker)
        self._created.add(resource.provider_id)
        return resource

    async def delete_resource(self, resource: SourceResource) -> None:
        if resource.provider_id not in self._created:
            raise UnsafeBoundaryError("Demo AI resource was not created by this run")
        await self._request("DELETE", f"/v1/documents/{resource.provider_id}")
        self._created.discard(resource.provider_id)

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        payload = await self._request("POST", f"/v1/documents/{resource.provider_id}/grants", json={"user_id": principal.external_id})
        return str(payload["grant_id"])

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        await self._request("DELETE", f"/v1/documents/{resource.provider_id}/grants/{principal.external_id}")

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        payload = await self._request("GET", f"/v1/documents/{resource.provider_id}/access", params={"user_id": principal.external_id})
        return bool(payload.get("allowed"))

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if resource.marker != "accessproof-generated":
            raise UnsafeBoundaryError("Demo AI tracked resource marker is invalid")
        self._created.add(resource.provider_id)
