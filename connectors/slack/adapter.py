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


class SlackAdapter(SourceAdapter):
    provider = "slack"
    API = "https://slack.com/api"

    def __init__(self, *, token: str, test_channel_id: str):
        if not test_channel_id:
            raise UnsafeBoundaryError("Explicit authorized test_channel_id is required")
        self.channel = test_channel_id
        self._client = httpx.AsyncClient(timeout=30, headers={"Authorization": f"Bearer {token}"})
        self._messages: set[str] = set()

    async def _call(self, method: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self._client.post(f"{self.API}/{method}", json=payload or {})
        self._last_provider_request_id = r.headers.get("x-slack-req-id") or r.headers.get(
            "x-request-id"
        )
        normalize_http_error(r)
        data = r.json()
        if not isinstance(data, dict):
            raise ValueError("Slack returned a non-object response")
        if not data.get("ok"):
            err = data.get("error", "unknown_error")
            if err in {
                "missing_scope",
                "no_permission",
                "not_allowed_token_type",
                "restricted_action",
            }:
                from packages.connector_sdk.base import AuthorizationError

                raise AuthorizationError(err)
            raise RuntimeError(f"Slack API error: {err}")
        return data

    async def validate_connection(self) -> ConnectionIdentity:
        auth = await self._call("auth.test")
        info = await self._call(
            "conversations.info", {"channel": self.channel, "include_num_members": True}
        )
        channel = info["channel"]
        if not channel.get("is_private"):
            raise UnsafeBoundaryError(
                "Slack permission regression tests require an authorized private test channel"
            )
        return ConnectionIdentity(
            provider=self.provider,
            tenant=auth.get("team_id"),
            account=auth.get("user_id"),
            boundary=self.channel,
            metadata={"channel_name": channel.get("name")},
        )

    async def discover_capabilities(self) -> CapabilityReport:
        supported = {
            Capability.RESOURCE_CREATE,
            Capability.RESOURCE_DELETE,
            Capability.PRIVATE_CONTAINER_MEMBER_REMOVE,
            Capability.PRIVATE_CONTAINER_MEMBER_ADD,
        }
        return CapabilityReport(
            {
                cap: (
                    CapabilityStatus.SUPPORTED
                    if cap in supported
                    else CapabilityStatus.UNAVAILABLE_DUE_TO_PROVIDER
                )
                for cap in Capability
            }
        )

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        data = await self._call(
            "chat.postMessage", {"channel": self.channel, "text": f"{name}\n{content}\n{marker}"}
        )
        ts = data["ts"]
        self._messages.add(ts)
        return SourceResource(
            provider_id=ts,
            name=name,
            marker="accessproof-generated",
            canary=marker,
            metadata={"channel_id": self.channel},
        )

    def _ensure_owned(self, resource: SourceResource) -> None:
        if resource.provider_id not in self._messages:
            raise UnsafeBoundaryError("Refusing mutation of untracked Slack message")

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if (
            resource.marker != "accessproof-generated"
            or resource.metadata.get("channel_id") != self.channel
        ):
            raise UnsafeBoundaryError(
                "Tracked Slack message does not match the authorized test channel"
            )
        self._messages.add(resource.provider_id)

    async def delete_resource(self, resource: SourceResource) -> None:
        self._ensure_owned(resource)
        await self._call("chat.delete", {"channel": self.channel, "ts": resource.provider_id})
        self._messages.discard(resource.provider_id)

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        self._ensure_owned(resource)
        await self._call(
            "conversations.invite", {"channel": self.channel, "users": principal.external_id}
        )
        return principal.external_id

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        self._ensure_owned(resource)
        await self._call(
            "conversations.kick", {"channel": self.channel, "user": principal.external_id}
        )

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        # users.conversations can only see private membership where the caller has relevant visibility.
        r = await self._client.get(
            f"{self.API}/users.conversations",
            params={"user": principal.external_id, "types": "private_channel", "limit": 200},
        )
        self._last_provider_request_id = r.headers.get("x-slack-req-id") or r.headers.get(
            "x-request-id"
        )
        normalize_http_error(r)
        data = r.json()
        if not isinstance(data, dict):
            raise ValueError("Slack returned a non-object response")
        if not data.get("ok"):
            raise RuntimeError(f"Slack API error: {data.get('error')}")
        return any(c.get("id") == self.channel for c in data.get("channels", []))
