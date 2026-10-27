from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource


class ConnectorError(RuntimeError):
    code = "connector_error"


class AuthenticationError(ConnectorError):
    code = "authentication_failed"


class AuthorizationError(ConnectorError):
    code = "insufficient_scope"


class RateLimitError(ConnectorError):
    code = "rate_limited"


class ProviderUnavailableError(ConnectorError):
    code = "provider_unavailable"


class UnsafeBoundaryError(ConnectorError):
    code = "unsafe_test_boundary"


class UnsupportedCapabilityError(ConnectorError):
    code = "unsupported_capability"


@dataclass(slots=True)
class CapabilityReport:
    capabilities: dict[Capability, CapabilityStatus]
    details: dict[str, str] = field(default_factory=dict)

    def supports(self, capability: Capability) -> bool:
        return self.capabilities.get(capability) is CapabilityStatus.SUPPORTED


@dataclass(slots=True)
class ConnectionIdentity:
    provider: str
    tenant: str | None
    account: str | None
    boundary: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SourceAdapter(ABC):
    provider: str

    @abstractmethod
    async def validate_connection(self) -> ConnectionIdentity: ...

    @abstractmethod
    async def discover_capabilities(self) -> CapabilityReport: ...

    @abstractmethod
    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource: ...

    @abstractmethod
    async def delete_resource(self, resource: SourceResource) -> None: ...

    @abstractmethod
    async def grant_access(self, resource: SourceResource, principal: Principal) -> str: ...

    @abstractmethod
    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None: ...

    @abstractmethod
    async def verify_user_can_access(
        self, resource: SourceResource, principal: Principal
    ) -> bool: ...

    async def get_effective_access(self, resource: SourceResource, principal: Principal) -> bool:
        return await self.verify_user_can_access(resource, principal)

    def get_last_provider_request_id(self) -> str | None:
        """Return the most recent provider correlation/request ID, when exposed.

        This is evidence metadata only. Callers must not infer provider success solely
        from the presence of a request ID.
        """
        return getattr(self, "_last_provider_request_id", None)

    async def create_group(self, *, name: str) -> str:
        raise UnsupportedCapabilityError("Group creation is not supported by this adapter")

    async def add_group_member(self, group_id: str, principal: Principal) -> None:
        raise UnsupportedCapabilityError("Group membership add is not supported by this adapter")

    async def remove_group_member(self, group_id: str, principal: Principal) -> None:
        raise UnsupportedCapabilityError(
            "Group membership removal is not supported by this adapter"
        )

    async def grant_group_access(self, resource: SourceResource, group_id: str) -> None:
        raise UnsupportedCapabilityError(
            "Group-mediated resource access is not supported by this adapter"
        )

    async def create_share_link(
        self, resource: SourceResource, principal: Principal | None = None
    ) -> str:
        raise UnsupportedCapabilityError("Share-link creation is not supported by this adapter")

    async def revoke_share_link(self, resource: SourceResource, link_id: str) -> None:
        raise UnsupportedCapabilityError("Share-link revocation is not supported by this adapter")

    async def grant_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        raise UnsupportedCapabilityError("Parent ACL setup is not supported by this adapter")

    async def revoke_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        raise UnsupportedCapabilityError("Parent ACL mutation is not supported by this adapter")

    async def move_resource(self, resource: SourceResource) -> None:
        raise UnsupportedCapabilityError("Resource move is not supported by this adapter")

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        """Rehydrate durable AccessProof ownership after runner/worker restart.

        Adapters with destructive cleanup MUST override this and validate the configured
        test boundary before accepting a provider resource ID.
        """
        raise UnsafeBoundaryError("Adapter does not support durable resource adoption")

    async def cleanup(self) -> None:
        return None
