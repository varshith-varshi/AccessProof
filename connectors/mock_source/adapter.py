from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import uuid4

from packages.connector_sdk.base import (
    CapabilityReport,
    ConnectionIdentity,
    ProviderUnavailableError,
    SourceAdapter,
)
from packages.domain.models import Capability, CapabilityStatus, Principal, SourceResource
from packages.test_engine.clock import Clock


@dataclass(slots=True)
class _MockResourceState:
    resource: SourceResource
    content: str
    granted: set[str] = field(default_factory=set)
    group_grants: set[str] = field(default_factory=set)
    parent_grants: set[str] = field(default_factory=set)
    share_link_grants: dict[str, str] = field(default_factory=dict)
    pending_revokes: dict[str, datetime] = field(default_factory=dict)
    moved_to_private: bool = False


class MockSourceAdapter(SourceAdapter):
    provider = "mock"

    def __init__(
        self,
        *,
        clock: Clock,
        source_mutation_delay_seconds: float = 0.0,
        provider_outage_after_mutation: bool = False,
        cleanup_failure: bool = False,
    ):
        self.clock = clock
        self.source_mutation_delay_seconds = source_mutation_delay_seconds
        self.provider_outage_after_mutation = provider_outage_after_mutation
        self.cleanup_failure = cleanup_failure
        self._mutation_seen = False
        self.resources: dict[str, _MockResourceState] = {}
        self.groups: dict[str, set[str]] = {}

    async def validate_connection(self) -> ConnectionIdentity:
        return ConnectionIdentity(
            provider=self.provider, tenant="local", account="simulator", boundary="mock-root"
        )

    async def discover_capabilities(self) -> CapabilityReport:
        return CapabilityReport({cap: CapabilityStatus.SUPPORTED for cap in Capability})

    async def create_resource(self, *, name: str, content: str, marker: str) -> SourceResource:
        rid = f"mock-{uuid4()}"
        resource = SourceResource(
            provider_id=rid, name=name, marker="accessproof-generated", canary=marker
        )
        self.resources[rid] = _MockResourceState(resource=resource, content=content)
        return resource

    async def delete_resource(self, resource: SourceResource) -> None:
        if self.cleanup_failure:
            raise ProviderUnavailableError("simulated cleanup outage")
        self.resources.pop(resource.provider_id, None)

    async def grant_access(self, resource: SourceResource, principal: Principal) -> str:
        state = self.resources[resource.provider_id]
        state.pending_revokes.pop(principal.external_id, None)
        state.granted.add(principal.external_id)
        return f"perm-{principal.external_id}"

    async def revoke_access(self, resource: SourceResource, principal: Principal) -> None:
        state = self.resources[resource.provider_id]
        self._mutation_seen = True
        effective_at = self.clock.now() + timedelta(seconds=self.source_mutation_delay_seconds)
        state.pending_revokes[principal.external_id] = effective_at

    async def create_group(self, *, name: str) -> str:
        gid = f"group-{uuid4()}"
        self.groups[gid] = set()
        return gid

    async def add_group_member(self, group_id: str, principal: Principal) -> None:
        self.groups[group_id].add(principal.external_id)

    async def remove_group_member(self, group_id: str, principal: Principal) -> None:
        self._mutation_seen = True
        self.groups[group_id].discard(principal.external_id)

    async def grant_group_access(self, resource: SourceResource, group_id: str) -> None:
        self.resources[resource.provider_id].group_grants.add(group_id)

    async def create_share_link(
        self, resource: SourceResource, principal: Principal | None = None
    ) -> str:
        link_id = f"link-{uuid4()}"
        principal_id = principal.external_id if principal else "*"
        self.resources[resource.provider_id].share_link_grants[link_id] = principal_id
        return link_id

    async def revoke_share_link(self, resource: SourceResource, link_id: str) -> None:
        self._mutation_seen = True
        self.resources[resource.provider_id].share_link_grants.pop(link_id, None)

    async def grant_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        self.resources[resource.provider_id].parent_grants.add(principal.external_id)

    async def revoke_parent_access(self, resource: SourceResource, principal: Principal) -> None:
        self._mutation_seen = True
        self.resources[resource.provider_id].parent_grants.discard(principal.external_id)

    async def move_resource(self, resource: SourceResource) -> None:
        self._mutation_seen = True
        state = self.resources[resource.provider_id]
        state.moved_to_private = True
        state.granted.clear()
        state.parent_grants.clear()
        state.group_grants.clear()
        state.share_link_grants.clear()

    def _apply_pending(self, state: _MockResourceState) -> None:
        now = self.clock.now()
        for principal_id, effective_at in list(state.pending_revokes.items()):
            if now >= effective_at:
                state.granted.discard(principal_id)
                del state.pending_revokes[principal_id]

    async def verify_user_can_access(self, resource: SourceResource, principal: Principal) -> bool:
        if self.provider_outage_after_mutation and self._mutation_seen:
            raise ProviderUnavailableError("simulated provider outage")
        state = self.resources.get(resource.provider_id)
        if state is None:
            return False
        self._apply_pending(state)
        if state.moved_to_private:
            return False
        if principal.external_id in state.granted or principal.external_id in state.parent_grants:
            return True
        if any(
            principal.external_id in self.groups.get(group_id, set())
            for group_id in state.group_grants
        ):
            return True
        if any(value in {"*", principal.external_id} for value in state.share_link_grants.values()):
            return True
        return False

    async def adopt_tracked_resource(self, resource: SourceResource) -> None:
        if resource.marker != "accessproof-generated":
            from packages.connector_sdk.base import UnsafeBoundaryError

            raise UnsafeBoundaryError("Mock tracked resource marker is invalid")

    async def cleanup(self) -> None:
        self.groups.clear()

    def get_content(self, resource_id: str) -> str:
        return self.resources[resource_id].content
