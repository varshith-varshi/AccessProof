from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

from .permissions import EffectiveAccessResolver, PermissionGrant, PermissionSnapshot
from .policy import AccessDecision, AccessMode, AuthorizationPolicy, Guard


@dataclass(frozen=True)
class PermissionEvent:
    organization_id: str
    provider: str
    subject_id: str
    resource_id: str
    effect: str
    provider_revision: int
    dedupe_key: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class Resource:
    source_id: str
    resource_id: str
    chunk_ids: tuple[str, ...] = ()


@dataclass
class FilterResult:
    decision_id: str
    decision: AccessDecision
    allowed: list[Resource]
    denied: list[Resource]
    unknown: list[Resource]
    policy_version: int
    reason: str


class GuardService:
    """Small, deterministic local control/data-plane service.

    Provider adapters submit normalized events. The service deduplicates and
    rejects stale revisions, then rebuilds the local policy snapshot. Requests
    are evaluated in one batch so chunks from one source resource share a
    single authorization result.
    """

    def __init__(self, organization_id: str, policy: AuthorizationPolicy):
        self.organization_id = organization_id
        self.policy = policy
        self._grants: dict[tuple[str, str], PermissionGrant] = {}
        self._revisions: dict[tuple[str, str], int] = {}
        self._events: dict[str, PermissionEvent] = {}
        self._lock = Lock()
        self.guard = Guard(EffectiveAccessResolver(PermissionSnapshot()), policy)

    @property
    def policy_version(self) -> int:
        return self.guard.policy.version

    def ingest(self, event: PermissionEvent) -> bool:
        if event.organization_id != self.organization_id:
            raise ValueError("wrong tenant")
        key = (event.subject_id, event.resource_id)
        with self._lock:
            if event.dedupe_key in self._events:
                return False
            if event.provider_revision < self._revisions.get(key, -1):
                return False
            self._events[event.dedupe_key] = event
            self._revisions[key] = event.provider_revision
            self._grants[key] = PermissionGrant(
                event.subject_id, event.resource_id, event.effect, event.provider, version=event.provider_revision
            )
            next_version = max(self.policy.version + 1, event.provider_revision)
            self.policy = replace(self.policy, version=next_version)
            self.guard.policy = self.policy
            self.guard.resolver.snapshot = PermissionSnapshot(list(self._grants.values()), next_version)
            return True

    def filter_resources(self, subject_id: str | None, application_id: str, resources: list[Resource]) -> FilterResult:
        # One check per unique source resource, then fan the result back to chunks.
        unique: dict[str, Resource] = {r.resource_id: r for r in resources}
        decision, ids = self.guard.authorize(subject_id=subject_id, application_id=application_id, resource_ids=list(unique))
        denied_ids = set(ids) if decision in (AccessDecision.BLOCK, AccessDecision.WOULD_BLOCK) else set()
        unknown = decision == AccessDecision.UNKNOWN
        denied = [r for r in unique.values() if r.resource_id in denied_ids]
        if unknown:
            return FilterResult(str(uuid4()), decision, [], [], list(unique.values()), self.policy.version, "identity_or_application_unknown")
        if self.policy.mode == AccessMode.SHADOW:
            return FilterResult(str(uuid4()), decision, list(unique.values()), denied, [], self.policy.version, "shadow_would_block")
        allowed = [r for r in unique.values() if r.resource_id not in denied_ids]
        return FilterResult(str(uuid4()), decision, allowed, denied, [], self.policy.version, "effective_access")

    def check_output(self, result: FilterResult, used_resource_ids: list[str]) -> AccessDecision:
        denied = {r.resource_id for r in result.denied}
        if denied.intersection(used_resource_ids):
            return AccessDecision.BLOCK if self.policy.mode == AccessMode.PROTECT else AccessDecision.WOULD_BLOCK
        return AccessDecision.ALLOW if self.policy.mode == AccessMode.PROTECT else AccessDecision.WOULD_ALLOW

    def event_count(self) -> int:
        return len(self._events)
