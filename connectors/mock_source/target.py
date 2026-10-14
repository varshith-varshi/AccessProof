from __future__ import annotations
from datetime import datetime

from packages.connector_sdk.target import AITargetAdapter, TargetObservation
from packages.domain.models import Principal, SourceResource
from packages.test_engine.clock import Clock
from connectors.mock_source.adapter import MockSourceAdapter


class MockRagTarget(AITargetAdapter):
    def __init__(
        self,
        *,
        source: MockSourceAdapter,
        clock: Clock,
        stale_acl_seconds: float = 0.0,
        outage_after_revoke: bool = False,
        force_negative_leak: bool = False,
        positive_never_ingests: bool = False,
    ):
        self.source = source
        self.clock = clock
        self.stale_acl_seconds = stale_acl_seconds
        self.outage_after_revoke = outage_after_revoke
        self.force_negative_leak = force_negative_leak
        self.positive_never_ingests = positive_never_ingests
        self._last_source_allowed: dict[tuple[str, str], bool] = {}
        self._revoked_at: dict[tuple[str, str], datetime] = {}
        self._indexed_resource: SourceResource | None = None
        self._indexed_content: str | None = None

    async def validate_connection(self) -> None:
        return None

    async def probe(self, *, principal: Principal, prompt: str) -> TargetObservation:
        if self.source.resources:
            state = next(iter(self.source.resources.values()))
            resource = state.resource
            self._indexed_resource = resource
            self._indexed_content = state.content
            source_allowed = await self.source.verify_user_can_access(resource, principal)
        elif self._indexed_resource is not None:
            # A deleted source document may remain in an AI index/cache temporarily.
            resource = self._indexed_resource
            source_allowed = False
        else:
            return TargetObservation(available=True, answer="No indexed content")

        key = (resource.provider_id, principal.external_id)
        previous_allowed = self._last_source_allowed.get(key)
        if previous_allowed is True and source_allowed is False and key not in self._revoked_at:
            self._revoked_at[key] = self.clock.now()
        if source_allowed:
            self._revoked_at.pop(key, None)
        self._last_source_allowed[key] = source_allowed
        if not source_allowed and key in self._revoked_at:
            elapsed = (self.clock.now() - self._revoked_at[key]).total_seconds()
            effective_allowed = elapsed < self.stale_acl_seconds
        else:
            effective_allowed = source_allowed

        if self.outage_after_revoke and not source_allowed:
            return TargetObservation(available=False, status_code=503)
        if self.force_negative_leak and principal.external_id.lower().startswith("bob"):
            effective_allowed = True
        if self.positive_never_ingests and principal.external_id.lower().startswith("alice"):
            effective_allowed = False

        if effective_allowed:
            content = self._indexed_content or ""
            return TargetObservation(
                available=True,
                answer=f"Synthetic result: {resource.canary}",
                citations=[resource.provider_id],
                retrieved_documents=[content],
                metadata={"prompt": prompt},
            )
        return TargetObservation(available=True, answer="I do not have access to that information.")
