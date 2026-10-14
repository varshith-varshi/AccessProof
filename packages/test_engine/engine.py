from __future__ import annotations
from collections.abc import Awaitable, Callable
from packages.test_engine.probes import OpenAICompatibleProbeGenerator
from packages.domain.models import ProbeGenerationInfo

from typing import Any

import hashlib
import inspect
from opentelemetry import trace
from dataclasses import asdict
from datetime import datetime
from uuid import UUID, uuid4

from packages.connector_sdk.base import (
    AuthenticationError,
    AuthorizationError,
    ProviderUnavailableError,
    RateLimitError,
    SourceAdapter,
    UnsupportedCapabilityError,
)
from packages.connector_sdk.target import AITargetAdapter
from packages.domain.models import (
    Capability,
    EngineCheckpoint,
    EngineResult,
    FailureDiagnostic,
    Principal,
    ProbeObservation,
    PropagationMetrics,
    RunOutcome,
    RunState,
    RunTimelineEvent,
    SourceGroundTruth,
    SourceResource,
)
from packages.domain.scenario import MutationType, ScenarioDefinition
from packages.test_engine.clock import Clock
from packages.test_engine.oracle import detect_exposure, response_hash
from packages.test_engine.synthetic import deterministic_probes, generate_synthetic_document

_tracer = trace.get_tracer("accessproof.test_engine")


class EngineInterrupted(RuntimeError):
    """Raised by checkpoint hooks to simulate/process a runner interruption safely."""


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _restore_metrics(raw: dict[str, Any] | None) -> PropagationMetrics:
    raw = raw or {}
    return PropagationMetrics(**{key: _dt(value) for key, value in raw.items()})


def _restore_resource(raw: dict[str, Any] | None) -> SourceResource | None:
    if not raw:
        return None
    return SourceResource(**raw)


def _restore_observations(raw: list[dict[str, Any]] | None) -> list[ProbeObservation]:
    from packages.domain.models import EvidenceLevel

    restored: list[ProbeObservation] = []
    for item in raw or []:
        value = dict(item)
        value["observed_at"] = _dt(value["observed_at"])
        if value.get("evidence_level"):
            value["evidence_level"] = EvidenceLevel(value["evidence_level"])
        restored.append(ProbeObservation(**value))
    return restored


def _restore_timeline(raw: list[dict[str, Any]] | None) -> list[RunTimelineEvent]:
    restored: list[RunTimelineEvent] = []
    for item in raw or []:
        restored.append(
            RunTimelineEvent(
                state=RunState(item["state"]),
                at=datetime.fromisoformat(item["at"]),
                detail=item.get("detail", ""),
            )
        )
    return restored


class PermissionRegressionEngine:
    def __init__(
        self,
        source: SourceAdapter,
        target: AITargetAdapter,
        *,
        clock: Clock | None = None,
        cancel_check: Callable[[], bool | Awaitable[bool]] | None = None,
        checkpoint_callback: Callable[[dict[str, Any]], None | Awaitable[None]] | None = None,
        probe_generator: OpenAICompatibleProbeGenerator | None = None,
    ):
        self.source = source
        self.target = target
        self.clock = clock or Clock()
        self.cancel_check = cancel_check
        self.checkpoint_callback = checkpoint_callback
        self.probe_generator = probe_generator
        self._probe_generation: ProbeGenerationInfo | None = None
        self._active_principal_external_id: str | None = None

    async def _is_canceled(self) -> bool:
        if self.cancel_check is None:
            return False
        value = self.cancel_check()
        if inspect.isawaitable(value):
            value = await value
        return bool(value)

    async def _checkpoint(
        self,
        *,
        run_id: UUID,
        phase: str,
        resource: SourceResource | None,
        metrics: PropagationMetrics,
        observations: list[ProbeObservation],
        timeline: list[RunTimelineEvent],
        probe_count: int = 0,
        polling_interval_seconds: float | None = None,
        clean_count: int = 0,
        clean_started_at: datetime | None = None,
        mutation_operation_id: str | None = None,
        mutation_provider_request_id: str | None = None,
        mutation_acknowledged: bool = False,
        source_confirmed: bool = False,
    ) -> dict[str, Any]:
        checkpoint = EngineCheckpoint(
            run_id=str(run_id),
            phase=phase,
            resource=asdict(resource) if resource else None,
            metrics={
                key: (value.isoformat() if value else None)
                for key, value in asdict(metrics).items()
            },
            observations=[
                {
                    **asdict(obs),
                    "observed_at": obs.observed_at.isoformat(),
                    "evidence_level": obs.evidence_level.value if obs.evidence_level else None,
                }
                for obs in observations
            ],
            timeline=[
                {"state": item.state.value, "at": item.at.isoformat(), "detail": item.detail}
                for item in timeline
            ],
            probe_count=probe_count,
            polling_interval_seconds=polling_interval_seconds,
            clean_count=clean_count,
            clean_started_at=clean_started_at.isoformat() if clean_started_at else None,
            mutation_operation_id=mutation_operation_id,
            mutation_provider_request_id=mutation_provider_request_id,
            mutation_acknowledged=mutation_acknowledged,
            source_confirmed=source_confirmed,
        )
        payload = asdict(checkpoint)
        if self.checkpoint_callback is not None:
            value = self.checkpoint_callback(payload)
            if inspect.isawaitable(value):
                await value
        return payload

    def _required_capabilities(self, scenario: ScenarioDefinition) -> list[Capability]:
        mutation = MutationType(scenario.mutation)
        mapping = {
            MutationType.DIRECT_USER_REVOKE: [
                Capability.DIRECT_USER_GRANT,
                Capability.DIRECT_USER_REVOKE,
            ],
            MutationType.GROUP_MEMBER_REMOVE: [
                Capability.GROUP_CREATE,
                Capability.GROUP_MEMBER_ADD,
                Capability.GROUP_MEMBER_REMOVE,
            ],
            MutationType.SHARE_LINK_REVOKE: [
                Capability.SHARE_LINK_CREATE,
                Capability.SHARE_LINK_REVOKE,
            ],
            MutationType.RESOURCE_DELETE: [
                Capability.DIRECT_USER_GRANT,
                Capability.RESOURCE_DELETE,
            ],
            MutationType.PARENT_ACL_CHANGE: [Capability.PARENT_PERMISSION_MUTATION],
            MutationType.RESOURCE_MOVE: [
                Capability.PARENT_PERMISSION_MUTATION,
                Capability.RESOURCE_MOVE,
            ],
        }
        return mapping.get(mutation, [])

    async def _setup_access_path(
        self, resource: SourceResource, principal: Principal, scenario: ScenarioDefinition
    ) -> None:
        mutation = MutationType(scenario.mutation)
        if mutation in {MutationType.DIRECT_USER_REVOKE, MutationType.RESOURCE_DELETE}:
            await self.source.grant_access(resource, principal)
            return
        if mutation is MutationType.RESOURCE_MOVE:
            # A move regression must exercise access inherited from the old parent.
            # A direct item grant normally survives a move and would make this test meaningless.
            await self.source.grant_parent_access(resource, principal)
            return
        if mutation is MutationType.GROUP_MEMBER_REMOVE:
            group_id = await self.source.create_group(name=f"AP_TEST_{resource.provider_id}")
            await self.source.add_group_member(group_id, principal)
            await self.source.grant_group_access(resource, group_id)
            resource.metadata["group_id"] = group_id
            return
        if mutation is MutationType.SHARE_LINK_REVOKE:
            resource.metadata["share_link_id"] = await self.source.create_share_link(
                resource, principal
            )
            return
        if mutation is MutationType.PARENT_ACL_CHANGE:
            await self.source.grant_parent_access(resource, principal)
            return
        raise UnsupportedCapabilityError(
            f"Scenario mutation {mutation.value} is not supported by the revocation engine"
        )

    async def _apply_mutation(
        self, resource: SourceResource, principal: Principal, scenario: ScenarioDefinition
    ) -> None:
        mutation = MutationType(scenario.mutation)
        if mutation is MutationType.DIRECT_USER_REVOKE:
            await self.source.revoke_access(resource, principal)
        elif mutation is MutationType.GROUP_MEMBER_REMOVE:
            await self.source.remove_group_member(str(resource.metadata["group_id"]), principal)
        elif mutation is MutationType.SHARE_LINK_REVOKE:
            await self.source.revoke_share_link(resource, str(resource.metadata["share_link_id"]))
        elif mutation is MutationType.RESOURCE_DELETE:
            # Persist the destructive boundary in the resource metadata before
            # invoking the provider. If the request outcome is ambiguous, the
            # generic cleanup path must not blindly issue the delete again.
            resource.metadata["delete_requested_by_scenario"] = True
            await self.source.delete_resource(resource)
            resource.metadata["deleted_by_scenario"] = True
        elif mutation is MutationType.PARENT_ACL_CHANGE:
            await self.source.revoke_parent_access(resource, principal)
        elif mutation is MutationType.RESOURCE_MOVE:
            await self.source.move_resource(resource)
        else:
            raise UnsupportedCapabilityError(
                f"Scenario mutation {mutation.value} is not supported by the revocation engine"
            )

    async def run_revocation(
        self,
        *,
        allowed: Principal,
        denied_control: Principal,
        scenario: ScenarioDefinition,
        resume_checkpoint: dict[str, Any] | None = None,
        run_id_override: str | UUID | None = None,
    ) -> EngineResult:
        resume = dict(resume_checkpoint or {})
        self._active_principal_external_id = allowed.external_id
        self._probe_generation = None
        run_id = (
            UUID(resume["run_id"])
            if resume.get("run_id")
            else (UUID(str(run_id_override)) if run_id_override else uuid4())
        )
        metrics = _restore_metrics(resume.get("metrics"))
        observations = _restore_observations(resume.get("observations"))
        timeline = _restore_timeline(resume.get("timeline"))
        resource = _restore_resource(resume.get("resource"))
        interrupted = False
        mutation_operation_id = resume.get("mutation_operation_id") or str(uuid4())
        mutation_provider_request_id = resume.get("mutation_provider_request_id")
        mutation_acknowledged = bool(resume.get("mutation_acknowledged"))
        source_confirmed = bool(resume.get("source_confirmed"))
        probe_count = int(resume.get("probe_count") or 0)
        interval = float(
            resume.get("polling_interval_seconds") or scenario.polling.initial_interval_seconds
        )
        clean_count = int(resume.get("clean_count") or 0)
        clean_started = _dt(resume.get("clean_started_at"))
        # Probe wording is deterministic for the selected synthetic domain and is
        # independent of the unique canary/resource IDs used by the security oracle.
        probe_set = deterministic_probes(
            generate_synthetic_document(category=scenario.synthetic_category.value)
        )

        def event(state: RunState, detail: str) -> None:
            timeline.append(RunTimelineEvent(state=state, at=self.clock.now(), detail=detail))

        try:
            if not resume:
                event(RunState.CREATED, "Run created")
            else:
                event(
                    RunState.VALIDATING_CONNECTIONS,
                    f"Recovered run from checkpoint phase={resume.get('phase', 'unknown')}",
                )
            event(RunState.VALIDATING_CONNECTIONS, "Validating source and target")
            with _tracer.start_as_current_span("accessproof.connections.validate") as span:
                span.set_attribute("accessproof.provider", self.source.provider)
                await self.source.validate_connection()
                await self.target.validate_connection()
            required_capabilities = self._required_capabilities(scenario)
            if not required_capabilities:
                return self._finish(
                    run_id,
                    RunOutcome.INCONCLUSIVE,
                    metrics,
                    observations,
                    timeline,
                    f"Scenario mutation {MutationType(scenario.mutation).value} is not implemented by the revocation engine",
                    scenario,
                    resource,
                )
            capability_report = await self.source.discover_capabilities()
            missing = [
                cap.value for cap in required_capabilities if not capability_report.supports(cap)
            ]
            if missing:
                return self._finish(
                    run_id,
                    RunOutcome.INCONCLUSIVE,
                    metrics,
                    observations,
                    timeline,
                    "Source connection does not support required capabilities: "
                    + ", ".join(missing),
                    scenario,
                    resource,
                )

            if resume and resource is not None:
                # A restarted runner reconstructs a fresh adapter instance. Re-adopt only
                # the exact checkpointed AccessProof resource after the adapter validates
                # that it still belongs to the configured test boundary. This restores
                # destructive-operation ownership guards without trusting a resource name.
                await self.source.adopt_tracked_resource(resource)

            if resource is None:
                event(RunState.PROVISIONING, "Creating synthetic resource")
                synthetic = generate_synthetic_document(category=scenario.synthetic_category.value)
                resource = await self.source.create_resource(
                    name=synthetic.title, content=synthetic.body, marker=synthetic.canary
                )
                metrics.resource_created_at = self.clock.now()
                resource.metadata["protected_signals"] = [synthetic.semantic_fact, synthetic.secret_value]
                await self._setup_access_path(resource, allowed, scenario)

                event(
                    RunState.VERIFYING_POSITIVE_CONTROL,
                    "Verifying source and AI access for allowed identity",
                )
                if not await self.source.verify_user_can_access(resource, allowed):
                    return self._finish(
                        run_id,
                        RunOutcome.PRECONDITION_FAILURE,
                        metrics,
                        observations,
                        timeline,
                        "Source positive control failed",
                        scenario,
                        resource,
                    )
                metrics.source_allowed_confirmed_at = self.clock.now()
                probes = deterministic_probes(synthetic)
                probe_set = list(probes)
                if scenario.llm_probes.enabled:
                    if self.probe_generator is None:
                        event(
                            RunState.PROVISIONING,
                            "Optional LLM probe generation is enabled but no BYOK provider is configured; continuing with deterministic probes",
                        )
                    else:
                        try:
                            generated, generation_info = await self.probe_generator.generate(
                                synthetic, scenario.llm_probes
                            )
                            self._probe_generation = generation_info
                            for probe in generated:
                                if probe not in probe_set:
                                    probe_set.append(probe)
                            event(
                                RunState.PROVISIONING,
                                f"Added {generation_info.generated_count} optional synthetic-only LLM probes using {generation_info.provider}/{generation_info.model}",
                            )
                        except Exception as exc:
                            event(
                                RunState.PROVISIONING,
                                f"Optional LLM probe generation unavailable ({type(exc).__name__}); continuing with deterministic probes",
                            )
                event(RunState.WAITING_FOR_TARGET_INGESTION, "Waiting for stable AI ingestion")
                positive_deadline = self.clock.now().timestamp() + scenario.positive_control.timeout_seconds
                positive_count = 0
                while self.clock.now().timestamp() <= positive_deadline:
                    positive = await self.target.probe(principal=allowed, prompt=probe_set[positive_count % len(probe_set)])
                    if not positive.available:
                        return self._finish(run_id, RunOutcome.INCONCLUSIVE, metrics, observations, timeline, "Target unavailable during positive control", scenario, resource)
                    positive_match = detect_exposure(
                        positive, canary=resource.canary, resource_id=resource.provider_id,
                        protected_signals=resource.metadata.get("protected_signals", []),
                    )
                    if positive_match.exposed:
                        metrics.first_ai_visibility_at = metrics.first_ai_visibility_at or self.clock.now()
                        positive_count += 1
                        if positive_count >= scenario.positive_control.required_observations:
                            metrics.positive_control_stable_at = self.clock.now()
                            break
                    else:
                        positive_count = 0
                    if self.clock.now().timestamp() >= positive_deadline:
                        break
                    await self.clock.sleep(min(scenario.positive_control.poll_interval_seconds, positive_deadline - self.clock.now().timestamp()))
                if metrics.positive_control_stable_at is None:
                    return self._finish(
                        run_id, RunOutcome.PRECONDITION_FAILURE, metrics, observations, timeline,
                        "AI_INGESTION_NOT_CONFIRMED: protected marker was not stably visible before the positive-control timeout",
                        scenario, resource,
                    )

                event(
                    RunState.VERIFYING_NEGATIVE_CONTROL,
                    "Verifying denied identity cannot retrieve canary",
                )
                negative = await self.target.probe(principal=denied_control, prompt=probe_set[0])
                negative_match = detect_exposure(
                    negative, canary=resource.canary, resource_id=resource.provider_id,
                    protected_signals=resource.metadata.get("protected_signals", []),
                )
                if not negative.available:
                    return self._finish(
                        run_id,
                        RunOutcome.INCONCLUSIVE,
                        metrics,
                        observations,
                        timeline,
                        "Target unavailable during negative control",
                        scenario,
                        resource,
                    )
                if negative_match.exposed:
                    return self._finish(
                        run_id,
                        RunOutcome.PRECONDITION_FAILURE,
                        metrics,
                        observations,
                        timeline,
                        "Denied control already had access before mutation",
                        scenario,
                        resource,
                    )

                await self._checkpoint(
                    run_id=run_id,
                    phase="preconditions_verified",
                    resource=resource,
                    metrics=metrics,
                    observations=observations,
                    timeline=timeline,
                    mutation_operation_id=mutation_operation_id,
                    mutation_provider_request_id=mutation_provider_request_id,
                )

            if resume.get("phase") == "mutation_requested" and not mutation_acknowledged:
                event(
                    RunState.MUTATING_SOURCE,
                    "Recovered from ambiguous post-request state; reconciling source before any replay",
                )
                reconcile_deadline = self.clock.now().timestamp() + min(
                    30.0, scenario.timeout_seconds
                )
                access_still_allowed = await self.source.verify_user_can_access(resource, allowed)
                while access_still_allowed and self.clock.now().timestamp() < reconcile_deadline:
                    await self.clock.sleep(1)
                    access_still_allowed = await self.source.verify_user_can_access(
                        resource, allowed
                    )
                if access_still_allowed:
                    return self._finish(
                        run_id,
                        RunOutcome.INCONCLUSIVE,
                        metrics,
                        observations,
                        timeline,
                        "Recovered with an ambiguous mutation outcome; source still allows access and AccessProof refuses to replay a destructive mutation blindly",
                        scenario,
                        resource,
                    )
                mutation_acknowledged = True
                source_confirmed = True
                metrics.mutation_provider_acknowledged_at = (
                    metrics.mutation_provider_acknowledged_at or self.clock.now()
                )
                metrics.source_ground_truth_changed_at = (
                    metrics.source_ground_truth_changed_at or self.clock.now()
                )
                await self._checkpoint(
                    run_id=run_id,
                    phase="source_confirmed",
                    resource=resource,
                    metrics=metrics,
                    observations=observations,
                    timeline=timeline,
                    mutation_operation_id=mutation_operation_id,
                    mutation_provider_request_id=mutation_provider_request_id,
                    mutation_acknowledged=True,
                    source_confirmed=True,
                )

            if not mutation_acknowledged:
                event(RunState.READY_FOR_MUTATION, "Preconditions satisfied")
                if await self._is_canceled():
                    return self._finish(
                        run_id,
                        RunOutcome.CANCELED,
                        metrics,
                        observations,
                        timeline,
                        "Run canceled before mutation",
                        scenario,
                        resource,
                    )
                event(
                    RunState.MUTATING_SOURCE,
                    f"Applying source mutation: {MutationType(scenario.mutation).value}",
                )
                if metrics.mutation_requested_at is None:
                    metrics.mutation_requested_at = self.clock.now()
                await self._checkpoint(
                    run_id=run_id,
                    phase="mutation_requested",
                    resource=resource,
                    metrics=metrics,
                    observations=observations,
                    timeline=timeline,
                    mutation_operation_id=mutation_operation_id,
                    mutation_provider_request_id=mutation_provider_request_id,
                )
                with _tracer.start_as_current_span("accessproof.source.mutation") as span:
                    span.set_attribute("accessproof.provider", self.source.provider)
                    span.set_attribute(
                        "accessproof.mutation_type", MutationType(scenario.mutation).value
                    )
                    await self._apply_mutation(resource, allowed, scenario)
                mutation_provider_request_id = self.source.get_last_provider_request_id()
                metrics.mutation_provider_acknowledged_at = self.clock.now()
                mutation_acknowledged = True
                await self._checkpoint(
                    run_id=run_id,
                    phase="mutation_acknowledged",
                    resource=resource,
                    metrics=metrics,
                    observations=observations,
                    timeline=timeline,
                    mutation_operation_id=mutation_operation_id,
                    mutation_provider_request_id=mutation_provider_request_id,
                    mutation_acknowledged=True,
                )
            else:
                event(
                    RunState.MUTATING_SOURCE,
                    "Recovered after provider acknowledgement; destructive mutation will not be replayed",
                )

            if not source_confirmed:
                event(
                    RunState.VERIFYING_SOURCE_GROUND_TRUTH, "Waiting for source denial confirmation"
                )
                source_deadline = self.clock.now().timestamp() + min(
                    scenario.source_denial_timeout_seconds or scenario.timeout_seconds,
                    scenario.timeout_seconds,
                )
                while await self.source.verify_user_can_access(resource, allowed):
                    if self.clock.now().timestamp() >= source_deadline:
                        return self._finish(
                            run_id,
                            RunOutcome.INCONCLUSIVE,
                            metrics,
                            observations,
                            timeline,
                            "Source mutation was acknowledged but denial could not be confirmed",
                            scenario,
                            resource,
                        )
                    await self.clock.sleep(1)
                if metrics.source_ground_truth_changed_at is None:
                    metrics.source_ground_truth_changed_at = self.clock.now()
                source_confirmed = True
                await self._checkpoint(
                    run_id=run_id,
                    phase="source_confirmed",
                    resource=resource,
                    metrics=metrics,
                    observations=observations,
                    timeline=timeline,
                    probe_count=probe_count,
                    polling_interval_seconds=interval,
                    clean_count=clean_count,
                    clean_started_at=clean_started,
                    mutation_operation_id=mutation_operation_id,
                    mutation_provider_request_id=mutation_provider_request_id,
                    mutation_acknowledged=True,
                    source_confirmed=True,
                )
            else:
                event(
                    RunState.VERIFYING_SOURCE_GROUND_TRUTH, "Recovered with confirmed source denial"
                )

            event(
                RunState.MEASURING_PROPAGATION,
                "Measuring AI exposure after confirmed source denial",
            )
            assert metrics.source_ground_truth_changed_at is not None
            deadline = metrics.source_ground_truth_changed_at.timestamp() + scenario.timeout_seconds

            while (
                self.clock.now().timestamp() <= deadline
                and probe_count < scenario.polling.maximum_probes
            ):
                if await self._is_canceled():
                    return self._finish(
                        run_id,
                        RunOutcome.CANCELED,
                        metrics,
                        observations,
                        timeline,
                        "Run canceled during propagation measurement",
                        scenario,
                        resource,
                    )
                if probe_count > 0:
                    remaining = deadline - self.clock.now().timestamp()
                    if remaining <= 0:
                        break
                    await self.clock.sleep(min(interval, remaining))
                probe_count += 1
                if metrics.first_post_mutation_probe_at is None:
                    metrics.first_post_mutation_probe_at = self.clock.now()

                with _tracer.start_as_current_span("accessproof.target.probe") as span:
                    span.set_attribute("accessproof.probe_number", probe_count)
                    target_observation = await self.target.probe(
                        principal=allowed,
                        prompt=probe_set[(probe_count - 1) % len(probe_set)],
                    )
                if not target_observation.available:
                    return self._finish(
                        run_id,
                        RunOutcome.INCONCLUSIVE,
                        metrics,
                        observations,
                        timeline,
                        "Target unavailable during propagation measurement",
                        scenario,
                        resource,
                    )

                match = detect_exposure(
                    target_observation, canary=resource.canary, resource_id=resource.provider_id,
                    protected_signals=resource.metadata.get("protected_signals", []),
                )
                observation = ProbeObservation(
                    observed_at=self.clock.now(),
                    exposed=match.exposed,
                    evidence_level=match.level,
                    matched_signal=match.signal,
                    response_hash=response_hash(target_observation),
                )
                observations.append(observation)

                if match.exposed:
                    metrics.last_observed_exposure_at = self.clock.now()
                    clean_count = 0
                    clean_started = None
                else:
                    if metrics.first_observed_denial_at is None:
                        metrics.first_observed_denial_at = self.clock.now()
                    clean_count += 1
                    clean_started = clean_started or self.clock.now()
                    clean_duration = (self.clock.now() - clean_started).total_seconds()
                    if (
                        clean_count >= scenario.stability.required_clean_observations
                        and clean_duration >= scenario.stability.required_clean_duration_seconds
                    ):
                        metrics.stable_denial_at = self.clock.now()
                        event(RunState.VERIFYING_STABLE_DENIAL, "Stable denial confirmed")
                        stable = metrics.stable_propagation_latency_seconds or 0.0
                        outcome = (
                            RunOutcome.PASS
                            if stable <= scenario.maximum_slo_seconds
                            else RunOutcome.FAIL
                        )
                        reason = (
                            f"Stable denial observed in {stable:.1f}s within {scenario.maximum_slo_seconds:.1f}s SLO"
                            if outcome is RunOutcome.PASS
                            else f"Stable denial took {stable:.1f}s, exceeding {scenario.maximum_slo_seconds:.1f}s SLO"
                        )
                        await self._checkpoint(
                            run_id=run_id,
                            phase="stable_denial",
                            resource=resource,
                            metrics=metrics,
                            observations=observations,
                            timeline=timeline,
                            probe_count=probe_count,
                            polling_interval_seconds=interval,
                            clean_count=clean_count,
                            clean_started_at=clean_started,
                            mutation_operation_id=mutation_operation_id,
                            mutation_acknowledged=True,
                            source_confirmed=True,
                        )
                        return self._finish(
                            run_id,
                            outcome,
                            metrics,
                            observations,
                            timeline,
                            reason,
                            scenario,
                            resource,
                        )

                interval = min(
                    scenario.polling.maximum_interval_seconds,
                    interval * scenario.polling.backoff_multiplier,
                )
                await self._checkpoint(
                    run_id=run_id,
                    phase="measuring_propagation",
                    resource=resource,
                    metrics=metrics,
                    observations=observations,
                    timeline=timeline,
                    probe_count=probe_count,
                    polling_interval_seconds=interval,
                    clean_count=clean_count,
                    clean_started_at=clean_started,
                    mutation_operation_id=mutation_operation_id,
                    mutation_provider_request_id=mutation_provider_request_id,
                    mutation_acknowledged=True,
                    source_confirmed=True,
                )

            return self._finish(
                run_id,
                RunOutcome.FAIL,
                metrics,
                observations,
                timeline,
                "Forbidden evidence remained accessible or stable denial was not reached before timeout",
                scenario,
                resource,
            )
        except EngineInterrupted:
            interrupted = True
            raise
        except UnsupportedCapabilityError as exc:
            return self._finish(
                run_id,
                RunOutcome.INCONCLUSIVE,
                metrics,
                observations,
                timeline,
                f"Unsupported source capability: {exc}",
                scenario,
                resource,
            )
        except ProviderUnavailableError as exc:
            return self._finish(
                run_id,
                RunOutcome.INCONCLUSIVE,
                metrics,
                observations,
                timeline,
                f"Provider unavailable: {exc}",
                scenario,
                resource,
            )
        except (RateLimitError, AuthenticationError, AuthorizationError) as exc:
            return self._finish(
                run_id,
                RunOutcome.INCONCLUSIVE,
                metrics,
                observations,
                timeline,
                f"Provider could not establish a conclusive result: {type(exc).__name__}: {exc}",
                scenario,
                resource,
            )
        except Exception as exc:
            return self._finish(
                run_id,
                RunOutcome.ERROR,
                metrics,
                observations,
                timeline,
                f"Internal AccessProof error: {type(exc).__name__}: {exc}",
                scenario,
                resource,
            )
        finally:
            if resource is not None and not interrupted:
                event(RunState.CLEANING_UP, "Cleaning synthetic resources")
                try:
                    if resource.metadata.get(
                        "delete_requested_by_scenario"
                    ) and not resource.metadata.get("deleted_by_scenario"):
                        event(
                            RunState.CLEANING_UP,
                            "Cleanup pending: resource deletion outcome is ambiguous and will not be replayed blindly",
                        )
                    elif not resource.metadata.get("delete_requested_by_scenario"):
                        await self.source.delete_resource(resource)
                    await self.source.cleanup()
                except Exception:
                    event(RunState.CLEANING_UP, "Cleanup pending: provider deletion failed")

    def _finish(
        self,
        run_id: UUID,
        outcome: RunOutcome,
        metrics: PropagationMetrics,
        observations: list[ProbeObservation],
        timeline: list[RunTimelineEvent],
        reason: str,
        scenario: ScenarioDefinition,
        resource: SourceResource | None,
    ) -> EngineResult:
        metrics.completed_at = self.clock.now()
        state = {
            RunOutcome.PASS: RunState.PASSED,
            RunOutcome.FAIL: RunState.FAILED,
            RunOutcome.INCONCLUSIVE: RunState.INCONCLUSIVE,
            RunOutcome.ERROR: RunState.ERROR,
            RunOutcome.CANCELED: RunState.CANCELED,
            RunOutcome.PRECONDITION_FAILURE: RunState.PRECONDITION_FAILURE,
        }[outcome]
        timeline.append(RunTimelineEvent(state=state, at=self.clock.now(), detail=reason))
        hashes = [hashlib.sha256(repr(asdict(o)).encode()).hexdigest() for o in observations]
        source_denied = metrics.source_ground_truth_changed_at is not None
        ground_truth = SourceGroundTruth(
            provider=getattr(self.source, "provider", "unknown"),
            principal=self._active_principal_external_id or "unknown",
            access_mechanism=MutationType(scenario.mutation).value,
            effective_access="DENIED" if source_denied else "UNKNOWN",
            confirmed_at=metrics.source_ground_truth_changed_at,
        )
        diagnostic = None
        if source_denied and any(item.exposed for item in observations):
            diagnostic = FailureDiagnostic(
                boundary="DOWNSTREAM_OF_SOURCE_AUTHORIZATION",
                confidence="CONFIRMED",
                summary="Source access was confirmed denied while the AI still exposed forbidden evidence.",
            )
        elif outcome is RunOutcome.FAIL:
            diagnostic = FailureDiagnostic(
                boundary="UNKNOWN",
                confidence="UNKNOWN",
                summary="The run failed, but available evidence does not prove a specific downstream component as the cause.",
            )
        return EngineResult(
            run_id=run_id,
            outcome=outcome,
            metrics=metrics,
            observations=observations,
            timeline=timeline,
            source_ground_truth="DENIED" if source_denied else "UNKNOWN",
            source_ground_truth_detail=ground_truth,
            diagnostic=diagnostic,
            probe_generation=self._probe_generation,
            expected_slo_seconds=scenario.maximum_slo_seconds,
            reason=reason,
            synthetic_resource=resource,
            evidence_hashes=hashes,
        )
