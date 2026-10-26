from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


class Capability(str, Enum):
    RESOURCE_CREATE = "RESOURCE_CREATE"
    RESOURCE_DELETE = "RESOURCE_DELETE"
    DIRECT_USER_GRANT = "DIRECT_USER_GRANT"
    DIRECT_USER_REVOKE = "DIRECT_USER_REVOKE"
    GROUP_CREATE = "GROUP_CREATE"
    GROUP_MEMBER_ADD = "GROUP_MEMBER_ADD"
    GROUP_MEMBER_REMOVE = "GROUP_MEMBER_REMOVE"
    SHARE_LINK_CREATE = "SHARE_LINK_CREATE"
    SHARE_LINK_REVOKE = "SHARE_LINK_REVOKE"
    PARENT_PERMISSION_MUTATION = "PARENT_PERMISSION_MUTATION"
    EFFECTIVE_ACCESS_QUERY = "EFFECTIVE_ACCESS_QUERY"
    USER_DISABLE = "USER_DISABLE"
    RESOURCE_MOVE = "RESOURCE_MOVE"
    PRIVATE_CONTAINER_CREATE = "PRIVATE_CONTAINER_CREATE"
    PRIVATE_CONTAINER_MEMBER_ADD = "PRIVATE_CONTAINER_MEMBER_ADD"
    PRIVATE_CONTAINER_MEMBER_REMOVE = "PRIVATE_CONTAINER_MEMBER_REMOVE"


class CapabilityStatus(str, Enum):
    # Canonical capability states exposed by the API/UI/test planner.
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    MISSING_SCOPE = "MISSING_SCOPE"
    PLAN_RESTRICTED = "PLAN_RESTRICTED"
    EXPERIMENTAL = "EXPERIMENTAL"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    PROVIDER_DEPRECATED = "PROVIDER_DEPRECATED"

    # Backward-compatible aliases for older connector code/configuration.
    UNAVAILABLE_DUE_TO_SCOPE = "MISSING_SCOPE"
    UNAVAILABLE_DUE_TO_PLAN = "PLAN_RESTRICTED"
    UNAVAILABLE_DUE_TO_PROVIDER = "UNSUPPORTED"
    NOT_YET_IMPLEMENTED = "NOT_IMPLEMENTED"


class RunState(str, Enum):
    CREATED = "CREATED"
    VALIDATING_CONNECTIONS = "VALIDATING_CONNECTIONS"
    PROVISIONING = "PROVISIONING"
    WAITING_FOR_SOURCE_READY = "WAITING_FOR_SOURCE_READY"
    WAITING_FOR_TARGET_INGESTION = "WAITING_FOR_TARGET_INGESTION"
    VERIFYING_POSITIVE_CONTROL = "VERIFYING_POSITIVE_CONTROL"
    VERIFYING_NEGATIVE_CONTROL = "VERIFYING_NEGATIVE_CONTROL"
    READY_FOR_MUTATION = "READY_FOR_MUTATION"
    MUTATING_SOURCE = "MUTATING_SOURCE"
    VERIFYING_SOURCE_GROUND_TRUTH = "VERIFYING_SOURCE_GROUND_TRUTH"
    MEASURING_PROPAGATION = "MEASURING_PROPAGATION"
    VERIFYING_STABLE_DENIAL = "VERIFYING_STABLE_DENIAL"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    CLEANING_UP = "CLEANING_UP"
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    CANCELED = "CANCELED"
    PRECONDITION_FAILURE = "PRECONDITION_FAILURE"


class RunOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    PRECONDITION_FAILURE = "PRECONDITION_FAILURE"
    CANCELED = "CANCELED"


class EvidenceLevel(str, Enum):
    ANSWER = "LEVEL_1_ANSWER_EXPOSURE"
    CITATION = "LEVEL_2_CITATION_EXPOSURE"
    RETRIEVAL = "LEVEL_3_RETRIEVAL_EXPOSURE"
    TOOL = "LEVEL_4_TOOL_EXPOSURE"


@dataclass(slots=True)
class Principal:
    external_id: str
    email: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)
    access_token: str | None = None
    session_id: str | None = None


@dataclass(slots=True)
class SourceResource:
    provider_id: str
    name: str
    marker: str
    canary: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ProbeObservation:
    observed_at: datetime
    exposed: bool
    evidence_level: EvidenceLevel | None = None
    matched_signal: str | None = None
    response_hash: str | None = None
    target_status: str = "ok"


@dataclass(slots=True)
class RunTimelineEvent:
    state: RunState
    at: datetime
    detail: str


@dataclass(slots=True)
class PropagationMetrics:
    resource_created_at: datetime | None = None
    source_allowed_confirmed_at: datetime | None = None
    first_ai_visibility_at: datetime | None = None
    positive_control_stable_at: datetime | None = None
    mutation_requested_at: datetime | None = None
    mutation_provider_acknowledged_at: datetime | None = None
    source_ground_truth_changed_at: datetime | None = None
    first_post_mutation_probe_at: datetime | None = None
    last_observed_exposure_at: datetime | None = None
    first_observed_denial_at: datetime | None = None
    stable_denial_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def provider_mutation_latency_seconds(self) -> float | None:
        if not self.mutation_requested_at or not self.mutation_provider_acknowledged_at:
            return None
        return (self.mutation_provider_acknowledged_at - self.mutation_requested_at).total_seconds()

    @property
    def initial_propagation_latency_seconds(self) -> float | None:
        if not self.source_ground_truth_changed_at or not self.first_observed_denial_at:
            return None
        return (self.first_observed_denial_at - self.source_ground_truth_changed_at).total_seconds()

    @property
    def stable_propagation_latency_seconds(self) -> float | None:
        if not self.source_ground_truth_changed_at or not self.stable_denial_at:
            return None
        return (self.stable_denial_at - self.source_ground_truth_changed_at).total_seconds()

    @property
    def exposure_window_seconds(self) -> float | None:
        if not self.source_ground_truth_changed_at or not self.last_observed_exposure_at:
            return 0.0 if self.source_ground_truth_changed_at else None
        return max(
            0.0,
            (self.last_observed_exposure_at - self.source_ground_truth_changed_at).total_seconds(),
        )


@dataclass(slots=True)
class EngineCheckpoint:
    run_id: str
    phase: str
    resource: dict[str, Any] | None = None
    metrics: dict[str, str | None] = field(default_factory=dict)
    observations: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    probe_count: int = 0
    polling_interval_seconds: float | None = None
    clean_count: int = 0
    clean_started_at: str | None = None
    mutation_operation_id: str | None = None
    mutation_provider_request_id: str | None = None
    mutation_acknowledged: bool = False
    source_confirmed: bool = False


@dataclass(slots=True)
class SourceGroundTruth:
    provider: str
    principal: str
    access_mechanism: str
    effective_access: str
    confirmed_at: datetime | None = None
    provider_detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FailureDiagnostic:
    boundary: str
    confidence: str
    summary: str


@dataclass(slots=True)
class ProbeGenerationInfo:
    provider: str
    model: str
    version: str | None
    generated_count: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    estimated_cost_usd: float | None = None
    status: str = "generated"


@dataclass(slots=True)
class EngineResult:
    run_id: UUID
    outcome: RunOutcome
    metrics: PropagationMetrics
    observations: list[ProbeObservation]
    timeline: list[RunTimelineEvent]
    source_ground_truth: str
    expected_slo_seconds: float
    reason: str
    source_ground_truth_detail: SourceGroundTruth | None = None
    diagnostic: FailureDiagnostic | None = None
    probe_generation: ProbeGenerationInfo | None = None
    synthetic_resource: SourceResource | None = None
    evidence_hashes: list[str] = field(default_factory=list)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_run_id() -> UUID:
    return uuid4()
