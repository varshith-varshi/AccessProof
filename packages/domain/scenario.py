from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field, model_validator


class MutationType(str, Enum):
    DIRECT_USER_REVOKE = "direct_user_revoke"
    DIRECT_USER_GRANT = "direct_user_grant"
    GROUP_MEMBER_REMOVE = "group_member_remove"
    GROUP_MEMBER_ADD = "group_member_add"
    SHARE_LINK_REVOKE = "share_link_revoke"
    RESOURCE_DELETE = "resource_delete"
    PARENT_ACL_CHANGE = "parent_acl_change"
    RESOURCE_MOVE = "resource_move"


class SyntheticCategory(str, Enum):
    FINANCE = "finance"
    HR = "hr"
    LEGAL = "legal"
    M_AND_A = "m_and_a"
    ENGINEERING = "engineering"
    SALES = "sales"
    CUSTOMER_SUPPORT = "customer_support"
    PROCUREMENT = "procurement"
    PROJECT_PLANNING = "project_planning"


class ScenarioSeverity(str, Enum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    INFORMATIONAL = "INFORMATIONAL"


class LlmProbePolicy(BaseModel):
    enabled: bool = False
    max_probes: int = Field(default=5, ge=1, le=20)
    cost_budget_usd: float = Field(default=0.05, ge=0, le=100)
    max_output_tokens: int = Field(default=300, ge=32, le=4000)
    requests_per_minute: int = Field(default=10, ge=1, le=120)


class StabilityPolicy(BaseModel):
    required_clean_observations: int = Field(default=3, ge=1, le=20)
    required_clean_duration_seconds: float = Field(default=0.0, ge=0, le=600)


class PositiveControlPolicy(BaseModel):
    """Wait for a fresh synthetic resource to become stably visible in the AI."""
    timeout_seconds: float = Field(default=120.0, gt=0, le=86400)
    poll_interval_seconds: float = Field(default=5.0, gt=0, le=300)
    required_observations: int = Field(default=1, ge=1, le=20)


class PollingPolicy(BaseModel):
    initial_interval_seconds: float = Field(default=5.0, gt=0, le=300)
    maximum_interval_seconds: float = Field(default=30.0, gt=0, le=600)
    backoff_multiplier: float = Field(default=1.5, ge=1.0, le=4.0)
    jitter_ratio: float = Field(default=0.0, ge=0, le=0.5)
    maximum_probes: int = Field(default=100, ge=1, le=5000)


class ScenarioDefinition(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    mutation: MutationType = MutationType.DIRECT_USER_REVOKE
    maximum_slo_seconds: float = Field(default=60.0, gt=0, le=86400)
    timeout_seconds: float = Field(default=900.0, gt=0, le=86400)
    source_denial_timeout_seconds: float | None = Field(default=None, gt=0, le=86400)
    positive_control: PositiveControlPolicy = Field(default_factory=PositiveControlPolicy)
    polling: PollingPolicy = Field(default_factory=PollingPolicy)
    stability: StabilityPolicy = Field(default_factory=StabilityPolicy)
    severity: ScenarioSeverity = ScenarioSeverity.REQUIRED
    synthetic_category: SyntheticCategory = SyntheticCategory.FINANCE
    llm_probes: LlmProbePolicy = Field(default_factory=LlmProbePolicy)

    @model_validator(mode="after")
    def validate_timing(self) -> "ScenarioDefinition":
        if self.timeout_seconds <= self.maximum_slo_seconds:
            raise ValueError("timeout_seconds must be greater than maximum_slo_seconds")
        if self.polling.maximum_interval_seconds < self.polling.initial_interval_seconds:
            raise ValueError("maximum polling interval must be >= initial interval")
        if (
            self.source_denial_timeout_seconds is not None
            and self.source_denial_timeout_seconds > self.timeout_seconds
        ):
            raise ValueError("source_denial_timeout_seconds must be <= timeout_seconds")
        return self
