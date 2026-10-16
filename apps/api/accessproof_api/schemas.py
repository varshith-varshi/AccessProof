from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    organization_name: str | None = Field(default=None, min_length=2, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    organization_id: str | None = None
    totp_code: str | None = None


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)


class SourceCreate(BaseModel):
    project_id: str
    provider: str
    name: str
    boundary: str = Field(min_length=1, max_length=2000)
    credentials: dict[str, Any] = Field(default_factory=dict)
    mutation_acknowledged: bool = False


class CurrentSourceCreate(BaseModel):
    """A current-product permission source without legacy project selection."""

    provider: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=200)
    boundary: str = Field(min_length=1, max_length=2000)
    credentials: dict[str, Any] = Field(default_factory=dict)


class TargetCreate(BaseModel):
    project_id: str
    name: str
    url: str
    runner_mode: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    credentials: dict[str, Any] = Field(default_factory=dict)


class TestIdentityCreate(BaseModel):
    project_id: str
    display_name: str = Field(min_length=1, max_length=200)
    provider_type: str = Field(default="static_bearer", max_length=50)
    provider_name: str | None = Field(default=None, max_length=200)
    subject_id: str = Field(min_length=1, max_length=320)
    email: str | None = Field(default=None, max_length=320)
    tenant_id: str | None = Field(default=None, max_length=320)
    issuer: str | None = None
    audience: str | None = Field(default=None, max_length=500)
    required_scopes: list[str] = Field(default_factory=list)
    credentials: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TestIdentityCredentialUpdate(BaseModel):
    credentials: dict[str, Any] = Field(default_factory=dict)


class SuiteCreate(BaseModel):
    project_id: str
    name: str
    scenario: dict[str, Any]


class RunCreate(BaseModel):
    project_id: str
    suite_id: str
    source_connection_id: str | None = None
    ai_target_id: str | None = None
    allowed_identity_id: str | None = None
    denied_identity_id: str | None = None
    allowed_principal: dict[str, Any] = Field(
        default_factory=lambda: {"external_id": "alice", "email": "alice@example.invalid"}
    )
    denied_principal: dict[str, Any] = Field(
        default_factory=lambda: {"external_id": "bob", "email": "bob@example.invalid"}
    )
    release: str = "manual"
    git_sha: str | None = None


class RunnerRegistrationCreate(BaseModel):
    project_id: str
    display_name: str | None = Field(default=None, min_length=2, max_length=200)
    expires_in_minutes: int = Field(default=30, ge=5, le=60)


class RunnerExchange(BaseModel):
    registration_token: str
    name: str = Field(min_length=2, max_length=200)
    version: str = "0.1.0"
    platform: str | None = Field(default=None, max_length=80)
    architecture: str | None = Field(default=None, max_length=80)
    capabilities: dict[str, Any] = Field(default_factory=dict)


class RunnerHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runner_id: str
    version: str = "0.1.0"
    platform: str | None = Field(default=None, max_length=80)
    architecture: str | None = Field(default=None, max_length=80)
    capabilities: dict[str, Any] | None = None


class RunnerLeaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runner_id: str


class RunnerCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runner_id: str
    run_id: str
    result: dict[str, Any]


class ApiKeyCreate(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    expires_in_days: int | None = Field(default=90, ge=1, le=3650)
    scopes: list[str] = Field(
        default_factory=lambda: ["projects:read", "runs:read", "runs:create", "reports:read"]
    )


class ReleaseCreate(BaseModel):
    project_id: str
    name: str = Field(min_length=1, max_length=200)
    git_sha: str | None = Field(default=None, max_length=64)
    branch: str | None = Field(default=None, max_length=200)
    environment: str = Field(default="staging", max_length=100)
    deployment: str | None = None
    connector_version: str | None = None
    retrieval_version: str | None = None
    model_version: str | None = None
    reranker_version: str | None = None


class WebhookCreate(BaseModel):
    project_id: str | None = None
    url: str


class EmailVerifyRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class GuardEventCreate(BaseModel):
    source_id: str
    provider: str
    provider_revision: int = 0
    subject_id: str
    resource_id: str
    change_type: Literal["grant_upsert", "grant_revoke", "membership_upsert", "membership_revoke", "sync_incomplete", "revoke"]
    dedupe_key: str
    grant_key: str | None = Field(default=None, max_length=255)
    grant_effect: Literal["allow", "deny"] = "allow"
    principal_type: Literal["subject", "group", "organization"] = "subject"
    principal_id: str | None = Field(default=None, max_length=255)
    group_id: str | None = Field(default=None, max_length=255)
    scope: str = Field(default="read", max_length=100)
    access_path: str | None = Field(default=None, max_length=255)
    snapshot_complete: bool = True


class GuardResourceInput(BaseModel):
    source_id: str
    resource_id: str
    chunk_ids: list[str] = []


class GuardFilterRequest(BaseModel):
    application_id: str
    request_id: str
    subject_id: str | None = None
    resources: list[GuardResourceInput]


class GuardCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    environment: str = Field(default="production", max_length=50)
    version: str = Field(default="1.0.0", max_length=50)


class GuardEnrollmentCreate(BaseModel):
    expires_in_minutes: int = Field(default=15, ge=1, le=60)


class GuardExchange(BaseModel):
    enrollment_token: str = Field(min_length=24, max_length=512)
    version: str = Field(min_length=1, max_length=50)


class GuardHeartbeat(BaseModel):
    guard_id: str
    version: str = Field(min_length=1, max_length=50)
    active_policy_version: int = Field(default=0, ge=0)
    cache_status: str = Field(default="healthy", max_length=30)
    degraded_conditions: list[str] = Field(default_factory=list, max_length=20)


class GuardPolicyAck(BaseModel):
    guard_id: str
    policy_version: int = Field(ge=1)
    status: Literal["received", "installed"]


class GuardAuditEventInput(BaseModel):
    event_id: str = Field(min_length=1, max_length=64)
    decision_id: str | None = Field(default=None, max_length=64)
    application_id: str = Field(min_length=1, max_length=36)
    subject_id: str = Field(min_length=1, max_length=255)
    request_id: str = Field(min_length=1, max_length=255)
    layer: Literal["layer1", "layer2"] = "layer1"
    result: str = Field(min_length=1, max_length=30)
    reason: str = Field(min_length=1, max_length=255)
    policy_version: int = Field(default=0, ge=0)
    resource_ids: list[str] = Field(default_factory=list, max_length=500)


class GuardAuditBatch(BaseModel):
    guard_id: str
    events: list[GuardAuditEventInput] = Field(min_length=1, max_length=100)


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


class MfaEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class MfaDisableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=64)


class InvitationCreate(BaseModel):
    email: EmailStr
    role: str = "ENGINEER"


class InvitationAccept(BaseModel):
    token: str


class MemberRoleUpdate(BaseModel):
    role: str


class RunnerCheckpointUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runner_id: str
    run_id: str
    checkpoint: dict[str, Any]


class ReleaseComparisonRequest(BaseModel):
    project_id: str
    candidate_release: str = Field(min_length=1, max_length=200)
    baseline_policy: str = "previous_successful"
    baseline_release: str | None = Field(default=None, max_length=200)
    maximum_absolute_regression_seconds: float | None = Field(default=30.0, ge=0)
    maximum_percentage_regression: float | None = Field(default=None, ge=0)
    block_on_inconclusive: bool = True


class RetentionPolicyUpdate(BaseModel):
    detailed_evidence_days: int = Field(default=90, ge=1, le=3650)
    report_days: int = Field(default=365, ge=1, le=3650)
    audit_days: int = Field(default=365, ge=1, le=3650)


class ProjectDeleteRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=200)


class OrganizationDeleteRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=200)


class SourceCredentialUpdate(BaseModel):
    credentials: dict[str, Any] = Field(default_factory=dict)


class RunnerAdminAction(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class OidcConfigurationUpdate(BaseModel):
    issuer_url: str = Field(min_length=8, max_length=1000)
    client_id: str = Field(min_length=1, max_length=500)
    client_secret: str = Field(min_length=1, max_length=4000)
    allowed_domains: list[str] = Field(default_factory=list)
    email_claim: str = Field(default="email", min_length=1, max_length=100)
    subject_claim: str = Field(default="sub", min_length=1, max_length=100)
    role_claim: str | None = Field(default=None, max_length=100)
    role_mapping: dict[str, str] = Field(default_factory=dict)
    default_role: str = "VIEWER"
    enforced: bool = False


class OidcBeginRequest(BaseModel):
    organization_id: str
    redirect_uri: str | None = Field(default=None, max_length=1000)


class OidcCallbackRequest(BaseModel):
    code: str = Field(min_length=1, max_length=4000)
    state: str = Field(min_length=1, max_length=1000)


class ScimConfigurationUpdate(BaseModel):
    default_role: str = "VIEWER"
    enabled: bool = True
