from __future__ import annotations
from sqlalchemy.orm import Session as OrmSession, SessionTransaction, Mapper
from sqlalchemy.engine import Connection

from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from apps.api.accessproof_api.config import settings


class Base(DeclarativeBase):
    pass


def _id() -> str:
    return str(uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def set_tenant_context(db: OrmSession, organization_id: str) -> None:
    """Attach tenant context to the ORM session and current PostgreSQL transaction.

    The session.info copy is critical because SET LOCAL/set_config(..., true) is
    cleared by COMMIT. The after_begin hook below reapplies the tenant to every
    subsequent transaction opened by the same request-scoped Session.
    """
    db.info["accessproof.organization_id"] = organization_id
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT set_config('accessproof.organization_id', :org_id, true)"),
            {"org_id": organization_id},
        )
        if not settings.rls_bypass:
            db.execute(text("SELECT set_config('accessproof.rls_bypass', 'off', true)"))


def _apply_rls_context(
    session: OrmSession, transaction: SessionTransaction, connection: Connection
) -> None:
    if connection.dialect.name != "postgresql":
        return
    bypass = bool(session.info.get("accessproof.rls_bypass", settings.rls_bypass))
    connection.execute(
        text("SELECT set_config('accessproof.rls_bypass', :value, true)"),
        {"value": "on" if bypass else "off"},
    )
    organization_id = session.info.get("accessproof.organization_id")
    if organization_id:
        connection.execute(
            text("SELECT set_config('accessproof.organization_id', :org_id, true)"),
            {"org_id": str(organization_id)},
        )


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(200))
    mutations_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(20))


class Invitation(Base):
    __tablename__ = "invitations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320), index=True)
    role: Mapped[str] = mapped_column(String(20))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    auth_method: Mapped[str] = mapped_column(String(20), default="password")
    auth_organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OneTimeToken(Base):
    __tablename__ = "one_time_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(50), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MfaMethod(Base):
    __tablename__ = "mfa_methods"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    encrypted_secret: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_hashes_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(200))
    scopes_json: Mapped[str] = mapped_column(Text, default="[]")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcConfiguration(Base):
    __tablename__ = "oidc_configurations"
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    issuer_url: Mapped[str] = mapped_column(String(1000))
    client_id: Mapped[str] = mapped_column(String(500))
    encrypted_client_secret: Mapped[str] = mapped_column(Text)
    allowed_domains_json: Mapped[str] = mapped_column(Text, default="[]")
    email_claim: Mapped[str] = mapped_column(String(100), default="email")
    subject_claim: Mapped[str] = mapped_column(String(100), default="sub")
    role_claim: Mapped[str | None] = mapped_column(String(100), nullable=True)
    role_mapping_json: Mapped[str] = mapped_column(Text, default="{}")
    default_role: Mapped[str] = mapped_column(String(20), default="VIEWER")
    enforced: Mapped[bool] = mapped_column(Boolean, default=False)
    discovery_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class OidcLoginState(Base):
    __tablename__ = "oidc_login_states"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_nonce: Mapped[str] = mapped_column(Text)
    encrypted_code_verifier: Mapped[str] = mapped_column(Text)
    redirect_uri: Mapped[str] = mapped_column(String(1000))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MicrosoftConsentState(Base):
    """One-time source consent state; no tokens or raw state are stored."""

    __tablename__ = "microsoft_consent_states"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    source_id: Mapped[str] = mapped_column(
        ForeignKey("source_connections.id", ondelete="CASCADE"), index=True
    )
    initiated_by_user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    config_fingerprint: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoogleSourceOAuthState(Base):
    """One-time tenant/source-bound Google consent transaction with PKCE."""

    __tablename__ = "google_source_oauth_states"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source_connections.id", ondelete="CASCADE"), index=True)
    initiated_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_verifier: Mapped[str] = mapped_column(Text)
    config_fingerprint: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcIdentity(Base):
    __tablename__ = "oidc_identities"
    __table_args__ = (
        UniqueConstraint("organization_id", "issuer", "subject", name="uq_oidc_identity_subject"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    issuer: Mapped[str] = mapped_column(String(1000), index=True)
    subject: Mapped[str] = mapped_column(String(500), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScimConfiguration(Base):
    __tablename__ = "scim_configurations"
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    default_role: Mapped[str] = mapped_column(String(20), default="VIEWER")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ScimIdentity(Base):
    __tablename__ = "scim_identities"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_scim_identity_user"),
        UniqueConstraint("organization_id", "user_name", name="uq_scim_identity_username"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    user_name: Mapped[str] = mapped_column(String(320), index=True)
    external_id: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ScimGroup(Base):
    __tablename__ = "scim_groups"
    __table_args__ = (
        UniqueConstraint("organization_id", "display_name", name="uq_scim_group_display_name"),
        UniqueConstraint("organization_id", "external_id", name="uq_scim_group_external_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    display_name: Mapped[str] = mapped_column(String(500), index=True)
    external_id: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    mapped_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ScimGroupMember(Base):
    __tablename__ = "scim_group_members"
    __table_args__ = (
        UniqueConstraint("group_id", "scim_identity_id", name="uq_scim_group_member"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    group_id: Mapped[str] = mapped_column(
        ForeignKey("scim_groups.id", ondelete="CASCADE"), index=True
    )
    scim_identity_id: Mapped[str] = mapped_column(
        ForeignKey("scim_identities.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceConnection(Base):
    __tablename__ = "source_connections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(200))
    boundary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="not_configured")
    mutation_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)
    capabilities_json: Mapped[str] = mapped_column(Text, default="{}")
    provider_identity_json: Mapped[str] = mapped_column(Text, default="{}")
    granted_scopes_json: Mapped[str] = mapped_column(Text, default="[]")
    missing_scopes_json: Mapped[str] = mapped_column(Text, default="[]")
    provider_api_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_capability_refresh_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class SourceEffectiveCertification(Base):
    """Signed, scope-specific live provider proof; not writable via customer API."""
    __tablename__ = "source_effective_certifications"
    __table_args__ = (UniqueConstraint("organization_id", "source_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source_connections.id", ondelete="CASCADE"), index=True)
    provider_profile: Mapped[str] = mapped_column(String(80))
    scope_digest: Mapped[str] = mapped_column(String(64))
    evidence_digest: Mapped[str] = mapped_column(String(64))
    verifier_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="unverified")
    certified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str] = mapped_column(String(64))


class ProviderSyncCursor(Base):
    """Tenant-scoped durable progress for a provider synchronization stream.

    Cursors are deliberately source-specific: a directory or ACL token from
    one customer/source must never be resumed against another boundary.
    """
    __tablename__ = "provider_sync_cursors"
    __table_args__ = (UniqueConstraint("organization_id", "source_id", "sync_kind"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source_connections.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50), index=True)
    sync_kind: Mapped[str] = mapped_column(String(50))
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_provider_revision: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="never_synced", index=True)
    last_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AITarget(Base):
    __tablename__ = "ai_targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(Text)
    runner_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)


class TestIdentity(Base):
    """A reusable, encrypted credential for a synthetic person used in a test."""
    __tablename__ = "test_identities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    provider_type: Mapped[str] = mapped_column(String(50), default="static_bearer")
    provider_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    subject_id: Mapped[str] = mapped_column(String(320))
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(320), nullable=True)
    issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    audience: Mapped[str | None] = mapped_column(String(500), nullable=True)
    required_scopes_json: Mapped[str] = mapped_column(Text, default="[]")
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="configured")
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    __table_args__ = (UniqueConstraint("project_id", "provider_type", "subject_id", name="uq_test_identity_subject"),)


class TestSuite(Base):
    __tablename__ = "test_suites"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    scenario_json: Mapped[str] = mapped_column(Text)


class Release(Base):
    __tablename__ = "releases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    git_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    environment: Mapped[str] = mapped_column(String(100), default="staging")
    deployment: Mapped[str | None] = mapped_column(String(200), nullable=True)
    connector_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    retrieval_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reranker_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRun(Base):
    __tablename__ = "test_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    suite_id: Mapped[str] = mapped_column(
        ForeignKey("test_suites.id", ondelete="RESTRICT"), index=True
    )
    source_connection_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    ai_target_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    allowed_identity_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    denied_identity_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    allowed_principal_json: Mapped[str] = mapped_column(Text, default="{}")
    denied_principal_json: Mapped[str] = mapped_column(Text, default="{}")
    release: Mapped[str] = mapped_column(String(200), default="manual")
    git_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Server-issued oracle material binds checkpoints and final evidence to this run.
    # It is never accepted from the runner or a browser client.
    oracle_canary: Mapped[str] = mapped_column(String(80), nullable=False, default=lambda: f"AP-CANARY-{uuid4()}")
    state: Mapped[str] = mapped_column(String(40), default="CREATED")
    outcome: Mapped[str | None] = mapped_column(String(40), nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    lease_owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunStateTransition(Base):
    __tablename__ = "run_state_transitions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(50))
    occurred_at: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    observed_at: Mapped[str] = mapped_column(String(64))
    exposed: Mapped[bool] = mapped_column(Boolean)
    evidence_level: Mapped[str | None] = mapped_column(String(60), nullable=True)
    matched_signal: Mapped[str | None] = mapped_column(String(100), nullable=True)
    response_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class SyntheticResourceRecord(Base):
    __tablename__ = "synthetic_resources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    provider_resource_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    marker: Mapped[str | None] = mapped_column(String(200), nullable=True)
    canary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("test_runs.id", ondelete="CASCADE"), unique=True, index=True
    )
    report_hash: Mapped[str] = mapped_column(String(64))
    signing_key_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signing_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    signed_manifest_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ControlPlaneReport(Base):
    """Immutable, tenant-scoped, signed evidence export.

    This is separate from legacy synthetic-run ``Report`` rows: its payload is
    derived from current control-plane state and machine-uploaded Guard audit
    metadata, never from a test run.
    """
    __tablename__ = "control_plane_reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    report_type: Mapped[str] = mapped_column(String(50), index=True)
    generated_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload_json: Mapped[str] = mapped_column(Text)
    report_hash: Mapped[str] = mapped_column(String(64))
    signing_key_id: Mapped[str] = mapped_column(String(200))
    signature: Mapped[str] = mapped_column(Text)
    signing_public_key: Mapped[str] = mapped_column(Text)
    signed_manifest_json: Mapped[str] = mapped_column(Text)


class Runner(Base):
    __tablename__ = "runners"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    credential_hash: Mapped[str] = mapped_column(String(64))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_job_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    credential_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    platform: Mapped[str | None] = mapped_column(String(80), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(80), nullable=True)
    capabilities_json: Mapped[str] = mapped_column(Text, default="{}")
    installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunnerRegistration(Base):
    __tablename__ = "runner_registrations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunnerCheckpoint(Base):
    __tablename__ = "runner_checkpoints"
    run_id: Mapped[str] = mapped_column(
        ForeignKey("test_runs.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    runner_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    phase: Mapped[str] = mapped_column(String(80), default="unknown", index=True)
    checkpoint_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class MutationJournal(Base):
    __tablename__ = "mutation_journal"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    operation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    principal: Mapped[str | None] = mapped_column(String(320), nullable=True)
    mutation_type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40), default="requested", index=True)
    pre_state_json: Mapped[str] = mapped_column(Text, default="{}")
    post_state_json: Mapped[str] = mapped_column(Text, default="{}")
    requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provider_request_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    retry_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CleanupTask(Base):
    __tablename__ = "cleanup_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50))
    provider_resource_id: Mapped[str] = mapped_column(String(500))
    resource_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AlertRecord(Base):
    __tablename__ = "alert_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    dedupe_key: Mapped[str] = mapped_column(String(300), unique=True, index=True)
    subject: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    organization_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    detailed_evidence_days: Mapped[int] = mapped_column(default=90)
    report_days: Mapped[int] = mapped_column(default=365)
    audit_days: Mapped[int] = mapped_column(default=365)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class DeletionReceipt(Base):
    __tablename__ = "deletion_receipts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id_hash: Mapped[str] = mapped_column(String(64), index=True)
    actor_user_id_hash: Mapped[str] = mapped_column(String(64))
    organization_name_hash: Mapped[str] = mapped_column(String(64))
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EmailOutbox(Base):
    __tablename__ = "email_outbox"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    recipient: Mapped[str] = mapped_column(String(320), index=True)
    template: Mapped[str] = mapped_column(String(80), index=True)
    subject: Mapped[str] = mapped_column(String(300))
    encrypted_payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    url: Mapped[str] = mapped_column(Text)
    secret_hash: Mapped[str] = mapped_column(String(64))
    encrypted_secret: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    attempts_json: Mapped[str] = mapped_column(Text, default="[]")
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Entitlement(Base):
    __tablename__ = "entitlements"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    key: Mapped[str] = mapped_column(String(100), index=True)
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(50), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UsageRecord(Base):
    __tablename__ = "usage_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    metric: Mapped[str] = mapped_column(String(100), index=True)
    quantity: Mapped[str] = mapped_column(String(50))
    period: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProviderEventSubscription(Base):
    """A provider watch channel bound to exactly one tenant source."""
    __tablename__ = "provider_event_subscriptions"
    __table_args__ = (UniqueConstraint("provider", "channel_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source_connections.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50), index=True)
    channel_type: Mapped[str] = mapped_column(String(50), default="acl")
    channel_id: Mapped[str] = mapped_column(String(255))
    provider_resource_id: Mapped[str] = mapped_column(String(1024))
    encrypted_channel_token: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="active", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_notification_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_successful_processing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ProviderEventJournal(Base):
    """Durable provider notification hint; never itself an authorization record."""
    __tablename__ = "provider_event_journal"
    __table_args__ = (UniqueConstraint("organization_id", "dedupe_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source_connections.id", ondelete="CASCADE"), index=True)
    subscription_id: Mapped[str] = mapped_column(ForeignKey("provider_event_subscriptions.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50), index=True)
    event_type: Mapped[str] = mapped_column(String(50))
    provider_message_number: Mapped[str] = mapped_column(String(128))
    dedupe_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="received", index=True)
    attempts: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    processing_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)



class GuardSubject(Base):
    __tablename__ = "guard_subjects"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "provider_subject_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50))
    provider_subject_id: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    primary_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GuardIdentityMapping(Base):
    """Verified bridge from an employee OIDC principal to a source identity.

    A mapping deliberately uses immutable issuer/subject values and a resolved
    source-side subject.  Mutable email addresses are presentation metadata,
    never proof of authorization.
    """
    __tablename__ = "guard_identity_mappings"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source_id", "oidc_issuer", "oidc_subject", "oidc_tenant_id",
            name="uq_guard_identity_mapping_principal",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source_connections.id", ondelete="CASCADE"), index=True)
    oidc_issuer: Mapped[str] = mapped_column(String(1000), index=True)
    oidc_subject: Mapped[str] = mapped_column(String(500), index=True)
    oidc_tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True, default="")
    source_subject_id: Mapped[str] = mapped_column(ForeignKey("guard_subjects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="VERIFIED", index=True)
    method: Mapped[str] = mapped_column(String(50), default="admin_verified")
    verified_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GuardResource(Base):
    __tablename__ = "guard_resources"
    __table_args__ = (UniqueConstraint("organization_id", "source_id", "provider_resource_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    provider_resource_id: Mapped[str] = mapped_column(String(512))
    parent_resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(50), default="document")
    scope: Mapped[str] = mapped_column(String(100), default="read")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Independent from delta-feed sync time: durable fair ACL reconciliation.
    last_reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class GuardPermissionEvent(Base):
    __tablename__ = "guard_permission_events"
    __table_args__ = (UniqueConstraint("organization_id", "dedupe_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    provider: Mapped[str] = mapped_column(String(50))
    provider_revision: Mapped[int] = mapped_column(default=0)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    resource_id: Mapped[str] = mapped_column(String(36), index=True)
    change_type: Mapped[str] = mapped_column(String(30))
    dedupe_key: Mapped[str] = mapped_column(String(128))
    processing_status: Mapped[str] = mapped_column(String(30), default="received")
    mutation_json: Mapped[str] = mapped_column(Text, default="{}")
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    processing_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardPolicy(Base):
    __tablename__ = "guard_policies"
    __table_args__ = (UniqueConstraint("organization_id", "policy_key", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    policy_key: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[int] = mapped_column(default=1)
    mode: Mapped[str] = mapped_column(String(20), default="shadow")
    decision: Mapped[str] = mapped_column(String(20))
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    resource_id: Mapped[str] = mapped_column(String(36), index=True)
    reason: Mapped[str] = mapped_column(String(255), default="effective_access")
    source_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    scope: Mapped[str] = mapped_column(String(100), default="read")
    source_revision: Mapped[int] = mapped_column(default=0)
    effective_state_version: Mapped[int] = mapped_column(default=0)
    supersedes_policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardPolicySequence(Base):
    """One durable, tenant-scoped allocator for immutable Guard policy versions."""
    __tablename__ = "guard_policy_sequences"
    __table_args__ = (UniqueConstraint("organization_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    next_version: Mapped[int] = mapped_column(default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GuardEffectiveAccess(Base):
    __tablename__ = "guard_effective_access"
    __table_args__ = (UniqueConstraint("organization_id", "source_id", "subject_id", "resource_id", "scope"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    resource_id: Mapped[str] = mapped_column(String(36), index=True)
    scope: Mapped[str] = mapped_column(String(100), default="read")
    decision: Mapped[str] = mapped_column(String(20))
    source_revision: Mapped[int] = mapped_column(default=0)
    state_version: Mapped[int] = mapped_column(default=1)
    reason: Mapped[str] = mapped_column(String(255), default="effective_access")
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardProtectionDecision(Base):
    __tablename__ = "guard_protection_decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    guard_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    application_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    request_id: Mapped[str] = mapped_column(String(255), index=True)
    policy_version: Mapped[int] = mapped_column(default=0)
    mode: Mapped[str] = mapped_column(String(20))
    result: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(String(255))
    resources_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardAuditEvent(Base):
    """Idempotently uploaded metadata-only Guard decision audit record."""
    __tablename__ = "guard_audit_events"
    __table_args__ = (UniqueConstraint("guard_id", "event_id", name="uq_guard_audit_event"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    guard_id: Mapped[str] = mapped_column(ForeignKey("guard_registrations.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(String(64))
    decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    application_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_id: Mapped[str] = mapped_column(String(255), index=True)
    request_id: Mapped[str] = mapped_column(String(255), index=True)
    layer: Mapped[str] = mapped_column(String(20), default="layer1")
    result: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(String(255))
    policy_version: Mapped[int] = mapped_column(default=0)
    authorization_revision: Mapped[int | None] = mapped_column(nullable=True)
    authorization_revision_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resources_json: Mapped[str] = mapped_column(Text, default="[]")
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthorizationRevisionSequence(Base):
    """Tenant/application-scoped allocator for monotonic authorization revisions."""
    __tablename__ = "authorization_revision_sequences"
    __table_args__ = (UniqueConstraint("organization_id", "application_row_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    application_row_id: Mapped[str] = mapped_column(ForeignKey("ai_applications.id", ondelete="CASCADE"), index=True)
    next_revision: Mapped[int] = mapped_column(default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AuthorizationRevision(Base):
    """Signed binding of one application decision boundary to exact source state.

    ``state_hash`` covers only stable authorization inputs. A control-plane poll
    that observes the same state reuses the existing revision; any ACL,
    directory, policy, route or binding change allocates a new monotonic one.
    """
    __tablename__ = "authorization_revisions"
    __table_args__ = (UniqueConstraint("organization_id", "application_row_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    application_row_id: Mapped[str] = mapped_column(ForeignKey("ai_applications.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[str] = mapped_column(String(255), index=True)
    source_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    guard_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revision: Mapped[int] = mapped_column()
    state_hash: Mapped[str] = mapped_column(String(64), index=True)
    revision_hash: Mapped[str] = mapped_column(String(64), unique=True)
    previous_revision_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text)
    signing_key_id: Mapped[str] = mapped_column(String(200))
    signature: Mapped[str] = mapped_column(Text)
    signing_public_key: Mapped[str] = mapped_column(Text)
    signed_manifest_json: Mapped[str] = mapped_column(Text)
    source_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardRegistration(Base):
    __tablename__ = "guard_registrations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    environment: Mapped[str] = mapped_column(String(50), default="production")
    status: Mapped[str] = mapped_column(String(30), default="pending")
    version: Mapped[str] = mapped_column(String(50), default="0.1.0")
    active_policy_version: Mapped[int] = mapped_column(default=0)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_policy_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health: Mapped[str] = mapped_column(String(30), default="not_enrolled")
    active_authorization_revisions_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    credential_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIApplication(Base):
    """Tenant-owned AI surface whose enforcement mode is backend controlled."""
    __tablename__ = "ai_applications"
    __table_args__ = (UniqueConstraint("organization_id", "application_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(20), default="shadow")
    guard_id: Mapped[str | None] = mapped_column(ForeignKey("guard_registrations.id", ondelete="SET NULL"), nullable=True, index=True)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("source_connections.id", ondelete="SET NULL"), nullable=True, index=True)
    adapter_type: Mapped[str] = mapped_column(String(50), default="generic-python", server_default="generic-python")
    adapter_contract_version: Mapped[str] = mapped_column(String(50), default="accessproof.rag/v1", server_default="accessproof.rag/v1")
    layer1_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    layer2_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provenance_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    buffering_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProtectionActivationRun(Base):
    """Durable, tenant-bound automatic preflight state; not authorization proof.

    Never mark a run active until a separate machine-authenticated customer RAG
    challenge and enrolled Guard Protect acknowledgement protocol is available.
    """
    __tablename__ = "protection_activation_runs"
    __table_args__ = (UniqueConstraint("organization_id", "application_row_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    application_row_id: Mapped[str] = mapped_column(ForeignKey("ai_applications.id", ondelete="CASCADE"), index=True)
    requested_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    state: Mapped[str] = mapped_column(String(32), default="action_required")
    guard_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    configuration_fingerprint: Mapped[str] = mapped_column(String(64))
    checks_json: Mapped[str] = mapped_column(Text, default="[]")
    reason_code: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RAGRouteChallenge(Base):
    """Nonce-bound machine-submitted reference-route evidence.

    Certification must still be paired with exact Guard audit decisions and
    current source readiness; this record alone grants no Protect access.
    """
    __tablename__ = "rag_route_challenges"
    __table_args__ = (UniqueConstraint("organization_id", "application_row_id", "nonce_digest"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    application_row_id: Mapped[str] = mapped_column(ForeignKey("ai_applications.id", ondelete="CASCADE"), index=True)
    guard_id: Mapped[str] = mapped_column(ForeignKey("guard_registrations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(36))
    nonce_digest: Mapped[str] = mapped_column(String(64), unique=True)
    configuration_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="issued")
    deployment_sha256: Mapped[str] = mapped_column(String(64))
    route_sha256: Mapped[str] = mapped_column(String(64))
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cutover_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GuardEnrollment(Base):
    __tablename__ = "guard_enrollments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    guard_id: Mapped[str] = mapped_column(ForeignKey("guard_registrations.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardGroup(Base):
    __tablename__ = "guard_groups"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "provider_group_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50))
    provider_group_id: Mapped[str] = mapped_column(String(255))
    provider_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GuardGroupMembership(Base):
    __tablename__ = "guard_group_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "group_id", "subject_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("guard_groups.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[str] = mapped_column(ForeignKey("guard_subjects.id", ondelete="CASCADE"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    provider_revision: Mapped[int] = mapped_column(default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GuardPermissionGrant(Base):
    __tablename__ = "guard_permission_grants"
    __table_args__ = (UniqueConstraint("organization_id", "source_id", "grant_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    resource_id: Mapped[str] = mapped_column(ForeignKey("guard_resources.id", ondelete="CASCADE"), index=True)
    grant_key: Mapped[str] = mapped_column(String(255))
    principal_type: Mapped[str] = mapped_column(String(30))
    principal_id: Mapped[str] = mapped_column(String(36), index=True)
    effect: Mapped[str] = mapped_column(String(10), default="allow")
    scope: Mapped[str] = mapped_column(String(100), default="read")
    inherited_from_resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    access_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    provider_revision: Mapped[int] = mapped_column(default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardPermissionSnapshot(Base):
    __tablename__ = "guard_permission_snapshots"
    __table_args__ = (UniqueConstraint("effective_access_id", "state_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    effective_access_id: Mapped[str] = mapped_column(ForeignKey("guard_effective_access.id", ondelete="CASCADE"), index=True)
    permission_event_id: Mapped[str] = mapped_column(ForeignKey("guard_permission_events.id", ondelete="CASCADE"), index=True)
    state_version: Mapped[int] = mapped_column(default=1)
    source_revision: Mapped[int] = mapped_column(default=0)
    decision: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(255))
    grant_keys_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuardPolicyDistribution(Base):
    __tablename__ = "guard_policy_distributions"
    __table_args__ = (UniqueConstraint("policy_id", "guard_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("guard_policies.id", ondelete="CASCADE"), index=True)
    guard_id: Mapped[str | None] = mapped_column(ForeignKey("guard_registrations.id", ondelete="CASCADE"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    guard_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    guard_installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str] = mapped_column(String(100))
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _reject_audit_mutation(
    mapper: Mapper[AuditEvent], connection: Connection, target: AuditEvent
) -> None:
    raise RuntimeError(
        "Audit events are append-only; use the explicit retention/deletion workflow for policy-driven purge"
    )


event.listen(AuditEvent, "before_update", _reject_audit_mutation)
event.listen(AuditEvent, "before_delete", _reject_audit_mutation)


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
event.listen(SessionLocal, "after_begin", _apply_rls_context)


def init_db() -> None:
    Base.metadata.create_all(engine)
