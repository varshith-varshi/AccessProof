from __future__ import annotations
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from collections import OrderedDict
from packages.connector_sdk.base import SourceAdapter
from packages.capability_registry import snapshot as capability_registry_snapshot
from packages.rag_core import adapter_registry
from apps.api.accessproof_api.rag_challenge_verifier import verify_reference_evidence, request_ids
from apps.api.accessproof_api import gateway_pairing
from apps.api.accessproof_api import verification_engine
from apps.api.accessproof_api import gateway_presence
from apps.api.accessproof_api.source_certification import effective_source_certified, _source_scope
from apps.api.accessproof_api.protection_state import (
    PROTECTION_STATES,
    STATE_MESSAGES,
    classify_protection_state,
)
from apps.api.accessproof_api.route_certification import (
    describe_route_certificate,
    reference_route_tested as _reference_challenge_tested,
    route_configuration_fingerprint as _route_configuration_fingerprint,
    valid_route_certificate as _valid_route_certificate,
)

from typing import Any, TypedDict

import json
import re
import gzip
import asyncio
from dataclasses import asdict
import hashlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from threading import Lock
from uuid import uuid4
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, PlainTextResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from apps.api.accessproof_api.auth import (
    Actor,
    create_session,
    current_actor,
    current_user,
    get_db,
    require,
)
from apps.api.accessproof_api.config import (
    V1ProviderScopeError,
    enforce_v1_browser_credential_policy,
    enforce_source_onboarding_provider,
    settings,
    validate_production_settings,
    v1_source_provider_allowed,
    certified_sharepoint_scope_allowed,
)
from apps.api.accessproof_api.db import (
    AITarget,
    AlertRecord,
    ApiKey,
    AuditEvent,
    DeletionReceipt,
    EmailOutbox,
    Entitlement,
    EvidenceItem,
    Invitation,
    Membership,
    MfaMethod,
    OneTimeToken,
    OidcConfiguration,
    OidcLoginState,
    OidcIdentity,
    MicrosoftConsentState, GoogleSourceOAuthState,
    ScimConfiguration,
    ScimIdentity,
    ScimGroup,
    ScimGroupMember,
    Organization,
    Project,
    Release,
    Report,
    ControlPlaneReport,
    RetentionPolicy,
    RunStateTransition,
    Runner,
    RunnerRegistration,
    RunnerCheckpoint,
    MutationJournal,
    CleanupTask,
    SyntheticResourceRecord,
    UsageRecord,
    GuardSubject,
    GuardIdentityMapping,
    GuardGroup,
    GuardGroupMembership,
    GuardResource,
    GuardPermissionEvent,
    GuardEnrollment,
    GuardRegistration,
    GuardPolicy,
    GuardPolicyDistribution,
    GuardEffectiveAccess,
    GuardAuditEvent,
    GuardProtectionDecision,
    AuthorizationRevision,
    AIApplication,
    VerificationEvent, VerificationRun, VerificationApproval, GuardPresenceLease, SessionLocal,
    AIApplicationSourceBinding,
    ProtectionActivationRun,
    RAGRouteChallenge,
    WebhookDelivery,
    WebhookEndpoint,
    Session as DbSession,
    SourceConnection,
    ProviderSyncCursor as ProviderSyncCursorModel,
    TestIdentity,
    TestRun,
    TestSuite,
    User,
    set_tenant_context,
)
from apps.api.accessproof_api.schemas import (
    OrganizationRename,
    SignupRequest as SignupRequest,
    LoginRequest as LoginRequest,
    ProjectCreate as ProjectCreate,
    SourceCreate as SourceCreate,
    CurrentSourceCreate as CurrentSourceCreate,
    TargetCreate as TargetCreate,
    TestIdentityCreate as TestIdentityCreate,
    TestIdentityCredentialUpdate as TestIdentityCredentialUpdate,
    SuiteCreate as SuiteCreate,
    RunCreate as RunCreate,
    RunnerRegistrationCreate as RunnerRegistrationCreate,
    RunnerExchange as RunnerExchange,
    RunnerHeartbeat as RunnerHeartbeat,
    RunnerLeaseRequest as RunnerLeaseRequest,
    RunnerCompleteRequest as RunnerCompleteRequest,
    ApiKeyCreate as ApiKeyCreate,
    ReleaseCreate as ReleaseCreate,
    WebhookCreate as WebhookCreate,
    EmailVerifyRequest as EmailVerifyRequest,
    ForgotPasswordRequest as ForgotPasswordRequest,
    ResendVerificationRequest as ResendVerificationRequest,
    GuardEventCreate as GuardEventCreate,
    GuardFilterRequest as GuardFilterRequest,
    GuardCreate as GuardCreate,
    GuardEnrollmentCreate as GuardEnrollmentCreate,
    GuardExchange as GuardExchange,
    GuardHeartbeat as GuardHeartbeat,
    GuardPolicyAck as GuardPolicyAck,
    GuardIdentityMappingCreate as GuardIdentityMappingCreate,
    GuardIdentityMappingStatusUpdate as GuardIdentityMappingStatusUpdate,
    GuardAuditBatch as GuardAuditBatch,
    AIApplicationCreate as AIApplicationCreate,
    AIApplicationModeUpdate as AIApplicationModeUpdate,
    AIApplicationVerification as AIApplicationVerification,
    ControlPlaneReportCreate as ControlPlaneReportCreate,
    RouteChallengeStart as RouteChallengeStart,
    RouteChallengeResult as RouteChallengeResult,
    RouteCutoverEvidence as RouteCutoverEvidence,
    ResetPasswordRequest as ResetPasswordRequest,
    ChangePasswordRequest as ChangePasswordRequest,
    MfaEnableRequest as MfaEnableRequest,
    MfaDisableRequest as MfaDisableRequest,
    InvitationCreate as InvitationCreate,
    InvitationAccept as InvitationAccept,
    MemberRoleUpdate as MemberRoleUpdate,
    RunnerCheckpointUpdate as RunnerCheckpointUpdate,
    ReleaseComparisonRequest as ReleaseComparisonRequest,
    RetentionPolicyUpdate as RetentionPolicyUpdate,
    ProjectDeleteRequest as ProjectDeleteRequest,
    OrganizationDeleteRequest as OrganizationDeleteRequest,
    SourceCredentialUpdate as SourceCredentialUpdate,
    RunnerAdminAction as RunnerAdminAction,
    OidcConfigurationUpdate as OidcConfigurationUpdate,
    OidcBeginRequest as OidcBeginRequest,
    OidcCallbackRequest as OidcCallbackRequest,
    ScimConfigurationUpdate as ScimConfigurationUpdate,
)
from packages.crypto.passwords import hash_password, verify_password
from packages.crypto.totp import generate_totp_secret, matched_totp_step, provisioning_uri
from packages.crypto.secrets import build_secret_backend, hash_token
from packages.crypto.signing import Ed25519Signer, verify_manifest, verify_manifest_with_trust
from packages.auth.oidc import OidcDiscovery, OidcError, OidcProviderClient
from packages.auth.microsoft_consent import (
    MicrosoftConsentError, authorization_url as microsoft_consent_url,
    graph_app_token, tenant_uuid,
)
from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import ProviderUnavailableError, AuthorizationError
from connectors.google_drive.adapter import GoogleDriveAdapter
from packages.auth.google_consent import (
    GoogleConsentError, authorization_url as google_consent_url, exchange_code as exchange_google_code,
)
from packages.domain.rbac import Permission, Role
from packages.domain.scenario import ScenarioDefinition
from packages.test_engine.regression import (
    BaselinePolicy,
    ScenarioMeasurement,
    compare_measurements,
    decide_release,
)
from packages.connector_sdk.http_target import validate_cloud_url
from connectors.factory import create_source_adapter
from apps.api.accessproof_api.directory_sync import synchronize_directory
from connectors.directory import DirectorySyncError
from packages.reporting.report import (
    render_html_payload,
    render_junit_payload,
    render_pdf_payload,
    render_sarif_payload,
)
from apps.api.accessproof_api.observability import (
    active_requests,
    api_latency,
    api_requests,
    log_request,
    metrics_payload,
    run_outcomes,
    propagation_latency,
    exposure_window,
    runner_leases,
    runner_heartbeats,
    run_queue_depth,
    runner_health,
    runner_heartbeat_max_age,
    cleanup_queue_depth,
    webhook_queue_depth,
    email_queue_depth,
    source_connection_health,
    authz_decisions,
    guard_revision_lag,
    source_freshness,
    directory_freshness,
    provider_event_lag,
    route_certificate_age,
    protected_route_coverage,
    cache_reauth,
    layer2_blocks,
    revocation_end_to_end,
    bounded_reason,
    logger,
)
from apps.api.accessproof_api.retention import apply_retention, get_or_create_policy
from apps.api.accessproof_api.event_sync import NotificationRejected, accept_google_notification, accept_microsoft_notifications
from apps.api.accessproof_api.authorization_revision import (
    AUTHORIZATION_REVISION_SCHEMA,
    REVISION_LIMITATIONS,
    issue_or_reuse_revision,
    latest_revision,
    revision_envelope,
)
from apps.api.accessproof_api.revocation_timeline import build_timeline as build_revocation_timeline
from apps.api.accessproof_api.alerts import queue_alert
from packages.observability.tracing import configure_tracing


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    validate_production_settings(settings)
    configure_tracing("accessproof-api")
    # Database schema is migration-driven in every environment. Test fixtures may
    # build disposable schemas explicitly, but runtime services never call create_all().
    yield


app = FastAPI(
    title=settings.product_name,
    version="0.1.0",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Organization-ID",
        "X-CSRF-Token",
        "Idempotency-Key",
        "X-Request-ID",
    ],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

_secret_box = build_secret_backend(
    backend=settings.secret_backend,
    local_key=settings.secret_encryption_key,
    aws_kms_key_id=settings.aws_kms_key_id,
    aws_region=settings.aws_region,
)
_report_signer = Ed25519Signer.from_secret(settings.report_signing_key)
_AUTH_MAX_BUCKETS = 4096
_auth_attempts: OrderedDict[str, list[float]] = OrderedDict()
_auth_attempts_lock = Lock()


def _limit_auth_request(request: Request, action: str, limit: int, window_seconds: int, discriminator: str = "") -> None:
    """Bound auth request bursts and memory, without storing raw account IDs."""
    if settings.env != "production":
        return
    client = request.client.host if request.client else "unknown"
    digest = hashlib.sha256(discriminator.strip().lower().encode()).hexdigest()[:16] if discriminator else ""
    key = f"{action}:{client}:{digest}"
    network_key = f"{action}:{client}:ALL"
    # Allow high-volume legitimate NATs, while closing the unlimited unique-
    # account brute-force path that a per-email limiter alone leaves open.
    network_limit = max(500, limit * 100)
    now = time.monotonic()
    with _auth_attempts_lock:
        for bucket, threshold in ((network_key, network_limit), (key, limit)):
            recent = [t for t in _auth_attempts.get(bucket, []) if t > now - window_seconds]
            if len(recent) >= threshold:
                raise HTTPException(429, "Too many requests. Please try again shortly.")
        for bucket in dict.fromkeys((network_key, key)):
            recent = [t for t in _auth_attempts.get(bucket, []) if t > now - window_seconds]
            recent.append(now)
            _auth_attempts[bucket] = recent
            _auth_attempts.move_to_end(bucket)
        if len(_auth_attempts) > _AUTH_MAX_BUCKETS:
            # Expire dormant identities; cap the remainder to avoid attacker-
            # controlled memory growth even across many distinct client IPs.
            for bucket, recent in list(_auth_attempts.items()):
                if not recent or recent[-1] <= now - 3600:
                    _auth_attempts.pop(bucket, None)
            while len(_auth_attempts) > _AUTH_MAX_BUCKETS:
                _auth_attempts.popitem(last=False)


def _issue_email_verification(db: OrmSession, user: User, organization_id: str) -> str:
    now = datetime.now(timezone.utc)
    for previous in db.scalars(
        select(OneTimeToken).where(
            OneTimeToken.user_id == user.id,
            OneTimeToken.purpose == "email_verify",
            OneTimeToken.used_at.is_(None),
        )
    ):
        previous.used_at = now
    raw = secrets.token_urlsafe(32)
    db.add(
        OneTimeToken(
            user_id=user.id,
            purpose="email_verify",
            token_hash=hash_token(raw),
            expires_at=now + timedelta(hours=24),
        )
    )
    _queue_email(
        db,
        recipient=user.email,
        organization_id=organization_id,
        template="verify_email",
        subject=f"Verify your {settings.product_name} email",
        text_body=(
            f"Welcome to {settings.product_name}.\n\n"
            "Verify your email address to activate your account:\n"
            # Keep the link aligned with the web-v2 route.  The API endpoint
            # is `/api/v1/auth/verify-email`, while the user-facing page is
            # `/verify`; linking to the API path directly leaves users at a
            # 404 page instead of submitting the token.
            f"{settings.public_app_url.rstrip('/')}/verify?token={raw}\n\n"
            "If you did not create this account, you can ignore this email."
        ),
    )
    return raw
_ALLOWED_API_KEY_SCOPES = {
    "projects:read",
    "projects:write",
    "runs:read",
    "runs:create",
    "reports:read",
    "sources:read",
    "sources:write",
    "targets:read",
    "targets:write",
    "suites:read",
    "suites:write",
    "releases:read",
    "releases:write",
    "runners:read",
    "runners:write",
    "audit:read",
    "webhooks:manage",
    "entitlements:read",
    "api_keys:manage",
}


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    correlation_id = request.headers.get("X-Request-ID") or str(uuid4())
    started = time.perf_counter()
    active_requests.inc()
    try:
        response = await call_next(request)
    finally:
        active_requests.dec()
    duration = time.perf_counter() - started
    route = request.url.path
    api_requests.labels(request.method, route, str(response.status_code)).inc()
    api_latency.labels(request.method, route).observe(duration)
    log_request(
        correlation_id=correlation_id,
        method=request.method,
        path=route,
        status=response.status_code,
        duration_seconds=duration,
    )
    response.headers["X-Request-ID"] = correlation_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    if settings.env == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _audit(
    db: OrmSession,
    actor: Actor | None,
    org_id: str,
    action: str,
    target_type: str,
    target_id: str | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    event = AuditEvent(
        organization_id=org_id,
        actor_user_id=actor.user.id if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        metadata_json=json.dumps(metadata or {}, sort_keys=True),
    )
    db.add(event)


def _queue_email(
    db: OrmSession,
    *,
    recipient: str,
    template: str,
    subject: str,
    text_body: str,
    organization_id: str | None = None,
) -> None:
    # One-time tokens are encrypted before persistence; the worker decrypts only
    # immediately before delivery. They are never written to application logs.
    db.add(
        EmailOutbox(
            organization_id=organization_id,
            recipient=recipient.lower(),
            template=template,
            subject=subject,
            encrypted_payload=_secret_box.encrypt(
                json.dumps({"text_body": text_body}, sort_keys=True)
            ),
            status="pending",
            attempts=0,
            next_attempt_at=datetime.now(timezone.utc),
        )
    )


def _project_for_actor(db: OrmSession, actor: Actor, project_id: str) -> Project:
    project = db.scalar(
        select(Project).where(
            Project.id == project_id, Project.organization_id == actor.membership.organization_id
        )
    )
    if not project:
        raise HTTPException(404, "Project not found")
    return project


def _version_tuple(value: str | None) -> tuple[int, ...]:
    if not value:
        return (0,)
    core = value.split("+", 1)[0].split("-", 1)[0]
    parts: list[int] = []
    for piece in core.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            return (0,)
    return tuple(parts) or (0,)


def _runner_version_compatible(version: str | None) -> bool:
    return _version_tuple(version) >= _version_tuple(settings.minimum_runner_version)


def _provider_api_version(adapter: SourceAdapter) -> str | None:
    for name in ("GRAPH", "API", "api_version"):
        value = getattr(adapter, name, None)
        if value:
            return str(value)
    return None


def _configured_scopes(credentials: dict[str, Any]) -> list[str]:
    raw = credentials.get("scopes")
    if raw is None:
        return []
    if isinstance(raw, str):
        return sorted({item for item in raw.replace(",", " ").split() if item})
    if isinstance(raw, (list, tuple, set)):
        return sorted({str(item) for item in raw if str(item)})
    return []


def _source_payload(row: SourceConnection) -> dict[str, Any]:
    return {
        "id": row.id,
        "provider": row.provider,
        "name": row.name,
        "boundary": row.boundary,
        "status": row.status,
        "mutation_acknowledged": row.mutation_acknowledged,
        "capabilities": json.loads(row.capabilities_json or "{}"),
        "provider_identity": json.loads(row.provider_identity_json or "{}"),
        "granted_scopes": json.loads(row.granted_scopes_json or "[]"),
        "missing_scopes": json.loads(row.missing_scopes_json or "[]"),
        "provider_api_version": row.provider_api_version,
        "last_validated_at": row.last_validated_at.isoformat() if row.last_validated_at else None,
        "last_capability_refresh_at": row.last_capability_refresh_at.isoformat()
        if row.last_capability_refresh_at
        else None,
        "last_error": row.last_error,
    }


_CURRENT_PRODUCT_WORKSPACE = "__accessproof_current_product__"


def _current_product_workspace(db: OrmSession, organization_id: str) -> Project:
    """Return an invisible legacy-compatibility workspace for an organization."""
    project = db.scalar(select(Project).where(
        Project.organization_id == organization_id,
        Project.name == _CURRENT_PRODUCT_WORKSPACE,
    ))
    if project is None:
        project = Project(organization_id=organization_id, name=_CURRENT_PRODUCT_WORKSPACE)
        db.add(project)
        db.flush()
    return project


@app.get("/health/live")
def live() -> dict[str, Any]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    try:
        db.execute(select(Organization.id).limit(1))
    except Exception as exc:
        raise HTTPException(503, "database unavailable") from exc
    dependencies = {"database": "ok"}
    if settings.redis_url:
        try:
            from redis import Redis

            client = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
            client.ping()
            client.close()
            dependencies["redis"] = "ok"
        except Exception as exc:
            raise HTTPException(503, "redis unavailable") from exc
    return {"status": "ready", "dependencies": dependencies}


def _refresh_database_metrics(db: OrmSession) -> None:
    for state in ("CREATED", "LEASED", "RUNNING", "RUNNER_DISCONNECTED"):
        count = (
            db.scalar(
                select(func.count(TestRun.id)).where(
                    TestRun.outcome.is_(None), TestRun.state == state
                )
            )
            or 0
        )
        run_queue_depth.labels(state).set(float(count))
    now = datetime.now(timezone.utc)
    health_counts = {"online": 0, "offline": 0, "disabled": 0, "revoked": 0}
    ages: list[float] = []
    for runner in db.scalars(select(Runner)):
        if runner.revoked:
            health_counts["revoked"] += 1
            continue
        if runner.disabled:
            health_counts["disabled"] += 1
            continue
        heartbeat = runner.last_heartbeat_at
        if heartbeat and heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        age = (now - heartbeat).total_seconds() if heartbeat else None
        if age is not None:
            ages.append(max(0.0, age))
        health_counts[
            "online" if age is not None and age <= settings.runner_offline_seconds else "offline"
        ] += 1
    for health, count in health_counts.items():
        runner_health.labels(health).set(float(count))
    runner_heartbeat_max_age.set(max(ages) if ages else 0.0)
    for status in ("pending", "retry", "running", "failed", "completed"):
        count = (
            db.scalar(select(func.count(CleanupTask.id)).where(CleanupTask.status == status)) or 0
        )
        cleanup_queue_depth.labels(status).set(float(count))
    for status in ("pending", "retry", "delivering", "failed", "delivered", "disabled"):
        count = (
            db.scalar(
                select(func.count(WebhookDelivery.id)).where(WebhookDelivery.status == status)
            )
            or 0
        )
        webhook_queue_depth.labels(status).set(float(count))
    for status in ("pending", "retry", "delivering", "failed", "delivered"):
        count = (
            db.scalar(select(func.count(EmailOutbox.id)).where(EmailOutbox.status == status)) or 0
        )
        email_queue_depth.labels(status).set(float(count))
    statuses = set(db.scalars(select(SourceConnection.status)).all()) | {
        "not_configured",
        "connected",
        "error",
        "disconnected",
    }
    for status in statuses:
        count = (
            db.scalar(
                select(func.count(SourceConnection.id)).where(SourceConnection.status == status)
            )
            or 0
        )
        source_connection_health.labels(status).set(float(count))
    _refresh_authorization_metrics(db, now)


def _refresh_authorization_metrics(db: OrmSession, now: datetime) -> None:
    """Populate authorization/route gauges from retained evidence.

    A gauge without a sample means no evidence was retained; it is never
    fabricated as zero. Ages are worst-case values so a single stale source or
    certificate is visible without exposing tenant or resource identifiers.
    """
    acl_ages: dict[str, float] = {}
    directory_ages: dict[str, float] = {}
    for cursor, source in db.execute(
        select(ProviderSyncCursorModel, SourceConnection).join(
            SourceConnection, SourceConnection.id == ProviderSyncCursorModel.source_id,
        ).where(
            ProviderSyncCursorModel.organization_id == SourceConnection.organization_id,
        )
    ):
        if (cursor.status != "connected" or cursor.last_success_at is None
                or cursor.last_error_code):
            continue
        synced_at = _utc(cursor.last_success_at)
        if synced_at is None:
            continue
        age = max(0.0, (now - synced_at).total_seconds())
        provider = source.provider.lower()
        if cursor.sync_kind == "acl":
            acl_ages[provider] = max(acl_ages.get(provider, 0.0), age)
        elif cursor.sync_kind == "directory":
            directory_ages[provider] = max(directory_ages.get(provider, 0.0), age)
    for provider, age in acl_ages.items():
        source_freshness.labels(provider).set(age)
    for provider, age in directory_ages.items():
        directory_freshness.labels(provider).set(age)

    event_lags: dict[str, float] = {}
    recent_events = db.scalars(select(GuardPermissionEvent).order_by(
        GuardPermissionEvent.received_at.desc()
    ).limit(5000)).all()
    for event in recent_events:
        observed = _utc(event.observed_at)
        received = _utc(event.received_at)
        if observed is None or received is None:
            continue
        lag = max(0.0, (received - observed).total_seconds())
        provider = event.provider.lower()
        event_lags[provider] = max(event_lags.get(provider, 0.0), lag)
    for provider, lag in event_lags.items():
        provider_event_lag.labels(provider).set(lag)

    certificate_ages: list[float] = []
    eligible = certified = 0
    applications = db.scalars(select(AIApplication).where(
        AIApplication.adapter_type == "accessproof-gateway",
    ).limit(1000)).all()
    for row in applications:
        certificate = describe_route_certificate(db, row, now=now)
        if certificate["age_seconds"] is not None:
            certificate_ages.append(float(certificate["age_seconds"]))
        if row.mode in {"protect", "protect_pending"}:
            eligible += 1
            if certificate["certified"]:
                certified += 1
    if certificate_ages:
        route_certificate_age.set(max(certificate_ages))
    if eligible:
        protected_route_coverage.set(certified / eligible)

    reported_lags: list[float] = []
    guards = db.scalars(select(GuardRegistration).where(
        GuardRegistration.active_authorization_revisions_json != "{}",
    )).all()
    for guard in guards:
        try:
            reported = json.loads(guard.active_authorization_revisions_json or "{}")
        except ValueError:
            continue
        if not isinstance(reported, dict):
            continue
        for application_id, report in reported.items():
            if not isinstance(report, dict) or not isinstance(report.get("revision"), int):
                continue
            latest = latest_revision(db, guard.organization_id, application_id)
            if latest is None or report["revision"] >= latest.revision:
                continue
            generated = _utc(latest.generated_at)
            if generated is None:
                continue
            reported_lags.append(max(0.0, (now - generated).total_seconds()))
    if reported_lags:
        guard_revision_lag.set(max(reported_lags))


_metrics_sessionmaker: Any = None


def _metrics_db() -> Iterator[OrmSession]:
    """Cross-tenant aggregates need a read-only role (P0-01).

    The API's runtime role is tenant-scoped by RLS, so it would see no rows
    and report false-calm zeros. ACCESSPROOF_METRICS_DATABASE_URL points at
    the SELECT-only ``accessproof_metrics`` role. Without it (development,
    SQLite) the request session is used.
    """
    global _metrics_sessionmaker
    url = os.getenv("ACCESSPROOF_METRICS_DATABASE_URL", "")
    if not url:
        yield from get_db()
        return
    if _metrics_sessionmaker is None:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        _metrics_sessionmaker = sessionmaker(bind=create_engine(url, pool_pre_ping=True, pool_size=2),
                                             autoflush=False, expire_on_commit=False)
    db = _metrics_sessionmaker()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@app.get("/metrics")
def metrics(db: OrmSession = Depends(_metrics_db)) -> Response:
    _refresh_database_metrics(db)
    payload, content_type = metrics_payload()
    return Response(payload, media_type=content_type)


_TERMINAL_RUN_STATES = {
    "PASSED",
    "FAILED",
    "INCONCLUSIVE",
    "ERROR",
    "CANCELED",
    "PRECONDITION_FAILURE",
}


def _assert_project_deletable(db: OrmSession, project: Project) -> None:
    active = db.scalar(
        select(TestRun.id)
        .where(TestRun.project_id == project.id, ~TestRun.state.in_(_TERMINAL_RUN_STATES))
        .limit(1)
    )
    if active:
        raise HTTPException(409, "Project has an active test run")
    pending = db.scalar(
        select(CleanupTask.id)
        .where(
            CleanupTask.project_id == project.id,
            CleanupTask.status.in_(["pending", "retry", "running"]),
        )
        .limit(1)
    )
    if pending:
        raise HTTPException(409, "Project has pending provider-resource cleanup")


def _delete_project_records(db: OrmSession, project: Project) -> None:
    run_ids = list(db.scalars(select(TestRun.id).where(TestRun.project_id == project.id)))
    if run_ids:
        db.execute(delete(Report).where(Report.run_id.in_(run_ids)))
        db.execute(delete(EvidenceItem).where(EvidenceItem.run_id.in_(run_ids)))
        db.execute(delete(RunStateTransition).where(RunStateTransition.run_id.in_(run_ids)))
        db.execute(
            delete(SyntheticResourceRecord).where(SyntheticResourceRecord.run_id.in_(run_ids))
        )
        db.execute(delete(RunnerCheckpoint).where(RunnerCheckpoint.run_id.in_(run_ids)))
        db.execute(delete(MutationJournal).where(MutationJournal.run_id.in_(run_ids)))
        db.execute(delete(CleanupTask).where(CleanupTask.run_id.in_(run_ids)))
        db.execute(delete(TestRun).where(TestRun.id.in_(run_ids)))
    endpoint_ids = list(
        db.scalars(select(WebhookEndpoint.id).where(WebhookEndpoint.project_id == project.id))
    )
    if endpoint_ids:
        db.execute(delete(WebhookDelivery).where(WebhookDelivery.endpoint_id.in_(endpoint_ids)))
    db.execute(delete(WebhookEndpoint).where(WebhookEndpoint.project_id == project.id))
    db.execute(delete(AlertRecord).where(AlertRecord.project_id == project.id))
    db.execute(delete(RunnerRegistration).where(RunnerRegistration.project_id == project.id))
    db.execute(delete(Runner).where(Runner.project_id == project.id))
    db.execute(delete(Release).where(Release.project_id == project.id))
    db.execute(delete(AITarget).where(AITarget.project_id == project.id))
    db.execute(delete(SourceConnection).where(SourceConnection.project_id == project.id))
    db.execute(delete(TestSuite).where(TestSuite.project_id == project.id))
    db.delete(project)


@app.get("/api/v1/branding")
def branding() -> dict[str, Any]:
    return {
        "product_name": settings.product_name,
        "company_name": settings.company_name,
        "support_url": settings.support_url,
        "support_email": settings.support_email,
    }


@app.post("/api/v1/guard/permission-events", status_code=201)
def guard_permission_event(
    payload: GuardEventCreate,
    x_accessproof_ingest_key: str | None = Header(default=None, alias="X-AccessProof-Ingest-Key"),
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Privileged, authenticated diagnostics ingress; provider sync uses internal DB writes.

    A normal SaaS session, even OWNER, is not evidence of a provider ACL.
    Production must provision a distinct high-entropy ingest key to enable
    this endpoint. There is deliberately no development fallback secret.
    """
    expected_ingest_key = os.getenv("ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY", "")
    if len(expected_ingest_key) < 32:
        raise HTTPException(503, "PROVIDER_EVENT_INGESTION_DISABLED")
    if not x_accessproof_ingest_key or not secrets.compare_digest(
        x_accessproof_ingest_key, expected_ingest_key
    ):
        raise HTTPException(403, "PROVIDER_EVENT_AUTHENTICATION_REQUIRED")
    organization_id = actor.membership.organization_id
    set_tenant_context(db, organization_id)
    source = db.scalar(select(SourceConnection).where(
        SourceConnection.id == payload.source_id,
        SourceConnection.organization_id == organization_id,
    ))
    if source is None:
        raise HTTPException(404, "Permission source not found")
    if source.provider.lower() != payload.provider.lower():
        raise HTTPException(422, "Provider does not match permission source")
    existing = db.scalar(select(GuardPermissionEvent).where(GuardPermissionEvent.organization_id == organization_id, GuardPermissionEvent.dedupe_key == payload.dedupe_key))
    if existing:
        return {"id": existing.id, "deduplicated": True, "status": existing.processing_status}
    subject = db.scalar(select(GuardSubject).where(
        GuardSubject.organization_id == organization_id,
        GuardSubject.provider == payload.provider,
        GuardSubject.provider_subject_id == payload.subject_id,
    ))
    if subject is None:
        subject = GuardSubject(
            organization_id=organization_id,
            provider=payload.provider,
            provider_subject_id=payload.subject_id,
            last_synced_at=datetime.now(timezone.utc),
        )
        db.add(subject)
        db.flush()
    resource = db.scalar(select(GuardResource).where(
        GuardResource.organization_id == organization_id,
        GuardResource.source_id == payload.source_id,
        GuardResource.provider_resource_id == payload.resource_id,
    ))
    if resource is None:
        resource = GuardResource(
            organization_id=organization_id,
            source_id=payload.source_id,
            provider_resource_id=payload.resource_id,
            scope=payload.scope,
            last_synced_at=datetime.now(timezone.utc),
        )
        db.add(resource)
        db.flush()
    mutation = {
        "grant_key": payload.grant_key,
        "grant_effect": payload.grant_effect,
        "principal_type": payload.principal_type,
        "principal_id": payload.principal_id,
        "group_id": payload.group_id,
        "scope": payload.scope,
        "access_path": payload.access_path,
        "snapshot_complete": payload.snapshot_complete,
    }
    row = GuardPermissionEvent(
        organization_id=organization_id,
        source_id=payload.source_id,
        provider=payload.provider,
        provider_revision=payload.provider_revision,
        subject_id=subject.id,
        resource_id=resource.id,
        change_type="grant_revoke" if payload.change_type == "revoke" else payload.change_type,
        dedupe_key=payload.dedupe_key,
        processing_status="queued",
        mutation_json=json.dumps(mutation, sort_keys=True),
    )
    db.add(row)
    db.commit()
    return {"id": row.id, "deduplicated": False, "status": row.processing_status}


@app.get("/api/v1/guard/permission-events")
def guard_permission_events(actor: Actor = Depends(require(Permission.AUDIT_READ)), db: OrmSession = Depends(get_db)) -> list[dict[str, Any]]:
    organization_id = actor.membership.organization_id
    set_tenant_context(db, organization_id)
    rows = db.scalars(select(GuardPermissionEvent).where(GuardPermissionEvent.organization_id == organization_id).order_by(GuardPermissionEvent.received_at.desc()).limit(100)).all()
    return [{"id": r.id, "source_id": r.source_id, "provider": r.provider, "subject_id": r.subject_id, "resource_id": r.resource_id, "change_type": r.change_type, "provider_revision": r.provider_revision, "status": r.processing_status, "dedupe_key": r.dedupe_key, "error_code": r.error_code, "policy_id": r.policy_id} for r in rows]


@app.post("/api/v1/provider-events/microsoft")
async def microsoft_graph_event_notification(request: Request, db: OrmSession = Depends(get_db)) -> Response:
    """Microsoft Graph change and lifecycle notifications (hints only).

    No user authentication: Microsoft calls it. Each item is authenticated by
    subscription id + per-subscription clientState secret + tenant + resource
    scope (event_sync.accept_microsoft_notifications), journaled, and then a
    worker fetches AUTHORITATIVE state from Microsoft. The payload never
    becomes authorization data.
    """
    token = request.query_params.get("validationToken")
    if token is not None:
        # Subscription/lifecycle URL validation: echo the token as plain text.
        if not token or len(token) > 4096:
            raise HTTPException(400, "INVALID_VALIDATION_TOKEN")
        return PlainTextResponse(token, status_code=200)
    content_length = request.headers.get("content-length")
    try:
        if content_length is not None and int(content_length) > 1_000_000:
            raise HTTPException(413, "NOTIFICATION_TOO_LARGE")
    except ValueError:
        raise HTTPException(400, "INVALID_CONTENT_LENGTH")
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > 1_000_000:
            raise HTTPException(413, "NOTIFICATION_TOO_LARGE")
        chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks) or b"null")
    except ValueError:
        raise HTTPException(400, "INVALID_NOTIFICATION_JSON")
    try:
        events, rejected = accept_microsoft_notifications(db, payload, decrypt_token=_secret_box.decrypt)
        db.commit()
    except NotificationRejected as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    except Exception:
        db.rollback()
        # Retryable: Microsoft redelivers, so an accepted hint is never lost.
        raise HTTPException(503, "NOTIFICATION_ENQUEUE_UNAVAILABLE")
    from apps.api.accessproof_api.observability import provider_notifications
    for code in rejected:
        provider_notifications.labels("microsoft365", "rejected").inc()
        logging.getLogger("accessproof.provider_events").warning("microsoft_notification_rejected code=%s", code)
    provider_notifications.labels("microsoft365", "accepted").inc(len(events))
    if not events:
        raise HTTPException(401, "NO_AUTHENTICATED_NOTIFICATIONS")
    return Response(status_code=202)


@app.post("/api/v1/provider-events/google-drive", status_code=204)
async def google_drive_event_notification(request: Request, db: OrmSession = Depends(get_db)) -> Response:
    """Receive a Google watch hint and enqueue authoritative ACL synchronization.

    This endpoint intentionally has no user authentication: Google calls it.
    Channel binding, encrypted token comparison, source binding, expiry, and
    durable deduplication establish whether the callback is accepted.
    """
    content_length = request.headers.get("content-length")
    try:
        if content_length is not None and int(content_length) > 8_192:
            raise HTTPException(413, "NOTIFICATION_TOO_LARGE")
    except ValueError:
        raise HTTPException(400, "INVALID_CONTENT_LENGTH")
    # Streaming inspection prevents chunked or missing-Content-Length
    # requests from allocating an unbounded body before the 8 KiB limit.
    received = 0
    non_whitespace = False
    async for chunk in request.stream():
        received += len(chunk)
        if received > 8_192:
            raise HTTPException(413, "NOTIFICATION_TOO_LARGE")
        if chunk.strip():
            non_whitespace = True
    if non_whitespace:
        # Google Drive channel notifications use headers; accepting a body here
        # creates an ambiguous untrusted authorization input.
        raise HTTPException(400, "UNEXPECTED_NOTIFICATION_BODY")
    try:
        accept_google_notification(
            db, headers=request.headers, decrypt_token=_secret_box.decrypt,
        )
        db.commit()
    except NotificationRejected as exc:
        db.rollback()
        # Deliberately use a stable code, not channel details or secret state.
        raise HTTPException(401, str(exc)) from exc
    except Exception:
        db.rollback()
        # Returning retryable failure prevents an accepted-but-lost revocation hint.
        raise HTTPException(503, "NOTIFICATION_ENQUEUE_UNAVAILABLE")
    return Response(status_code=204)


@app.post("/api/v1/guards", status_code=201)
def create_guard(
    payload: GuardCreate,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Create a customer-side Guard record; enrollment is deliberately separate."""
    row = GuardRegistration(
        organization_id=actor.membership.organization_id,
        name=payload.name,
        environment=payload.environment,
        version=payload.version,
        status="not_enrolled",
        health="not_enrolled",
    )
    db.add(row)
    db.flush()
    _audit(db, actor, row.organization_id, "guard.created", "guard", row.id)
    db.commit()
    return {"id": row.id, "name": row.name, "status": row.status, "environment": row.environment}


@app.get("/api/v1/guards/download")
def download_guard_installer(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
) -> FileResponse:
    """Authenticated delivery of the Guard runtime bundle.

    The release is built into the API image, not read from a caller-controlled
    filename or an untrusted URL. Never include secrets or local .env files.
    """
    from pathlib import Path
    release_version = os.getenv("ACCESSPROOF_GUARD_RELEASE_VERSION", "0.1.0")
    parts = release_version.split(".")
    if len(parts) != 3 or any(not part.isdigit() or not part for part in parts):
        raise HTTPException(503, "GUARD_RELEASE_VERSION_INVALID")
    filename = f"accessproof-guard-{release_version}.tar.gz"
    base = Path(os.getenv("ACCESSPROOF_GUARD_RELEASE_DIR", "/app/guard-releases"))
    release = base / filename
    if not release.is_file():
        raise HTTPException(503, "GUARD_PACKAGE_NOT_PUBLISHED")
    return FileResponse(
        path=release,
        filename=filename,
        media_type="application/gzip",
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )


@app.get("/api/v1/guards")
def list_guards(
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(GuardRegistration).where(
        GuardRegistration.organization_id == actor.membership.organization_id
    ).order_by(GuardRegistration.created_at.desc())).all()
    result: list[dict[str, Any]] = []
    for row in rows:
        heartbeat = row.last_heartbeat_at
        if heartbeat and heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        online = bool(heartbeat and (now - heartbeat).total_seconds() <= settings.runner_offline_seconds)
        health = "revoked" if row.revoked_at else ("online" if online else row.health)
        result.append({
            "id": row.id, "name": row.name, "environment": row.environment,
            "version": row.version, "status": row.status, "health": health,
            "active_policy_version": row.active_policy_version,
            "last_heartbeat_at": heartbeat.isoformat() if heartbeat else None,
            "last_policy_sync_at": row.last_policy_sync_at.isoformat() if row.last_policy_sync_at else None,
            "enrolled_at": row.enrolled_at.isoformat() if row.enrolled_at else None,
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        })
    return result


@app.post("/api/v1/guards/{guard_id}/revoke")
def revoke_guard(
    guard_id: str,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    guard = db.scalar(select(GuardRegistration).where(
        GuardRegistration.id == guard_id,
        GuardRegistration.organization_id == actor.membership.organization_id,
    ))
    if guard is None:
        raise HTTPException(404, "Guard not found")
    if guard.revoked_at is None:
        guard.revoked_at = datetime.now(timezone.utc)
        guard.status = "revoked"
        guard.health = "revoked"
        _audit(db, actor, guard.organization_id, "guard.revoked", "guard", guard.id)
        db.commit()
    return {"id": guard.id, "revoked": True}


@app.post("/api/v1/guards/{guard_id}/enrollments", status_code=201)
def create_guard_enrollment(
    guard_id: str,
    payload: GuardEnrollmentCreate,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    guard = db.scalar(select(GuardRegistration).where(
        GuardRegistration.id == guard_id,
        GuardRegistration.organization_id == actor.membership.organization_id,
    ))
    if guard is None:
        raise HTTPException(404, "Guard not found")
    if guard.revoked_at:
        raise HTTPException(409, "Revoked Guard cannot be enrolled")
    token = f"AP-GUARD-{secrets.token_urlsafe(36)}"
    row = GuardEnrollment(
        organization_id=guard.organization_id,
        guard_id=guard.id,
        token_hash=hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.expires_in_minutes),
    )
    db.add(row)
    _audit(db, actor, guard.organization_id, "guard.enrollment_created", "guard", guard.id)
    db.commit()
    # The bootstrap token is returned once, and is never persisted in plaintext.
    return {"enrollment_token": token, "expires_in_seconds": payload.expires_in_minutes * 60, "guard_id": guard.id}


@app.post("/api/v1/guards/exchange", status_code=201)
def exchange_guard(payload: GuardExchange, db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    enrollment = db.scalar(select(GuardEnrollment).where(
        GuardEnrollment.token_hash == hash_token(payload.enrollment_token)
    ).with_for_update())
    if enrollment is None or enrollment.used_at or enrollment.revoked_at:
        raise HTTPException(401, "Invalid enrollment token")
    expires_at = enrollment.expires_at if enrollment.expires_at.tzinfo else enrollment.expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(401, "Expired enrollment token")
    guard = db.get(GuardRegistration, enrollment.guard_id)
    if guard is None or guard.organization_id != enrollment.organization_id or guard.revoked_at:
        raise HTTPException(401, "Invalid enrollment token")
    # Tenant derived from the matched one-time secret, never from the caller.
    set_tenant_context(db, guard.organization_id)
    credential = secrets.token_urlsafe(48)
    guard.credential_hash = hash_token(credential)
    guard.version = payload.version
    guard.status = "enrolled"
    guard.health = "offline"
    guard.enrolled_at = now
    enrollment.used_at = now
    db.add(AuditEvent(
        organization_id=guard.organization_id,
        action="guard.enrolled",
        target_type="guard",
        target_id=guard.id,
        metadata_json=json.dumps({"version": payload.version}),
    ))
    db.commit()
    return {"guard_id": guard.id, "guard_credential": credential}


def _authenticate_guard(db: OrmSession, guard_id: str, authorization: str | None) -> GuardRegistration:
    scheme, _, credential = (authorization or "").partition(" ")
    guard = db.get(GuardRegistration, guard_id)
    if (scheme.lower() != "bearer" or not credential or guard is None or guard.revoked_at
            or not guard.credential_hash or guard.credential_hash != hash_token(credential)):
        raise HTTPException(401, "Invalid Guard credential")
    set_tenant_context(db, guard.organization_id)
    return guard


def _guard_subject_identifier(db: OrmSession, organization_id: str, subject_id: str) -> str:
    """Return the provider's stable principal identifier for Guard policy checks.

    Internal UUIDs are useful for relational state, but an application Guard
    receives a verified JWT `sub`. Publishing the UUID would make every policy
    miss and fail closed. Imported rows without a matching subject retain their
    stored identifier for backwards-compatible remediation.
    """
    subject = db.scalar(select(GuardSubject).where(
        GuardSubject.organization_id == organization_id,
        GuardSubject.id == subject_id,
    ))
    return subject.provider_subject_id if subject else subject_id


def _guard_resource_identifier(db: OrmSession, organization_id: str, resource_id: str) -> str:
    """Return the provider resource identifier used by the application Guard.

    The control plane stores normalized relational UUIDs, while the Guard sees
    the source/provider resource identifier returned by its RAG integration.
    Sending the UUID here would make an otherwise valid policy fail closed.
    """
    resource = db.scalar(select(GuardResource).where(
        GuardResource.organization_id == organization_id,
        GuardResource.id == resource_id,
    ))
    return resource.provider_resource_id if resource else resource_id


@app.post("/api/v1/guards/heartbeat")
def guard_heartbeat(
    payload: GuardHeartbeat,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    guard = _authenticate_guard(db, payload.guard_id, authorization)
    if "active_authorization_revisions" in payload.model_fields_set:
        reported_revisions: dict[str, dict[str, object]] = {}
        for application_id, report in payload.active_authorization_revisions.items():
            application = db.scalar(select(AIApplication).where(
                AIApplication.organization_id == guard.organization_id,
                AIApplication.application_id == application_id,
                AIApplication.guard_id == guard.id,
            ))
            if application is None:
                raise HTTPException(403, "AUTHORIZATION_REVISION_APPLICATION_NOT_BOUND")
            issued = db.scalar(select(AuthorizationRevision).where(
                AuthorizationRevision.organization_id == guard.organization_id,
                AuthorizationRevision.application_id == application_id,
                AuthorizationRevision.revision == report.revision,
                AuthorizationRevision.revision_hash == report.revision_hash,
            ))
            if issued is None:
                raise HTTPException(409, "AUTHORIZATION_REVISION_NOT_ISSUED")
            reported_revisions[application_id] = {
                "revision": report.revision, "revision_hash": report.revision_hash,
            }
        guard.active_authorization_revisions_json = json.dumps(
            reported_revisions, sort_keys=True
        )
    reported_policy_version = int(payload.active_policy_version)
    if reported_policy_version < int(guard.active_policy_version or 0):
        raise HTTPException(409, "Guard policy version cannot move backwards")
    if reported_policy_version > int(guard.active_policy_version or 0):
        installed = db.scalar(
            select(GuardPolicyDistribution.id)
            .join(GuardPolicy, GuardPolicy.id == GuardPolicyDistribution.policy_id)
            .where(
                GuardPolicyDistribution.organization_id == guard.organization_id,
                GuardPolicyDistribution.guard_id == guard.id,
                GuardPolicyDistribution.status == "installed",
                GuardPolicy.version == reported_policy_version,
            )
            .limit(1)
        )
        if installed is None:
            raise HTTPException(409, "Guard policy version was not distributed and installed")
    # A previously enrolled sequence-aware Guard cannot use an old heartbeat
    # to keep its connection green. Authenticate first; then hold the lease
    # row lock until the SQL transaction commits. Clock is server authoritative.
    lease = db.scalar(select(GuardPresenceLease).where(
        GuardPresenceLease.guard_id == guard.id,
        GuardPresenceLease.organization_id == guard.organization_id,
    ).with_for_update())
    if payload.presence_sequence is not None:
        if lease is not None and payload.presence_sequence <= lease.sequence:
            raise HTTPException(409, "GUARD_HEARTBEAT_REPLAY")
        if lease is None:
            lease = GuardPresenceLease(guard_id=guard.id,
                                      organization_id=guard.organization_id,
                                      session_nonce="monotonic-v1", sequence=0,
                                      received_at=datetime.now(timezone.utc),
                                      expires_at=datetime.now(timezone.utc))
            db.add(lease)
        lease.sequence = payload.presence_sequence
        lease.received_at = datetime.now(timezone.utc)
        lease.expires_at = lease.received_at + timedelta(seconds=settings.guard_offline_seconds)
    elif lease is not None:
        # Once a Guard upgrades, legacy unsigned-sequence payloads cannot
        # keep it alive. Older unupgraded Guards remain in compatibility mode.
        raise HTTPException(409, "GUARD_PRESENCE_SEQUENCE_REQUIRED")
    guard.last_heartbeat_at = datetime.now(timezone.utc)
    guard.last_policy_sync_at = guard.last_heartbeat_at
    guard.version = payload.version
    guard.active_policy_version = reported_policy_version
    guard.health = "degraded" if payload.degraded_conditions else payload.cache_status
    # Do not report Protect as active until this specific machine reports
    # having installed the application's Protect binding.
    guard_can_confirm_protect = (
        payload.cache_status == "healthy"
        and not payload.degraded_conditions
        and payload.active_policy_version > 0
    )
    for application_id, active_mode in payload.active_applications.items():
        row = db.scalar(select(AIApplication).where(
            AIApplication.organization_id == guard.organization_id,
            AIApplication.guard_id == guard.id,
            AIApplication.application_id == application_id,
        ))
        if (row is not None and row.mode == "protect_pending" and active_mode == "protect"
                and guard_can_confirm_protect and all(
                    check["ok"] for check in _automatic_activation_checklist(db, row)
                )):
            row.mode = "protect"
            _audit(db, None, row.organization_id, "PROTECT_ACTIVATED", "ai_application", row.id,
                   {"guard_id": guard.id})
    db.commit()
    return {"ok": True}


def _production_google_drive_permission_ids_ready(db: OrmSession, organization_id: str) -> bool:
    """No Protect health before a complete provider-backed Drive identity map.

    Google Workspace Directory IDs, Drive permission IDs, and emails are
    distinct trust domains. A successful legacy directory cursor predating
    the bridge migration is never proof that Drive ACL grants are bound to
    those employees. Removed/suspended principals aren't ALLOW subjects.
    """
    if settings.env != "production":
        return True
    known_active = db.scalar(select(GuardSubject.id).where(
        GuardSubject.organization_id == organization_id,
        GuardSubject.provider == "google-drive",
        GuardSubject.status == "active",
    ).limit(1))
    if known_active is None:
        return False
    unresolved_user = db.scalar(select(GuardSubject.id).where(
        GuardSubject.organization_id == organization_id,
        GuardSubject.provider == "google-drive",
        GuardSubject.status == "active",
        GuardSubject.drive_permission_id.is_(None),
    ).limit(1))
    unresolved_group = db.scalar(select(GuardGroup.id).where(
        GuardGroup.organization_id == organization_id,
        GuardGroup.provider == "google-drive",
        GuardGroup.status == "active",
        GuardGroup.drive_permission_id.is_(None),
    ).limit(1))
    return unresolved_user is None and unresolved_group is None


_GUARD_POLICY_PATH = re.compile(r"^/api/v1/guards/[0-9a-fA-F-]{1,64}/policies$")


@app.middleware("http")
async def _gzip_guard_policy_sync(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Compress ONLY the machine-to-machine Guard policy envelope (identity
    sets can reach tens of MB for large directories). Never applied globally:
    this response echoes no caller input or credential (no BREACH oracle)."""
    response = await call_next(request)
    if (request.method != "GET" or response.status_code != 200
            or not _GUARD_POLICY_PATH.match(request.url.path)
            or "gzip" not in request.headers.get("accept-encoding", "").lower()
            or response.headers.get("content-encoding")):
        return response
    body = b"".join([chunk async for chunk in response.body_iterator])  # type: ignore[attr-defined]
    headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
    if len(body) < 64 * 1024:
        return Response(content=body, status_code=response.status_code, headers=headers)
    headers.update({"content-encoding": "gzip", "vary": "Accept-Encoding"})
    return Response(content=gzip.compress(body, compresslevel=6), status_code=response.status_code, headers=headers)


@app.get("/api/v1/guards/{guard_id}/policies")
def guard_policies(
    guard_id: str,
    after_version: int = 0,
    full_snapshot: bool = False,
    identity_version: str = "",
    content_versions_digest: str = "",
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Machine-only policy synchronization; no human credential is accepted."""
    guard = _authenticate_guard(db, guard_id, authorization)
    latest = int(db.scalar(select(func.max(GuardPolicy.version)).where(
        GuardPolicy.organization_id == guard.organization_id
    )) or 0)
    # Source health is evaluated at every machine sync, independent of policy
    # version. Guard must not trust an old ALLOW when Drive ACL polling fails.
    max_acl_age = max(60, int(os.getenv("ACCESSPROOF_SOURCE_ACL_MAX_AGE_SECONDS", "900")))
    max_directory_age = max(60, int(os.getenv("ACCESSPROOF_SOURCE_DIRECTORY_MAX_AGE_SECONDS", "900")))
    source_cursors = {
        (row.source_id, row.sync_kind): row
        for row in db.scalars(select(ProviderSyncCursorModel).where(
            ProviderSyncCursorModel.organization_id == guard.organization_id,
            ProviderSyncCursorModel.sync_kind.in_(["acl", "directory"]),
        ))
    }
    now = datetime.now(timezone.utc)

    def source_acl_healthy(source_id: str | None, *, waive_microsoft_certificate: bool = False) -> bool:
        # Both document grants and group/employee membership must be fresh.
        # A valid ACL read with an expired directory snapshot is not safe.
        # waive_microsoft_certificate is used ONLY to decide whether a
        # protect_pending app may enter the certification window (D-19); the
        # returned health for every binding is always computed without it.
        if source_id is None:
            return False
        bound_source = db.scalar(select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == guard.organization_id,
        ))
        if (bound_source is None or bound_source.status != "connected"
                or bound_source.last_validated_at is None or bound_source.last_error):
            return False
        # A previously synchronized cursor is not proof that the OAuth source
        # still has usable credentials. In particular, a disconnected Google
        # source with no token must never become a healthy Protect binding.
        if bound_source.provider.lower() == "google-drive":
            try:
                credentials = json.loads(_secret_box.decrypt(bound_source.encrypted_credentials or ""))
                if (not isinstance(credentials.get("access_token"), str)
                        or not credentials["access_token"]
                        or credentials.get("test_root_folder_id") != bound_source.boundary):
                    return False
            except Exception:
                return False
        if (bound_source.provider == "google-drive" and
                not _production_google_drive_permission_ids_ready(db, guard.organization_id)):
            return False
        # Microsoft Graph sharing records are never sufficient. Only a
        # source-bound, independently issued, fresh provider-live certificate
        # for this exact profile can permit a Protect binding.
        if bound_source.provider.lower() in {"microsoft365", "sharepoint", "onedrive"}:
            try:
                certificate_credentials = json.loads(_secret_box.decrypt(bound_source.encrypted_credentials or ""))
            except Exception:
                # Corrupted/undecryptable source secrets cannot certify access.
                return False
            if (not waive_microsoft_certificate
                    and not effective_source_certified(db, bound_source, certificate_credentials)):
                return False
        for kind, threshold in (("acl", max_acl_age), ("directory", max_directory_age)):
            cursor = source_cursors.get((source_id, kind))
            if cursor is None or cursor.status != "connected" or cursor.last_success_at is None:
                return False
            checked_at = cursor.last_success_at
            if checked_at.tzinfo is None:
                checked_at = checked_at.replace(tzinfo=timezone.utc)
            age = (now - checked_at).total_seconds()
            if not 0 <= age <= threshold or cursor.last_error_code:
                return False
        # Provider freshness only proves that an ACL/directory snapshot was
        # fetched. Pending GuardPermissionEvent rows have not yet become
        # effective policy. Do not declare the source healthy in that gap.
        unresolved = db.scalar(select(GuardPermissionEvent.id).where(
            GuardPermissionEvent.organization_id == guard.organization_id,
            GuardPermissionEvent.source_id == source_id,
            GuardPermissionEvent.processing_status != "resolved",
        ).limit(1))
        if unresolved is not None:
            return False
        outstanding = db.scalar(select(GuardPolicyDistribution.id).join(
            GuardPolicy, GuardPolicy.id == GuardPolicyDistribution.policy_id
        ).where(
            GuardPolicyDistribution.organization_id == guard.organization_id,
            GuardPolicyDistribution.guard_id == guard.id,
            GuardPolicy.source_id == source_id,
            GuardPolicyDistribution.status.in_(["pending", "received"]),
        ).limit(1))
        return outstanding is None

    # Bindings are delivered even when the policy version is unchanged.
    bound_rows = list(db.scalars(select(AIApplication).where(
        AIApplication.organization_id == guard.organization_id,
        AIApplication.guard_id == guard.id,
        AIApplication.source_id.is_not(None),
    )).all())
    binding_rows = db.execute(select(
        AIApplicationSourceBinding.application_row_id,
        AIApplicationSourceBinding.source_id,
    ).where(
        AIApplicationSourceBinding.organization_id == guard.organization_id,
    )).all()
    bindings_by_app: dict[str, list[str]] = {}
    for app_row_id, source_id in binding_rows:
        bindings_by_app.setdefault(str(app_row_id), []).append(str(source_id))
    bound_applications = []
    for row in bound_rows:
        source_ids = sorted(set(bindings_by_app.get(row.id, []) + (
            [row.source_id] if row.source_id is not None else []
        )))
        health = {source_id: source_acl_healthy(source_id) for source_id in source_ids}
        # D-19 certification window: a protect_pending (never activated),
        # single-source Microsoft app whose ONLY missing requirement is the
        # independent certificate may serve real, mapping-bound Guard decisions
        # so the certifier can observe the live route. Health stays false, so
        # the Guard and Gateway are never reported ready, older Guards that do
        # not understand the flag keep failing closed, and activation still
        # requires the certificate and every gate.
        certification_window = bool(
            row.mode == "protect_pending" and len(source_ids) == 1
            and not health[source_ids[0]]
            and source_acl_healthy(source_ids[0], waive_microsoft_certificate=True)
        )
        bound_applications.append({
            "application_id": row.application_id, "source_id": row.source_id,
            "source_ids": source_ids, "source_health": health,
            "source_acl_healthy": all(health.values()),
            "certification_window": certification_window,
            "mode": "protect" if row.mode == "protect_pending" else row.mode,
        })
    # A revision is issued only when stable authorization state changes. It
    # binds every subsequent Guard decision to this exact source/policy state.
    authorization_revisions = [
        revision_envelope(issue_or_reuse_revision(db, row, signer=_report_signer))
        for row in bound_rows
    ]
    if authorization_revisions:
        db.commit()
    # The Guard receives only verified mappings for its own organization.  It
    # resolves a JWT principal locally and never sends employee tokens to us.
    # Identity envelope (scales to large directories): resend the verified
    # mapping set only when it changed since the version the Guard holds.
    # Older Guards never send identity_version and always get the full set.
    from apps.api.accessproof_api.identity_resolution import identity_version as _identity_version
    current_identity_version = _identity_version(db, guard.organization_id)
    identity_unchanged = bool(identity_version) and identity_version == current_identity_version
    mappings = [] if identity_unchanged else [
        {
            "source_id": row.source_id,
            "issuer": row.oidc_issuer,
            "subject": row.oidc_subject,
            "tenant_id": row.oidc_tenant_id or "",
            "source_subject_id": subject.provider_subject_id,
        }
        for row, subject, source in db.execute(
            select(GuardIdentityMapping, GuardSubject, SourceConnection)
            .join(GuardSubject, GuardSubject.id == GuardIdentityMapping.source_subject_id)
            .join(SourceConnection, SourceConnection.id == GuardIdentityMapping.source_id)
            .where(
                GuardIdentityMapping.organization_id == guard.organization_id,
                GuardIdentityMapping.status == "VERIFIED",
                GuardIdentityMapping.revoked_at.is_(None),
                GuardSubject.organization_id == guard.organization_id,
                GuardSubject.status == "active",
                SourceConnection.organization_id == guard.organization_id,
            )
        )
        # Older or corrupted mappings must not link source A's identity to
        # source B's policy graph, even when an immutable ID string collides.
        if subject.provider == (
            "microsoft365" if source.provider.lower() in {"sharepoint", "onedrive", "microsoft365"}
            else source.provider.lower()
        )
    ]
    def _identity_envelope() -> dict[str, Any]:
        if identity_unchanged:
            return {"identity_mappings_unchanged": True, "identity_version": current_identity_version}
        return {"identity_mappings": mappings, "identity_version": current_identity_version}

    # Current document versions for cached-chunk freshness. Re-sent only when
    # changed since the digest the Guard holds; older Guards ignore the key.
    from apps.api.accessproof_api.content_versions import resource_versions_envelope
    versions = resource_versions_envelope(
        db, guard.organization_id,
        [sid for app_binding in bound_applications for sid in app_binding["source_ids"]],
    )
    _versions_envelope: dict[str, Any] = (
        {"resource_versions_unchanged": True, "resource_versions_digest": versions["digest"]}
        if content_versions_digest and content_versions_digest == versions["digest"]
        else {"resource_versions": {"sources": versions["sources"], "items": versions["items"]},
              "resource_versions_digest": versions["digest"]}
    )

    if full_snapshot:
        states = db.scalars(select(GuardEffectiveAccess).where(
            GuardEffectiveAccess.organization_id == guard.organization_id
        )).all()
        return {"kind": "full", "version": latest, "applications": bound_applications, **_identity_envelope(), **_versions_envelope, "authorization_state_token": _authorization_state_token(db, guard), "authorization_revisions": authorization_revisions, "decisions": [
            {"subject_id": _guard_subject_identifier(db, guard.organization_id, row.subject_id), "source_id": row.source_id, "resource_id": _guard_resource_identifier(db, guard.organization_id, row.resource_id),
             "scope": row.scope, "decision": row.decision, "reason": row.reason}
            for row in states
        ]}
    rows = db.scalars(select(GuardPolicy).where(
        GuardPolicy.organization_id == guard.organization_id,
        GuardPolicy.version > after_version,
    ).order_by(GuardPolicy.version.asc())).all()
    return {"kind": "incremental", "version": latest, "applications": bound_applications, **_identity_envelope(), **_versions_envelope, "authorization_state_token": _authorization_state_token(db, guard), "authorization_revisions": authorization_revisions, "policies": [
        {"version": row.version, "subject_id": _guard_subject_identifier(db, guard.organization_id, row.subject_id), "source_id": row.source_id,
         "resource_id": _guard_resource_identifier(db, guard.organization_id, row.resource_id), "scope": row.scope, "decision": row.decision,
         "reason": row.reason}
        for row in rows
    ]}


def _guard_bound_source_ids(db: OrmSession, guard: GuardRegistration) -> list[str]:
    rows = db.execute(select(AIApplication.id, AIApplication.source_id).where(
        AIApplication.organization_id == guard.organization_id,
        AIApplication.guard_id == guard.id,
    )).all()
    ids = {str(source) for _, source in rows if source}
    app_rows = [str(row_id) for row_id, _ in rows]
    if app_rows:
        ids.update(str(source) for source in db.scalars(select(AIApplicationSourceBinding.source_id).where(
            AIApplicationSourceBinding.organization_id == guard.organization_id,
            AIApplicationSourceBinding.application_row_id.in_(app_rows),
        )))
    return sorted(ids)


def _authorization_state_token(db: OrmSession, guard: GuardRegistration) -> str:
    """Cheap fingerprint of everything that changes a Guard's authorization
    envelope WITHOUT necessarily changing the policy version: unresolved
    permission events, outstanding distributions, source sync state and the
    identity set. A Guard long-polling with an older token is woken at once
    (it then fetches and verifies the full envelope through the normal path)."""
    sources = _guard_bound_source_ids(db, guard)
    unresolved = 0
    cursors: list[list[str]] = []
    if sources:
        unresolved = int(db.scalar(select(func.count(GuardPermissionEvent.id)).where(
            GuardPermissionEvent.organization_id == guard.organization_id,
            GuardPermissionEvent.source_id.in_(sources),
            GuardPermissionEvent.processing_status != "resolved",
        )) or 0)
        cursors = [[str(c.source_id), str(c.sync_kind), str(c.status), str(c.last_success_at), str(c.last_error_code)]
                   for c in db.scalars(select(ProviderSyncCursorModel).where(
                       ProviderSyncCursorModel.organization_id == guard.organization_id,
                       ProviderSyncCursorModel.source_id.in_(sources),
                   ).order_by(ProviderSyncCursorModel.source_id, ProviderSyncCursorModel.sync_kind))]
    outstanding = int(db.scalar(select(func.count(GuardPolicyDistribution.id)).where(
        GuardPolicyDistribution.organization_id == guard.organization_id,
        GuardPolicyDistribution.guard_id == guard.id,
        GuardPolicyDistribution.status.in_(["pending", "received"]),
    )) or 0)
    latest = int(db.scalar(select(func.max(GuardPolicy.version)).where(
        GuardPolicy.organization_id == guard.organization_id)) or 0)
    from apps.api.accessproof_api.identity_resolution import identity_version as _identity_version
    raw = json.dumps([latest, unresolved, outstanding, cursors, _identity_version(db, guard.organization_id)],
                     separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


@app.get("/api/v1/guards/{guard_id}/policy-notifications")
async def guard_policy_notification(
    guard_id: str,
    after_version: int = 0,
    wait_seconds: int = 20,
    state_token: str = "",
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Authenticated outbound long-poll wake-up for an enrolled Guard.

    This delivers no policy data. A Guard treats it only as a signal to call
    the normal policy endpoint, preserving the existing signature/version and
    atomic-installation checks. A Guard that sends the authorization state
    token from its last envelope is also woken when that state changes
    (e.g. source health recovering and a new revision becoming issuable),
    not only when the policy version advances.
    """
    guard = _authenticate_guard(db, guard_id, authorization)
    if after_version < 0 or wait_seconds < 0 or wait_seconds > 25 or len(state_token) > 64:
        raise HTTPException(422, "INVALID_NOTIFICATION_WAIT")
    deadline = time.monotonic() + wait_seconds
    while True:
        latest = int(db.scalar(select(func.max(GuardPolicy.version)).where(
            GuardPolicy.organization_id == guard.organization_id
        )) or 0)
        if latest > after_version:
            return {"event_type": "POLICY_UPDATE_AVAILABLE", "guard_id": guard.id, "policy_version": latest}
        if state_token and _authorization_state_token(db, guard) != state_token:
            return {"event_type": "AUTHORIZATION_STATE_CHANGED", "guard_id": guard.id, "policy_version": latest}
        if time.monotonic() >= deadline:
            return {"event_type": "KEEPALIVE", "guard_id": guard.id, "policy_version": latest}
        db.rollback()  # release the snapshot; see newly committed state next poll
        await asyncio.sleep(0.25)


def _identity_mapping_payload(row: GuardIdentityMapping, subject: GuardSubject) -> dict[str, Any]:
    return {
        "id": row.id, "source_id": row.source_id, "oidc_issuer": row.oidc_issuer,
        "oidc_subject": row.oidc_subject, "oidc_tenant_id": row.oidc_tenant_id or None,
        "source_subject_id": row.source_subject_id,
        "source_subject": {
            "id": subject.id, "stable_id": subject.provider_subject_id,
            "name": subject.display_name or subject.primary_email or subject.provider_subject_id,
        },
        "status": row.status, "method": row.method,
        "verified_at": row.verified_at.isoformat() if row.verified_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


@app.get("/api/v1/current/identity-mappings")
def list_current_identity_mappings(
    status: str | None = None, method: str | None = None,
    limit: int = 200, offset: int = 0,
    actor: Actor = Depends(require(Permission.RESULT_READ)), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    # Automatic resolution can produce one row per employee: always paginate.
    limit, offset = max(1, min(limit, 1000)), max(0, offset)
    query = (
        select(GuardIdentityMapping, GuardSubject)
        .join(GuardSubject, GuardSubject.id == GuardIdentityMapping.source_subject_id)
        .where(GuardIdentityMapping.organization_id == actor.membership.organization_id)
    )
    if status:
        query = query.where(GuardIdentityMapping.status == status.upper())
    if method:
        query = query.where(GuardIdentityMapping.method == method)
    return [
        _identity_mapping_payload(row, subject)
        for row, subject in db.execute(
            query.order_by(GuardIdentityMapping.updated_at.desc(), GuardIdentityMapping.id.desc())
            .limit(limit).offset(offset)
        )
    ]


@app.get("/api/v1/current/identity-resolution")
def current_identity_resolution(
    actor: Actor = Depends(require(Permission.RESULT_READ)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    """Automatic identity resolution status (counts only, no personal data).

    Never reports resolution as complete when the directory is unsynchronized,
    stale or failing, or when a Microsoft source has no authoritative tenant.
    """
    from apps.api.accessproof_api.identity_resolution import MICROSOFT_PROVIDERS, resolution_summary
    org_id = actor.membership.organization_id
    summary = resolution_summary(db, org_id)
    max_age = max(60, int(os.getenv("ACCESSPROOF_SOURCE_DIRECTORY_MAX_AGE_SECONDS", "900")))
    now = datetime.now(timezone.utc)
    sources = []
    for source in db.scalars(select(SourceConnection).where(SourceConnection.organization_id == org_id)):
        if source.provider.lower() not in MICROSOFT_PROVIDERS:
            continue
        cursor = db.scalar(select(ProviderSyncCursorModel).where(
            ProviderSyncCursorModel.organization_id == org_id, ProviderSyncCursorModel.source_id == source.id,
            ProviderSyncCursorModel.sync_kind == "directory"))
        seen = cursor.last_success_at if cursor else None
        if seen is not None and seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        age = (now - seen).total_seconds() if seen else None
        automatic = int(db.scalar(select(func.count(GuardIdentityMapping.id)).where(
            GuardIdentityMapping.organization_id == org_id, GuardIdentityMapping.source_id == source.id,
            GuardIdentityMapping.method == "directory_verified", GuardIdentityMapping.status == "VERIFIED")) or 0)
        if cursor is None or seen is None:
            state = "DIRECTORY_NOT_SYNCHRONIZED"
        elif cursor.last_error_code:
            state = f"DIRECTORY_UNAVAILABLE:{cursor.last_error_code}"
        elif age is None or age > max_age:
            state = "DIRECTORY_STALE"
        elif automatic == 0:
            state = "NO_RESOLVED_IDENTITIES"
        else:
            state = "ACTIVE"
        sources.append({"source_id": source.id, "name": source.name, "state": state,
                        "automatic_verified": automatic,
                        "directory_last_success_at": seen.isoformat() if seen else None,
                        "directory_age_seconds": int(age) if age is not None else None})
    return {"mode": "automatic_directory_verified", "sources": sources, **summary,
            "manual_mapping_required_for_members": False,
            "notes": ["Guests, disabled and unclassifiable accounts are never bound automatically.",
                      "A binding grants no document access; current ACL evidence is always required."]}


@app.post("/api/v1/current/identity-mappings", status_code=201)
def create_current_identity_mapping(
    payload: GuardIdentityMappingCreate,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = actor.membership.organization_id
    # Issuers are opaque exact strings; a trailing slash is security-significant.
    if payload.oidc_issuer != payload.oidc_issuer.strip() or not payload.oidc_issuer.startswith("https://"):
        raise HTTPException(422, "OIDC issuer must be an exact HTTPS issuer URL")
    source = db.scalar(select(SourceConnection).where(SourceConnection.id == payload.source_id, SourceConnection.organization_id == org_id))
    subject = db.scalar(select(GuardSubject).where(GuardSubject.id == payload.source_subject_id, GuardSubject.organization_id == org_id, GuardSubject.status == "active"))
    if source is None or subject is None:
        raise HTTPException(404, "Permission source or active source identity not found")
    source_provider = ("microsoft365"
        if source.provider.lower() in {"sharepoint", "onedrive", "microsoft365"}
        else source.provider.lower())
    if subject.provider != source_provider:
        raise HTTPException(422, "Source identity does not belong to this source provider")
    tenant = payload.oidc_tenant_id or ""
    row = db.scalar(select(GuardIdentityMapping).where(
        GuardIdentityMapping.organization_id == org_id,
        GuardIdentityMapping.source_id == source.id,
        GuardIdentityMapping.oidc_issuer == payload.oidc_issuer,
        GuardIdentityMapping.oidc_subject == payload.oidc_subject,
        GuardIdentityMapping.oidc_tenant_id == tenant,
    ))
    now = datetime.now(timezone.utc)
    if row is None:
        row = GuardIdentityMapping(
            organization_id=org_id, source_id=source.id, oidc_issuer=payload.oidc_issuer,
            oidc_subject=payload.oidc_subject, oidc_tenant_id=tenant,
            source_subject_id=subject.id, status="VERIFIED", method=payload.method,
            verified_by_user_id=actor.user.id, verified_at=now,
        )
        db.add(row)
    else:
        row.source_subject_id = subject.id
        row.status, row.method, row.verified_by_user_id = "VERIFIED", payload.method, actor.user.id
        row.verified_at, row.revoked_at = now, None
    _audit(db, actor, org_id, "identity_mapping.verified", "identity_mapping", row.id,
           {"source_id": source.id, "issuer": payload.oidc_issuer, "method": payload.method})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Identity mapping conflicts with an existing verified mapping") from exc
    db.refresh(row)
    return _identity_mapping_payload(row, subject)


@app.patch("/api/v1/current/identity-mappings/{mapping_id}")
def update_current_identity_mapping(
    mapping_id: str, payload: GuardIdentityMappingStatusUpdate,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(GuardIdentityMapping).where(
        GuardIdentityMapping.id == mapping_id,
        GuardIdentityMapping.organization_id == actor.membership.organization_id,
    ))
    if row is None:
        raise HTTPException(404, "Identity mapping not found")
    subject = db.get(GuardSubject, row.source_subject_id)
    if subject is None:
        raise HTTPException(409, "Mapped source identity no longer exists")
    now = datetime.now(timezone.utc)
    row.status = payload.status
    row.revoked_at = now if payload.status == "REVOKED" else None
    # An administrator's decision makes the row administrator-owned: automatic
    # directory reconciliation never overrides it (identity_resolution.py).
    row.verified_by_user_id = actor.user.id
    _audit(db, actor, row.organization_id, "identity_mapping.status_changed", "identity_mapping", row.id,
           {"status": payload.status, "source_id": row.source_id, "method": row.method})
    db.commit()
    return _identity_mapping_payload(row, subject)


@app.post("/api/v1/guards/policies/ack")
def guard_policy_ack(
    payload: GuardPolicyAck,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    guard = _authenticate_guard(db, payload.guard_id, authorization)
    policy = db.scalar(select(GuardPolicy).where(
        GuardPolicy.organization_id == guard.organization_id,
        GuardPolicy.version == payload.policy_version,
    ))
    if policy is None:
        raise HTTPException(404, "Policy not found")
    distribution = db.scalar(select(GuardPolicyDistribution).where(
        GuardPolicyDistribution.organization_id == guard.organization_id,
        GuardPolicyDistribution.policy_id == policy.id,
        GuardPolicyDistribution.guard_id == guard.id,
    ))
    if distribution is None:
        distribution = GuardPolicyDistribution(
            organization_id=guard.organization_id, policy_id=policy.id, guard_id=guard.id, status="pending"
        )
        db.add(distribution)
        db.flush()
    now = datetime.now(timezone.utc)
    if payload.status == "received":
        distribution.guard_received_at = distribution.guard_received_at or now
        distribution.status = "received"
        _audit(db, None, guard.organization_id, "guard.policy_received", "guard_policy", policy.id, {"guard_id": guard.id, "version": policy.version})
    else:
        distribution.guard_received_at = distribution.guard_received_at or now
        distribution.guard_installed_at = distribution.guard_installed_at or now
        distribution.status = "installed"
        guard.active_policy_version = max(guard.active_policy_version, payload.policy_version)
        guard.last_policy_sync_at = now
        _audit(db, None, guard.organization_id, "guard.policy_installed", "guard_policy", policy.id, {"guard_id": guard.id, "version": policy.version})
    db.commit()
    return {"ok": True, "status": distribution.status}


@app.post("/api/v1/guards/audit-events", status_code=202)
def upload_guard_audit_events(
    payload: GuardAuditBatch,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, int]:
    """Accept bounded, metadata-only Guard audit batches idempotently."""
    guard = _authenticate_guard(db, payload.guard_id, authorization)
    now = datetime.now(timezone.utc)
    accepted = 0
    for item in payload.events:
        if (item.authorization_revision is None) != (item.authorization_revision_hash is None):
            raise HTTPException(422, "AUTHORIZATION_REVISION_BINDING_INCOMPLETE")
        occurred_at = item.occurred_at
        if occurred_at is not None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc) if occurred_at.tzinfo is None else occurred_at
            if occurred_at > now + timedelta(minutes=5):
                raise HTTPException(422, "AUDIT_OCCURRED_AT_IN_FUTURE")
        if item.authorization_revision_hash is not None:
            revision = db.scalar(select(AuthorizationRevision).where(
                AuthorizationRevision.organization_id == guard.organization_id,
                AuthorizationRevision.application_id == item.application_id,
                AuthorizationRevision.revision == item.authorization_revision,
                AuthorizationRevision.revision_hash == item.authorization_revision_hash,
            ))
            if revision is None:
                raise HTTPException(422, "AUTHORIZATION_REVISION_UNKNOWN")
        # The unique constraint is the authority here.  The nested savepoint
        # makes concurrent replays harmless without discarding other items in
        # the same batch.
        try:
            with db.begin_nested():
                db.add(GuardAuditEvent(
                    organization_id=guard.organization_id,
                    guard_id=guard.id,
                    event_id=item.event_id,
                    decision_id=item.decision_id,
                    application_id=item.application_id,
                    subject_id=item.subject_id,
                    request_id=item.request_id,
                    layer=item.layer,
                    result=item.result,
                    reason=item.reason,
                    policy_version=item.policy_version,
                    authorization_revision=item.authorization_revision,
                    authorization_revision_hash=item.authorization_revision_hash,
                    resources_json=json.dumps(sorted(set(item.resource_ids))),
                    occurred_at=occurred_at or now,
                ))
                db.flush()
        except IntegrityError:
            continue
        accepted += 1
        reason = bounded_reason(item.reason)
        authz_decisions.labels(item.layer, item.result, reason).inc()
        if item.result in {"block", "would_block"}:
            if item.layer == "layer2":
                layer2_blocks.labels(reason).inc()
            if reason.startswith("CACHE_"):
                cache_reauth.labels(item.result).inc()
        if item.layer == "layer1" and item.result in {"block", "would_block"}:
            _observe_revocation_end_to_end(
                db, guard, item.application_id, occurred_at or now, item.event_id,
            )
    db.commit()
    return {"accepted": accepted}


def _observe_revocation_end_to_end(
    db: OrmSession, guard: GuardRegistration, application_id: str,
    denial_at: datetime, event_id: str,
) -> None:
    """Measure provider-observed change to first Guard denial, once.

    The measurement is recorded only when the denial is the first blocking
    Layer 1 audit for that application after a retained revocation event.
    """
    application = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == guard.organization_id,
        AIApplication.application_id == application_id,
        AIApplication.guard_id == guard.id,
    ))
    if application is None or application.source_id is None:
        return
    revocation = db.scalar(select(GuardPermissionEvent).where(
        GuardPermissionEvent.organization_id == guard.organization_id,
        GuardPermissionEvent.source_id == application.source_id,
        GuardPermissionEvent.change_type.in_((
            "grant_revoke", "membership_revoke", "user_disable", "revoke",
        )),
        GuardPermissionEvent.completed_at.is_not(None),
        GuardPermissionEvent.completed_at <= denial_at,
    ).order_by(GuardPermissionEvent.completed_at.desc()).limit(1))
    if revocation is None or revocation.completed_at is None:
        return
    completed = _utc(revocation.completed_at)
    earlier = db.scalar(select(GuardAuditEvent.id).where(
        GuardAuditEvent.organization_id == guard.organization_id,
        GuardAuditEvent.guard_id == guard.id,
        GuardAuditEvent.application_id == application_id,
        GuardAuditEvent.layer == "layer1",
        GuardAuditEvent.result.in_(("block", "would_block")),
        GuardAuditEvent.event_id != event_id,
        GuardAuditEvent.created_at >= completed,
        GuardAuditEvent.created_at <= denial_at,
    ).limit(1))
    if earlier is not None:
        return
    observed = _utc(revocation.observed_at)
    if observed is None:
        return
    elapsed = (denial_at - observed).total_seconds()
    if 0 <= elapsed <= 7 * 24 * 3600:
        revocation_end_to_end.observe(elapsed)


@app.post("/api/v1/auth/signup", status_code=201)
def signup(
    payload: SignupRequest, request: Request, response: Response, db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _limit_auth_request(request, "signup", limit=5, window_seconds=60 * 60, discriminator=payload.email)
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        raise HTTPException(409, "Account already exists")
    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        # Development accounts retain the existing local walkthrough convenience.
        # Production always requires the emailed verification link.
        email_verified=settings.env != "production",
        email_verified_at=datetime.now(timezone.utc) if settings.env != "production" else None,
    )
    organization_name = payload.organization_name or f"{payload.email.split('@', 1)[0]}'s organization"
    org = Organization(name=organization_name)
    db.add_all([user, org])
    db.flush()
    # Every tenant row written below (membership audit, default records) must
    # carry this new tenant's RLS context; never rely on a privileged role.
    set_tenant_context(db, org.id)
    membership = Membership(user_id=user.id, organization_id=org.id, role=Role.OWNER.value)
    db.add(membership)
    _audit(db, None, org.id, "organization.created", "organization", org.id)
    verify_raw = _issue_email_verification(db, user, org.id)
    db.commit()
    if settings.env != "production":
        token = create_session(db, user.id)
        csrf = secrets.token_urlsafe(32)
        response.set_cookie("accessproof_session", token, httponly=True, samesite="lax", max_age=7 * 24 * 3600, path="/")
        response.set_cookie("accessproof_csrf", csrf, httponly=False, samesite="lax", max_age=7 * 24 * 3600, path="/")
    body = {
        "organization_id": org.id,
        "email_verification_required": True,
    }
    if settings.env != "production":
        body["development_verification_token"] = verify_raw
        body["session_token"] = token
    return body


@app.post("/api/v1/auth/login")
def login(
    payload: LoginRequest, response: Response, request: Request, db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _limit_auth_request(request, "login", limit=10, window_seconds=15 * 60, discriminator=payload.email)
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if not user.email_verified:
        # Keep unverified accounts blocked, but make recovery self-service:
        # every authenticated login attempt rotates the old token and queues a
        # fresh verification message.  The normal login rate limit still
        # applies, and `_issue_email_verification` invalidates prior tokens.
        membership = db.scalar(select(Membership).where(Membership.user_id == user.id))
        if membership:
            _issue_email_verification(db, user, membership.organization_id)
            db.commit()
        raise HTTPException(403, "Please verify your email. A new verification link was sent.")
    memberships = list(db.scalars(select(Membership).where(Membership.user_id == user.id)))
    if not memberships:
        raise HTTPException(403, "No organization membership")
    if payload.organization_id and payload.organization_id not in {
        m.organization_id for m in memberships
    }:
        raise HTTPException(403, "Not a member of requested organization")
    if payload.organization_id:
        selected_membership = next(
            m for m in memberships if m.organization_id == payload.organization_id
        )
        set_tenant_context(db, payload.organization_id)
        oidc = db.get(OidcConfiguration, payload.organization_id)
        if oidc and oidc.enforced and selected_membership.role != Role.OWNER.value:
            raise HTTPException(
                403, detail={"code": "sso_required", "organization_id": payload.organization_id}
            )
    elif len(memberships) == 1:
        only = memberships[0]
        set_tenant_context(db, only.organization_id)
        oidc = db.get(OidcConfiguration, only.organization_id)
        if oidc and oidc.enforced and only.role != Role.OWNER.value:
            raise HTTPException(
                403, detail={"code": "sso_required", "organization_id": only.organization_id}
            )
    mfa = db.scalar(
        select(MfaMethod).where(MfaMethod.user_id == user.id, MfaMethod.enabled.is_(True)).with_for_update()
    )
    if mfa:
        if not payload.totp_code:
            raise HTTPException(401, detail={"code": "mfa_required"})
        valid = _consume_totp(mfa, payload.totp_code)
        if valid:
            db.commit()
        else:
            recovery_hashes = json.loads(mfa.recovery_hashes_json)
            candidate = hash_token(payload.totp_code)
            if candidate in recovery_hashes:
                recovery_hashes.remove(candidate)
                mfa.recovery_hashes_json = json.dumps(recovery_hashes)
                db.commit()
                valid = True
        if not valid:
            raise HTTPException(401, "Invalid MFA code")
    token = create_session(db, user.id)
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "accessproof_session",
        token,
        httponly=True,
        secure=settings.env == "production",
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/",
    )
    response.set_cookie(
        "accessproof_csrf",
        csrf,
        httponly=False,
        secure=settings.env == "production",
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/",
    )
    return {
        "session_token": token,
        "organizations": [{"id": m.organization_id, "role": m.role} for m in memberships],
    }


def _oidc_config_payload(row: OidcConfiguration) -> dict[str, Any]:
    return {
        "organization_id": row.organization_id,
        "issuer_url": row.issuer_url,
        "client_id": row.client_id,
        "allowed_domains": json.loads(row.allowed_domains_json or "[]"),
        "email_claim": row.email_claim,
        "subject_claim": row.subject_claim,
        "role_claim": row.role_claim,
        "role_mapping": json.loads(row.role_mapping_json or "{}"),
        "default_role": row.default_role,
        "enforced": row.enforced,
        "configured": True,
    }


def _validate_oidc_role(value: str, *, allow_owner: bool = False) -> str:
    try:
        role = Role(value.upper()).value
    except ValueError as exc:
        raise HTTPException(422, f"Invalid OIDC role: {value}") from exc
    if role == Role.OWNER.value and not allow_owner:
        raise HTTPException(422, "OIDC auto-provisioning cannot assign OWNER")
    return role


@app.get("/api/v1/auth/oidc/config")
def get_oidc_config(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    row = db.get(OidcConfiguration, actor.membership.organization_id)
    return {"configured": False} if row is None else _oidc_config_payload(row)


@app.put("/api/v1/auth/oidc/config")
def put_oidc_config(
    payload: OidcConfigurationUpdate,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    default_role = _validate_oidc_role(payload.default_role)
    role_mapping = {str(k): _validate_oidc_role(str(v)) for k, v in payload.role_mapping.items()}
    domains = sorted({d.strip().lower().lstrip("@") for d in payload.allowed_domains if d.strip()})
    try:
        provider = OidcProviderClient(payload.issuer_url)
        discovery = provider.discovery()
        provider.close()
    except (OidcError, ValueError) as exc:
        raise HTTPException(422, f"OIDC discovery validation failed: {exc}") from exc
    org_id = actor.membership.organization_id
    row = db.get(OidcConfiguration, org_id)
    values = {
        "issuer_url": discovery.issuer,
        "client_id": payload.client_id,
        "encrypted_client_secret": _secret_box.encrypt(payload.client_secret),
        "allowed_domains_json": json.dumps(domains, sort_keys=True),
        "email_claim": payload.email_claim,
        "subject_claim": payload.subject_claim,
        "role_claim": payload.role_claim,
        "role_mapping_json": json.dumps(role_mapping, sort_keys=True),
        "default_role": default_role,
        "enforced": payload.enforced,
        "discovery_json": json.dumps(asdict(discovery), sort_keys=True),
    }
    if row is None:
        row = OidcConfiguration(organization_id=org_id, **values)
        db.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
    _audit(
        db,
        actor,
        org_id,
        "oidc.configuration.updated",
        "organization",
        org_id,
        {"issuer": discovery.issuer, "enforced": payload.enforced},
    )
    db.commit()
    db.refresh(row)
    return _oidc_config_payload(row)


@app.delete("/api/v1/auth/oidc/config", status_code=204)
def delete_oidc_config(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db)
) -> Response:
    org_id = actor.membership.organization_id
    row = db.get(OidcConfiguration, org_id)
    if row:
        db.delete(row)
        _audit(db, actor, org_id, "oidc.configuration.deleted", "organization", org_id)
        db.commit()
    return Response(status_code=204)


@app.post("/api/v1/auth/oidc/begin")
def begin_oidc(payload: OidcBeginRequest, db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    set_tenant_context(db, payload.organization_id)
    config = db.get(OidcConfiguration, payload.organization_id)
    if config is None:
        raise HTTPException(404, "OIDC is not configured for this organization")
    configured_redirect = (
        settings.oidc_redirect_uri
        or f"{settings.public_app_url.rstrip(chr(47))}/api/v1/auth/oidc/callback"
    )
    redirect_uri = payload.redirect_uri or configured_redirect
    if redirect_uri != configured_redirect:
        raise HTTPException(422, "OIDC redirect URI does not match the configured callback")
    try:
        discovery = OidcDiscovery(**json.loads(config.discovery_json))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            503, "OIDC provider metadata is invalid; administrator must revalidate configuration"
        ) from exc
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = OidcProviderClient.new_pkce()
    row = OidcLoginState(
        organization_id=config.organization_id,
        state_hash=hash_token(state),
        encrypted_nonce=_secret_box.encrypt(nonce),
        encrypted_code_verifier=_secret_box.encrypt(verifier),
        redirect_uri=redirect_uri,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(row)
    db.commit()
    return {
        "authorization_url": OidcProviderClient.authorization_url(
            discovery,
            client_id=config.client_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_challenge=challenge,
        ),
        "state": state,
    }


def _oidc_role_for_claims(config: OidcConfiguration, claims: dict[str, Any]) -> str:
    role = config.default_role
    if config.role_claim:
        raw = claims.get(config.role_claim)
        mapping = json.loads(config.role_mapping_json or "{}")
        candidates = raw if isinstance(raw, list) else [raw]
        for candidate in candidates:
            if candidate is not None and str(candidate) in mapping:
                role = mapping[str(candidate)]
                break
    return _validate_oidc_role(role)


def _complete_oidc(
    payload: OidcCallbackRequest, response: Response, db: OrmSession
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    # Lock the one-time state row before exchanging the authorization code so
    # concurrent callbacks cannot both consume a valid login transaction.
    state_row = db.scalar(
        select(OidcLoginState)
        .where(OidcLoginState.state_hash == hash_token(payload.state))
        .with_for_update()
    )
    if state_row is None or state_row.used_at is not None:
        raise HTTPException(400, "Invalid or already-used OIDC state")
    expiry = (
        state_row.expires_at
        if state_row.expires_at.tzinfo
        else state_row.expires_at.replace(tzinfo=timezone.utc)
    )
    if expiry <= now:
        raise HTTPException(400, "Expired OIDC state")
    set_tenant_context(db, state_row.organization_id)
    config = db.get(OidcConfiguration, state_row.organization_id)
    if config is None:
        raise HTTPException(400, "OIDC configuration no longer exists")
    # Persist consumption before the network exchange. PostgreSQL row locking
    # serializes callers; this explicit commit also preserves one-time behavior
    # for SQLite/dev deployments where SELECT FOR UPDATE is a no-op.
    state_row.used_at = now
    db.commit()
    try:
        discovery = OidcDiscovery(**json.loads(config.discovery_json))
        nonce = _secret_box.decrypt(state_row.encrypted_nonce)
        verifier = _secret_box.decrypt(state_row.encrypted_code_verifier)
        provider = OidcProviderClient(config.issuer_url)
        tokens = provider.exchange_code(
            discovery,
            client_id=config.client_id,
            client_secret=_secret_box.decrypt(config.encrypted_client_secret),
            code=payload.code,
            redirect_uri=state_row.redirect_uri,
            code_verifier=verifier,
        )
        claims = provider.validate_id_token(
            discovery, id_token=str(tokens["id_token"]), client_id=config.client_id, nonce=nonce
        )
        provider.close()
    except (OidcError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(401, f"OIDC authentication failed: {exc}") from exc

    subject = str(claims.get(config.subject_claim) or "")
    email = str(claims.get(config.email_claim) or "").strip().lower()
    if not subject or not email or "@" not in email:
        raise HTTPException(403, "OIDC identity is missing required subject/email claims")
    if claims.get("email_verified") is not True:
        raise HTTPException(403, "OIDC provider must assert a verified email")
    allowed_domains = set(json.loads(config.allowed_domains_json or "[]"))
    if allowed_domains and email.rsplit("@", 1)[1] not in allowed_domains:
        raise HTTPException(403, "OIDC email domain is not allowed for this organization")

    identity = db.scalar(
        select(OidcIdentity).where(
            OidcIdentity.organization_id == config.organization_id,
            OidcIdentity.issuer == config.issuer_url,
            OidcIdentity.subject == subject,
        )
    )
    user = db.get(User, identity.user_id) if identity else None
    if user is None:
        # An IdP in one organization must never claim a globally-existing user
        # merely by asserting that person's email. Existing members can link
        # their account through their organization; a collision from another
        # tenant is rejected rather than becoming an implicit account takeover.
        existing_user = db.scalar(select(User).where(User.email == email))
        if existing_user is not None:
            existing_membership = db.scalar(
                select(Membership).where(
                    Membership.user_id == existing_user.id,
                    Membership.organization_id == config.organization_id,
                )
            )
            if existing_membership is None:
                raise HTTPException(
                    403,
                    "OIDC identity must be linked by an existing organization member",
                )
            user = existing_user
        else:
            user = User(
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(48)),
                email_verified=True,
            )
            db.add(user)
            db.flush()
        db.add(
            OidcIdentity(
                organization_id=config.organization_id,
                user_id=user.id,
                issuer=config.issuer_url,
                subject=subject,
            )
        )
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id, Membership.organization_id == config.organization_id
        )
    )
    if membership is None:
        membership = Membership(
            user_id=user.id,
            organization_id=config.organization_id,
            role=_oidc_role_for_claims(config, claims),
        )
        db.add(membership)
    # Do not silently bypass a locally configured second factor. Organizations
    # using local MFA must configure their IdP to emit an MFA authentication
    # method reference before SSO can create a session for that user.
    local_mfa = db.scalar(
        select(MfaMethod).where(MfaMethod.user_id == user.id, MfaMethod.enabled.is_(True))
    )
    if local_mfa:
        amr = claims.get("amr")
        methods = {str(value).lower() for value in (amr if isinstance(amr, list) else [amr])}
        if not methods.intersection({"mfa", "otp", "hwk", "swk"}):
            raise HTTPException(403, "OIDC authentication did not satisfy the required MFA policy")
    user.email_verified = True
    db.commit()

    token = create_session(
        db, user.id, auth_method="oidc", auth_organization_id=config.organization_id
    )
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "accessproof_session",
        token,
        httponly=True,
        secure=settings.env == "production",
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/",
    )
    response.set_cookie(
        "accessproof_csrf",
        csrf,
        httponly=False,
        secure=settings.env == "production",
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/",
    )
    return {
        "session_token": token,
        "organization_id": config.organization_id,
        "user_id": user.id,
        "role": membership.role,
    }


@app.post("/api/v1/auth/oidc/callback")
def oidc_callback(
    payload: OidcCallbackRequest, response: Response, db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    return _complete_oidc(payload, response, db)


@app.get("/api/v1/auth/oidc/callback")
def oidc_callback_browser(
    code: str, state: str, db: OrmSession = Depends(get_db)
) -> RedirectResponse:
    # Authorization servers return code/state through a browser GET. The API
    # consumes the one-time state, sets the HttpOnly session cookie on the
    # redirect response, then hands the browser back to the web application.
    redirect = RedirectResponse(
        url=settings.public_app_url.rstrip("/") + "/oidc/complete", status_code=303
    )
    result = _complete_oidc(OidcCallbackRequest(code=code, state=state), redirect, db)
    redirect.headers["Location"] = (
        settings.public_app_url.rstrip("/")
        + f"/oidc/complete?organization_id={result['organization_id']}"
    )
    return redirect


@app.post("/api/v1/auth/verify-email")
def verify_email(payload: EmailVerifyRequest, db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    row = db.scalar(
        select(OneTimeToken).where(
            OneTimeToken.token_hash == hash_token(payload.token),
            OneTimeToken.purpose == "email_verify",
        )
    )
    if not row or row.used_at is not None:
        raise HTTPException(400, "Invalid verification token")
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if exp <= now:
        raise HTTPException(400, "Expired verification token")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(400, "Invalid verification token")
    user.email_verified = True
    user.email_verified_at = now
    row.used_at = now
    db.commit()
    return {"verified": True}


@app.post("/api/v1/auth/resend-verification")
def resend_verification(
    payload: ResendVerificationRequest, request: Request, db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _limit_auth_request(request, "resend-verification", limit=3, window_seconds=15 * 60, discriminator=payload.email)
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user and not user.email_verified:
        membership = db.scalar(select(Membership).where(Membership.user_id == user.id))
        if membership:
            _issue_email_verification(db, user, membership.organization_id)
            db.commit()
    return {"accepted": True}


@app.post("/api/v1/auth/forgot-password")
def forgot_password(
    payload: ForgotPasswordRequest, request: Request, db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _limit_auth_request(request, "forgot-password", limit=3, window_seconds=15 * 60, discriminator=payload.email)
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    response: dict[str, Any] = {"accepted": True}
    if user:
        raw = secrets.token_urlsafe(32)
        for previous in db.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user.id,
                OneTimeToken.purpose == "password_reset",
                OneTimeToken.used_at.is_(None),
            )
        ):
            previous.used_at = datetime.now(timezone.utc)
        db.add(
            OneTimeToken(
                user_id=user.id,
                purpose="password_reset",
                token_hash=hash_token(raw),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            )
        )
        org_id = db.scalar(
            select(Membership.organization_id).where(Membership.user_id == user.id).limit(1)
        )
        _queue_email(
            db,
            recipient=user.email,
            organization_id=org_id,
            template="password_reset",
            subject=f"Reset your {settings.product_name} password",
            text_body=f"Reset your password: {settings.public_app_url.rstrip('/')}/reset-password?token={raw}",
        )
        db.commit()
        if settings.env != "production":
            response["development_reset_token"] = raw
    return response


@app.post("/api/v1/auth/reset-password")
def reset_password(
    payload: ResetPasswordRequest, request: Request, db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _limit_auth_request(request, "reset-password", limit=10, window_seconds=15 * 60)
    now = datetime.now(timezone.utc)
    row = db.scalar(
        select(OneTimeToken)
        .where(
            OneTimeToken.token_hash == hash_token(payload.token),
            OneTimeToken.purpose == "password_reset",
        )
        .with_for_update()
    )
    if not row or row.used_at is not None:
        raise HTTPException(400, "Invalid reset token")
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if exp <= now:
        raise HTTPException(400, "Expired reset token")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(400, "Invalid reset token")
    user.password_hash = hash_password(payload.new_password)
    row.used_at = now
    for sess in db.scalars(
        select(DbSession).where(DbSession.user_id == user.id, DbSession.revoked_at.is_(None))
    ):
        sess.revoked_at = now
    db.commit()
    return {"reset": True}


@app.post("/api/v1/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    actor: Actor = Depends(current_actor),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    if not verify_password(payload.current_password, actor.user.password_hash):
        raise HTTPException(401, "Current password is incorrect")
    now = datetime.now(timezone.utc)
    actor.user.password_hash = hash_password(payload.new_password)
    # Password changes invalidate all sessions, including this one. The caller
    # must authenticate again with the new secret, preventing stolen sessions
    # from surviving an account-recovery event.
    for session in db.scalars(
        select(DbSession).where(DbSession.user_id == actor.user.id, DbSession.revoked_at.is_(None))
    ):
        session.revoked_at = now
    db.commit()
    return {"changed": True}


@app.get("/api/v1/auth/sessions")
def list_sessions(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(DbSession)
        .where(DbSession.user_id == actor.user.id)
        .order_by(DbSession.created_at.desc())
    )
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "expires_at": r.expires_at.isoformat(),
            "revoked": r.revoked_at is not None,
        }
        for r in rows
    ]


@app.delete("/api/v1/auth/sessions/{session_id}", status_code=204)
def revoke_session(
    session_id: str, actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> Response:
    row = db.scalar(
        select(DbSession).where(DbSession.id == session_id, DbSession.user_id == actor.user.id)
    )
    if not row:
        raise HTTPException(404, "Session not found")
    row.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return Response(status_code=204)


def _consume_totp(method: MfaMethod, code: str) -> bool:
    """Accept a TOTP code at most once (RFC 6238 section 5.2).

    The caller must hold a row lock on `method` so two concurrent requests
    cannot both accept the same code.
    """
    step = matched_totp_step(_secret_box.decrypt(method.encrypted_secret), code)
    if step is None or (method.last_totp_step is not None and step <= method.last_totp_step):
        return False
    method.last_totp_step = step
    return True


@app.post("/api/v1/auth/mfa/setup")
def mfa_setup(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    existing = db.scalar(select(MfaMethod).where(MfaMethod.user_id == actor.user.id))
    if existing and existing.enabled:
        raise HTTPException(409, "MFA already enabled")
    secret = generate_totp_secret()
    recovery = [secrets.token_urlsafe(10) for _ in range(10)]
    if existing:
        existing.encrypted_secret = _secret_box.encrypt(secret)
        existing.recovery_hashes_json = json.dumps([hash_token(x) for x in recovery])
        existing.enabled = False
    else:
        db.add(
            MfaMethod(
                user_id=actor.user.id,
                encrypted_secret=_secret_box.encrypt(secret),
                recovery_hashes_json=json.dumps([hash_token(x) for x in recovery]),
            )
        )
    db.commit()
    return {
        "provisioning_uri": provisioning_uri(secret, actor.user.email, settings.product_name),
        "recovery_codes": recovery,
    }


@app.post("/api/v1/auth/mfa/enable")
def mfa_enable(
    payload: MfaEnableRequest,
    actor: Actor = Depends(current_actor),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(MfaMethod).where(MfaMethod.user_id == actor.user.id).with_for_update())
    if not row:
        raise HTTPException(409, "Run MFA setup first")
    if not _consume_totp(row, payload.code):
        raise HTTPException(400, "Invalid TOTP code")
    row.enabled = True
    db.commit()
    return {"enabled": True}


@app.post("/api/v1/auth/mfa/disable")
def mfa_disable(
    payload: MfaDisableRequest,
    actor: Actor = Depends(current_actor),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(MfaMethod).where(MfaMethod.user_id == actor.user.id, MfaMethod.enabled.is_(True)).with_for_update()
    )
    if not row:
        return {"enabled": False}
    valid = _consume_totp(row, payload.code)
    if not valid:
        hashes = json.loads(row.recovery_hashes_json)
        candidate = hash_token(payload.code)
        if candidate in hashes:
            # Recovery codes are one-time credentials regardless of whether
            # they are used for login or to disable MFA. A successful disable
            # must consume the code before MFA can be re-enabled.
            hashes.remove(candidate)
            row.recovery_hashes_json = json.dumps(hashes)
            valid = True
    if not valid:
        raise HTTPException(400, "Invalid MFA or recovery code")
    row.enabled = False
    db.commit()
    return {"enabled": False}


@app.post("/api/v1/auth/logout", status_code=204)
def logout(actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)) -> Response:
    sess = db.scalar(select(DbSession).where(DbSession.token_hash == hash_token(actor.token)))
    if sess:
        sess.revoked_at = datetime.now(timezone.utc)
        db.commit()
    response = Response(status_code=204)
    response.delete_cookie("accessproof_session", path="/")
    response.delete_cookie("accessproof_csrf", path="/")
    return response


@app.post("/api/v1/organization/invitations", status_code=201)
def create_invitation(
    payload: InvitationCreate,
    actor: Actor = Depends(require(Permission.MEMBER_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        role = Role(payload.role.upper())
    except ValueError as exc:
        raise HTTPException(422, "Invalid role") from exc
    if role is Role.OWNER:
        raise HTTPException(422, "Ownership transfer is a separate operation")
    raw = secrets.token_urlsafe(32)
    row = Invitation(
        organization_id=actor.membership.organization_id,
        email=payload.email.lower(),
        role=role.value,
        token_hash=hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(row)
    db.flush()
    _audit(
        db,
        actor,
        row.organization_id,
        "invitation.created",
        "invitation",
        row.id,
        {"role": row.role},
    )
    _queue_email(
        db,
        recipient=row.email,
        organization_id=row.organization_id,
        template="organization_invitation",
        subject=f"You've been invited to {settings.product_name}",
        text_body=f"Accept your invitation: {settings.public_app_url.rstrip('/')}/accept-invitation?token={raw}",
    )
    db.commit()
    response = {
        "id": row.id,
        "email": row.email,
        "role": row.role,
        "expires_at": row.expires_at.isoformat(),
    }
    if settings.env != "production":
        response["development_invitation_token"] = raw
    return response


@app.post("/api/v1/auth/invitations/accept")
def accept_invitation(
    payload: InvitationAccept, user: User = Depends(current_user), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    row = db.scalar(select(Invitation).where(Invitation.token_hash == hash_token(payload.token)))
    if not row or row.accepted_at is not None:
        raise HTTPException(400, "Invalid invitation")
    expiry = (
        row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    )
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(400, "Expired invitation")
    if row.email.lower() != user.email.lower():
        raise HTTPException(403, "Invitation is for a different account")
    existing = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id, Membership.organization_id == row.organization_id
        )
    )
    if not existing:
        db.add(Membership(user_id=user.id, organization_id=row.organization_id, role=row.role))
    row.accepted_at = datetime.now(timezone.utc)
    db.commit()
    return {"organization_id": row.organization_id, "role": row.role}


@app.get("/api/v1/organization/members")
def list_members(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == actor.membership.organization_id)
    ).all()
    return [
        {"membership_id": m.id, "user_id": u.id, "email": u.email, "role": m.role} for m, u in rows
    ]


@app.patch("/api/v1/organization/members/{membership_id}")
def update_member_role(
    membership_id: str,
    payload: MemberRoleUpdate,
    actor: Actor = Depends(require(Permission.MEMBER_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(Membership).where(
            Membership.id == membership_id,
            Membership.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Membership not found")
    try:
        new_role = Role(payload.role.upper())
    except ValueError as exc:
        raise HTTPException(422, "Invalid role") from exc
    if row.role == Role.OWNER.value or new_role is Role.OWNER:
        raise HTTPException(409, "Ownership transfer is not supported by this endpoint")
    row.role = new_role.value
    _audit(
        db,
        actor,
        row.organization_id,
        "member.role_changed",
        "membership",
        row.id,
        {"role": new_role.value},
    )
    db.commit()
    return {"membership_id": row.id, "role": row.role}


@app.post("/api/v1/api-keys", status_code=201)
def create_api_key(
    payload: ApiKeyCreate,
    actor: Actor = Depends(require(Permission.CI_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    raw = "ap_" + secrets.token_urlsafe(40)
    expires = (
        datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )
    scopes = sorted(set(payload.scopes))
    invalid = [scope for scope in scopes if scope not in _ALLOWED_API_KEY_SCOPES]
    if invalid:
        raise HTTPException(422, "Unsupported API key scopes: " + ", ".join(invalid))
    if not scopes:
        raise HTTPException(422, "At least one API key scope is required")
    row = ApiKey(
        user_id=actor.user.id,
        organization_id=actor.membership.organization_id,
        token_hash=hash_token(raw),
        label=payload.label,
        scopes_json=json.dumps(scopes),
        expires_at=expires,
    )
    db.add(row)
    db.flush()
    _audit(
        db,
        actor,
        actor.membership.organization_id,
        "api_key.created",
        "api_key",
        row.id,
        {"label": payload.label, "scopes": scopes},
    )
    db.commit()
    return {
        "id": row.id,
        "api_key": raw,
        "label": row.label,
        "scopes": scopes,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
    }


@app.get("/api/v1/api-keys")
def list_api_keys(
    actor: Actor = Depends(require(Permission.CI_MANAGE)), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(ApiKey)
        .where(ApiKey.organization_id == actor.membership.organization_id)
        .order_by(ApiKey.created_at.desc())
    )
    return [
        {
            "id": r.id,
            "label": r.label,
            "scopes": json.loads(r.scopes_json or "[]"),
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "revoked": r.revoked_at is not None,
        }
        for r in rows
    ]


@app.delete("/api/v1/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    key_id: str,
    actor: Actor = Depends(require(Permission.CI_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> Response:
    row = db.scalar(
        select(ApiKey).where(
            ApiKey.id == key_id, ApiKey.organization_id == actor.membership.organization_id
        )
    )
    if not row:
        raise HTTPException(404, "API key not found")
    row.revoked_at = datetime.now(timezone.utc)
    _audit(db, actor, actor.membership.organization_id, "api_key.revoked", "api_key", row.id)
    db.commit()
    return Response(status_code=204)


def _entitlement_value(db: OrmSession, organization_id: str, key: str) -> str | None:
    row = db.scalar(
        select(Entitlement)
        .where(Entitlement.organization_id == organization_id, Entitlement.key == key)
        .order_by(Entitlement.created_at.desc())
        .limit(1)
    )
    return row.value if row is not None else None


def _entitlement_limit(db: OrmSession, organization_id: str, key: str) -> int | None:
    raw = _entitlement_value(db, organization_id, key)
    if raw is None or str(raw).strip().lower() in {"", "unlimited", "none"}:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(500, f"Invalid entitlement value for {key}") from exc
    if value < 0:
        raise HTTPException(500, f"Invalid entitlement value for {key}")
    return value


def _enforce_count_entitlement(
    db: OrmSession, organization_id: str, key: str, current_count: int
) -> None:
    limit = _entitlement_limit(db, organization_id, key)
    if limit is not None and current_count >= limit:
        raise HTTPException(402, f"Entitlement limit reached: {key}={limit}")


def _enforce_connector_entitlement(db: OrmSession, organization_id: str, provider: str) -> None:
    raw = _entitlement_value(db, organization_id, "connectors")
    if raw is None or str(raw).strip().lower() in {"", "all", "*", "unlimited"}:
        return
    try:
        parsed = json.loads(raw)
        allowed = (
            {str(x).lower() for x in parsed} if isinstance(parsed, list) else {str(parsed).lower()}
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        allowed = {part.strip().lower() for part in str(raw).split(",") if part.strip()}
    aliases = {"sharepoint": "microsoft365", "onedrive": "microsoft365"}
    normalized = aliases.get(provider.lower(), provider.lower())
    normalized_allowed = {aliases.get(item, item) for item in allowed}
    if normalized not in normalized_allowed:
        raise HTTPException(402, f"Connector is not enabled by entitlement: {provider}")


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    weight = pos - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


@app.get("/api/v1/dashboard")
def dashboard(
    actor: Actor = Depends(require(Permission.RESULT_READ)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    org_id = actor.membership.organization_id
    project_count = int(
        db.scalar(select(func.count(Project.id)).where(Project.organization_id == org_id)) or 0
    )
    runs = list(
        db.scalars(
            select(TestRun)
            .where(TestRun.organization_id == org_id)
            .order_by(TestRun.created_at.desc())
            .limit(500)
        )
    )
    latencies: list[float] = []
    by_source: dict[str, list[float]] = {}
    by_suite: dict[str, list[float]] = {}
    outcomes = {
        "PASS": 0,
        "FAIL": 0,
        "INCONCLUSIVE": 0,
        "PRECONDITION_FAILURE": 0,
        "ERROR": 0,
        "CANCELED": 0,
    }
    recent_runs: list[dict[str, Any]] = []
    for run in runs:
        if run.outcome in outcomes:
            outcomes[run.outcome] += 1
        payload = json.loads(run.result_json) if run.result_json else {}
        stable = (payload.get("derived") or {}).get("stable_propagation_latency_seconds")
        if isinstance(stable, (int, float)):
            value = float(stable)
            latencies.append(value)
            if run.source_connection_id:
                by_source.setdefault(run.source_connection_id, []).append(value)
            by_suite.setdefault(run.suite_id, []).append(value)
        if len(recent_runs) < 10:
            recent_runs.append(
                {
                    "id": run.id,
                    "project_id": run.project_id,
                    "suite_id": run.suite_id,
                    "release": run.release,
                    "outcome": run.outcome,
                    "state": run.state,
                    "created_at": run.created_at.isoformat(),
                    "stable_propagation_latency_seconds": stable,
                }
            )
    source_names = {
        row.id: row.name
        for row in db.scalars(
            select(SourceConnection).where(SourceConnection.organization_id == org_id)
        )
    }
    suite_names = {
        row.id: row.name
        for row in db.scalars(select(TestSuite).where(TestSuite.organization_id == org_id))
    }
    worst_source_id = (
        max(by_source, key=lambda key: sum(by_source[key]) / len(by_source[key]))
        if by_source
        else None
    )
    worst_suite_id = (
        max(by_suite, key=lambda key: sum(by_suite[key]) / len(by_suite[key])) if by_suite else None
    )
    now = datetime.now(timezone.utc)
    runners = list(
        db.scalars(
            select(Runner).where(Runner.organization_id == org_id, Runner.revoked.is_(False))
        )
    )
    online = 0
    for runner in runners:
        heartbeat = runner.last_heartbeat_at
        if heartbeat and heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        if (
            heartbeat
            and not runner.disabled
            and (now - heartbeat).total_seconds() <= settings.runner_offline_seconds
        ):
            online += 1
    broken_sources = int(
        db.scalar(
            select(func.count(SourceConnection.id)).where(
                SourceConnection.organization_id == org_id,
                SourceConnection.status.notin_(["connected", "validated"]),
            )
        )
        or 0
    )
    return {
        "projects": project_count,
        "latest_release_status": next((r.outcome for r in runs if r.outcome), None),
        "outcomes": outcomes,
        "slo_failures": outcomes["FAIL"],
        "median_revocation_latency_seconds": _percentile(latencies, 0.5),
        "p95_revocation_latency_seconds": _percentile(latencies, 0.95),
        "worst_source": (
            {
                "id": worst_source_id,
                "name": source_names.get(worst_source_id, worst_source_id),
                "average_seconds": sum(by_source[worst_source_id])
                / len(by_source[worst_source_id]),
            }
            if worst_source_id
            else None
        ),
        "worst_scenario": (
            {
                "id": worst_suite_id,
                "name": suite_names.get(worst_suite_id, worst_suite_id),
                "average_seconds": sum(by_suite[worst_suite_id]) / len(by_suite[worst_suite_id]),
            }
            if worst_suite_id
            else None
        ),
        "runner_health": {
            "online": online,
            "total": len(runners),
            "offline": max(0, len(runners) - online),
        },
        "broken_connections": broken_sources,
        "recent_runs": recent_runs,
    }


_CURRENT_ACTIVITY_ACTIONS = {
    "source.created": ("PERMISSION_SOURCE_CONNECTED", "info", "Permission source connected"),
    "source.validated": ("PERMISSION_SOURCE_RECOVERED", "info", "Permission source validated"),
    "source.capabilities_refreshed": ("PERMISSION_SOURCE_RECOVERED", "info", "Permission source capabilities refreshed"),
    "source.reauthorized": ("PERMISSION_SOURCE_RECOVERED", "info", "Permission source reauthorized"),
    "guard.policy_committed": ("POLICY_COMMITTED", "info", "Authorization policy committed"),
    "guard.policy_received": ("GUARD_POLICY_RECEIVED", "info", "Guard received authorization policy"),
    "guard.policy_installed": ("GUARD_POLICY_INSTALLED", "info", "Guard installed authorization policy"),
    "guard.enrolled": ("GUARD_ONLINE", "info", "Guard enrolled"),
    "directory.sync_completed": ("RECONCILIATION_COMPLETED", "info", "Directory synchronization completed"),
    "directory.sync_degraded": ("PERMISSION_SOURCE_DEGRADED", "warning", "Directory synchronization requires attention"),
}


@app.get("/api/v1/current/dashboard")
def current_dashboard(
    actor: Actor = Depends(require(Permission.RESULT_READ)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    """Current authorization-enforcement dashboard, intentionally run-free."""
    org_id = actor.membership.organization_id
    now = datetime.now(timezone.utc)
    guards = list(db.scalars(select(GuardRegistration).where(
        GuardRegistration.organization_id == org_id,
        GuardRegistration.revoked_at.is_(None),
    )))
    guards_online = 0
    for guard in guards:
        heartbeat = guard.last_heartbeat_at
        if heartbeat and heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        if heartbeat and (now - heartbeat).total_seconds() <= settings.runner_offline_seconds:
            guards_online += 1
    source_count = int(db.scalar(select(func.count(SourceConnection.id)).where(
        SourceConnection.organization_id == org_id
    )) or 0)
    live_blocked_count = int(db.scalar(select(func.count(GuardAuditEvent.id)).where(
        GuardAuditEvent.organization_id == org_id,
        GuardAuditEvent.result.in_(["block", "would_block"]),
    )) or 0)
    # Old installations can contain the pre-audit projection while their Guards
    # roll forward.  Keep it visible, but new Guard uploads use GuardAuditEvent.
    legacy_blocked_count = int(db.scalar(select(func.count(GuardProtectionDecision.id)).where(
        GuardProtectionDecision.organization_id == org_id,
        GuardProtectionDecision.result.in_(["block", "would_block"]),
    )) or 0)
    blocked_count = live_blocked_count + legacy_blocked_count
    application_ids = set(db.scalars(select(GuardAuditEvent.application_id).where(
        GuardAuditEvent.organization_id == org_id
    )))
    application_ids.update(db.scalars(select(GuardProtectionDecision.application_id).where(
        GuardProtectionDecision.organization_id == org_id
    )))
    application_ids.update(db.scalars(select(AIApplication.application_id).where(
        AIApplication.organization_id == org_id
    )))
    application_count = len(application_ids)

    activity: list[dict[str, Any]] = []
    for audit_event in db.scalars(select(AuditEvent).where(
        AuditEvent.organization_id == org_id,
        AuditEvent.action.in_(_CURRENT_ACTIVITY_ACTIONS),
    ).order_by(AuditEvent.created_at.desc()).limit(50)):
        event_type, severity, summary = _CURRENT_ACTIVITY_ACTIONS[audit_event.action]
        metadata = json.loads(audit_event.metadata_json or "{}")
        activity.append({
            "id": audit_event.id, "type": event_type, "severity": severity,
            "timestamp": audit_event.created_at.isoformat(), "summary": summary,
            "guard_id": metadata.get("guard_id") if isinstance(metadata, dict) else None,
            "policy_version": metadata.get("version") if isinstance(metadata, dict) else None,
        })
    for guard_audit_event in db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == org_id,
        GuardAuditEvent.result.in_(["block", "would_block"]),
    ).order_by(GuardAuditEvent.created_at.desc()).limit(50)):
        activity.append({
            "id": guard_audit_event.id, "type": "LAYER2_BLOCK" if "PROVENANCE" in guard_audit_event.reason else "LAYER1_BLOCK",
            "severity": "warning", "timestamp": guard_audit_event.created_at.isoformat(),
            "summary": "Guard blocked an AI request", "guard_id": guard_audit_event.guard_id,
            "application_id": guard_audit_event.application_id, "policy_version": guard_audit_event.policy_version,
        })
    # Protection decisions are durable current-product authorization events.
    # A Guard audit upload may arrive later, so show the decision promptly.
    for decision in db.scalars(select(GuardProtectionDecision).where(
        GuardProtectionDecision.organization_id == org_id,
        GuardProtectionDecision.result.in_(["block", "would_block"]),
    ).order_by(GuardProtectionDecision.created_at.desc()).limit(50)):
        activity.append({
            "id": f"decision:{decision.id}",
            "type": "LAYER2_BLOCK" if "PROVENANCE" in decision.reason else "LAYER1_BLOCK",
            "severity": "warning", "timestamp": decision.created_at.isoformat(),
            "summary": "Guard blocked an AI request", "guard_id": decision.guard_id,
            "application_id": decision.application_id, "policy_version": decision.policy_version,
        })
    activity.sort(key=lambda item: item["timestamp"], reverse=True)
    snapshot = _protection_snapshot(db, org_id)
    decision_since = now - timedelta(hours=24)
    decision_window = {
        "layer1": {"allow": 0, "block": 0, "would_allow": 0, "would_block": 0},
        "layer2": {"allow": 0, "block": 0, "would_allow": 0, "would_block": 0},
    }
    observed_decisions = 0
    for layer, result, count in db.execute(select(
        GuardAuditEvent.layer, GuardAuditEvent.result, func.count(GuardAuditEvent.id),
    ).where(
        GuardAuditEvent.organization_id == org_id,
        GuardAuditEvent.created_at >= decision_since,
    ).group_by(GuardAuditEvent.layer, GuardAuditEvent.result)).all():
        layer_key = "layer2" if layer == "layer2" else "layer1"
        if result in decision_window[layer_key]:
            decision_window[layer_key][result] += int(count)
            observed_decisions += int(count)
    latest_decision = _utc(db.scalar(select(func.max(GuardAuditEvent.created_at)).where(
        GuardAuditEvent.organization_id == org_id,
    )))
    totals = snapshot["totals"]
    return {
        "ai_applications": application_count,
        "guards_online": guards_online,
        "guards_total": len(guards),
        "permission_sources": source_count,
        "blocked_requests": blocked_count,
        "recent_activity": activity[:25],
        "protection": {
            "applications_registered": totals["applications_registered"],
            "applications_protected_verified": totals["applications_protected_verified"],
            "applications_not_verified": totals["applications_not_verified"],
            "applications_unsupported": totals["applications_unsupported"],
            "guards": totals["guards"],
            "sources_fresh": totals["sources_fresh"],
            "sources_total": totals["sources_total"],
            "decisions_24h": {
                **decision_window,
                "telemetry": "OBSERVED" if observed_decisions else "NO_DATA",
                "total": observed_decisions,
            },
            "latest_decision_at": latest_decision.isoformat() if latest_decision else None,
        },
    }


@app.get("/api/v1/current/protection-decisions")
def current_protection_decisions(
    limit: int = 100,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Tenant-scoped, metadata-only Guard decision history for web-v2."""
    rows = db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == actor.membership.organization_id,
    ).order_by(GuardAuditEvent.created_at.desc()).limit(max(1, min(limit, 250)))).all()
    return [{
        "id": row.id, "decision_id": row.decision_id, "guard_id": row.guard_id,
        "application_id": row.application_id, "subject_id": row.subject_id,
        "request_id": row.request_id, "layer": row.layer, "result": row.result,
        "reason": row.reason, "policy_version": row.policy_version,
        "resource_ids": json.loads(row.resources_json or "[]"),
        "created_at": row.created_at.isoformat(),
    } for row in rows]


class GuardEvidence(TypedDict):
    positive: bool
    denial: bool
    provenance: bool
    requests: dict[str, set[str]]


def _verified_guard_evidence(
    db: OrmSession, row: AIApplication, *, max_age_days: int = 7,
) -> GuardEvidence:
    """Derive proof from machine-authenticated Guard audit events, not UI flags.

    These records prove Guard endpoints ran; they cannot by themselves prove
    that arbitrary customer RAG code always uses the SDK boundary. Buffering
    and end-to-end invocation remain explicit operator-attested checks.
    """
    if not row.guard_id:
        return {
            "positive": False,
            "denial": False,
            "provenance": False,
            "requests": {"positive": set(), "denial": set(), "provenance": set()},
        }
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    events = list(db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == row.organization_id,
        GuardAuditEvent.guard_id == row.guard_id,
        GuardAuditEvent.application_id == row.application_id,
        GuardAuditEvent.created_at >= cutoff,
        GuardAuditEvent.policy_version > 0,
    )).all())
    by_request: dict[str, list[GuardAuditEvent]] = {}
    for event in events:
        by_request.setdefault(event.request_id, []).append(event)
    positive: set[str] = set()
    denial: set[str] = set()
    provenance: set[str] = set()
    for request_id, records in by_request.items():
        layer1_allow = [r for r in records if r.layer == "layer1" and r.result in ("allow", "would_allow")]
        layer2_allow = [r for r in records if r.layer == "layer2" and r.result in ("allow", "would_allow")
                        and r.reason == "TRUSTED_PROVENANCE_VALID"]
        if any(a.decision_id and a.decision_id == b.decision_id and a.subject_id == b.subject_id
               for a in layer1_allow for b in layer2_allow):
            positive.add(request_id)
        if any(r.layer == "layer1" and r.result in ("block", "would_block") for r in records):
            denial.add(request_id)
        if any(r.layer == "layer2" and r.result in ("block", "would_block")
               and r.reason in ("PROVENANCE_ESCAPE", "PROVENANCE_MISSING") for r in records):
            provenance.add(request_id)
    return {"positive": bool(positive), "denial": bool(denial),
            "provenance": bool(provenance),
            "requests": {"positive": positive, "denial": denial, "provenance": provenance}}


def _application_checks(db: OrmSession, row: AIApplication, organization_id: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []
    adapter = next((item for item in adapter_registry() if item["id"] == row.adapter_type), None)
    protects_retrieval = bool(
        adapter
        and adapter["contract_version"] == row.adapter_contract_version
        and adapter["pre_generation_filtering"]
        and adapter["output_verification"]
        and adapter["protect_mode"]
        and row.adapter_type == "accessproof-gateway"
    )
    checks.append({
        "code": "ENFORCEMENT_ADAPTER_CONFIGURED",
        "ok": protects_retrieval,
        "reason": None if protects_retrieval else "This adapter does not provide a verified Layer 1 and Layer 2 Protect boundary.",
    })
    guard = db.get(GuardRegistration, row.guard_id) if row.guard_id else None
    source = db.get(SourceConnection, row.source_id) if row.source_id else None
    heartbeat_ok = bool(guard and guard.last_heartbeat_at and (now - (guard.last_heartbeat_at.replace(tzinfo=timezone.utc) if guard.last_heartbeat_at.tzinfo is None else guard.last_heartbeat_at)).total_seconds() <= settings.guard_offline_seconds)
    checks.append({"code": "APPLICATION_EXISTS", "ok": True, "reason": None})
    checks.append({"code": "TENANT_SCOPE_VALID", "ok": row.organization_id == organization_id, "reason": None if row.organization_id == organization_id else "Application belongs to another organization."})
    checks.append({"code": "GUARD_BOUND", "ok": guard is not None, "reason": None if guard else "Bind an AccessProof Guard."})
    guard_enrolled = bool(guard and guard.enrolled_at is not None)
    guard_revoked = bool(guard and guard.revoked_at is None)
    checks.append({"code": "GUARD_ENROLLED", "ok": guard_enrolled, "reason": None if guard_enrolled else "Enroll the selected Guard."})
    checks.append({"code": "GUARD_NOT_REVOKED", "ok": guard_revoked, "reason": None if guard_revoked else "The selected Guard has been revoked."})
    checks.append({"code": "GUARD_HEARTBEAT_RECENT", "ok": heartbeat_ok, "reason": None if heartbeat_ok else "The selected Guard has no recent heartbeat."})
    installed = bool(guard and guard.active_policy_version > 0 and db.scalar(select(GuardPolicyDistribution.id).where(
        GuardPolicyDistribution.organization_id == organization_id,
        GuardPolicyDistribution.guard_id == guard.id,
        GuardPolicyDistribution.status == "installed",
    )) is not None)
    checks.append({"code": "GUARD_POLICY_INSTALLED", "ok": installed, "reason": None if installed else "The Guard has not installed a policy."})
    source_credentials_ok = bool(source and source.encrypted_credentials)
    if source_credentials_ok and source and source.provider.lower() == "google-drive":
        try:
            credentials = json.loads(_secret_box.decrypt(source.encrypted_credentials or ""))
            source_credentials_ok = bool(
                isinstance(credentials.get("access_token"), str)
                and credentials["access_token"]
                and credentials.get("test_root_folder_id") == source.boundary
            )
        except Exception:
            source_credentials_ok = False
    source_connected = bool(source and source.status == "connected"
                            and source.last_validated_at is not None
                            and not source.last_error and source_credentials_ok)
    if source and source.provider == "google-drive":
        permission_ids_ready = _production_google_drive_permission_ids_ready(db, organization_id)
        checks.append({
            "code": "GOOGLE_DRIVE_PERMISSION_IDENTITIES_VERIFIED",
            "ok": permission_ids_ready,
            "reason": None if permission_ids_ready else "Resolve each active Workspace principal to Google's verified Drive permission ID before Protect.",
        })
        source_connected = source_connected and permission_ids_ready
    # The default Google-only scope stays enforced. Microsoft SharePoint is
    # eligible ONLY with an exact verified effective-permissions certificate.
    source_in_v1_scope = bool(source and v1_source_provider_allowed(source.provider, settings))
    checks.append({"code": "PERMISSION_SOURCE_CONFIGURED", "ok": source_credentials_ok, "reason": None if source_credentials_ok else "Connect a permission source with valid, approved credentials."})
    checks.append({"code": "PERMISSION_SOURCE_TRUSTED", "ok": source_connected, "reason": None if source_connected else "Connect and validate a permission source."})
    microsoft_preview = bool(source and source.provider.lower() in {"microsoft365", "sharepoint", "onedrive"})
    microsoft_certified = False
    if microsoft_preview:
        # Per-source eligibility. No public API issues these certificates:
        # this cannot be satisfied with mock Graph responses, an admin toggle
        # or a healthy Guard heartbeat.
        certified = False
        # D-04: bind before decrypting. A missing/undecryptable credential
        # previously raised UnboundLocalError below, turning the dashboard,
        # activation status and Guard heartbeat into HTTP 500s.
        certificate_credentials: Any = {}
        try:
            certificate_credentials = json.loads(_secret_box.decrypt(source.encrypted_credentials or "")) if source else {}
            certified = effective_source_certified(db, source, certificate_credentials) if source else False
        except Exception:
            # Encryption backend/key failures are never positive ACL proof.
            certified = False
        microsoft_certified = certified
        checks.append({
            "code": "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
            "ok": certified,
            "reason": None if certified else "This exact Microsoft tenant, source, library/drive and permission profile still require independent live-provider certification. Graph sharing records do not prove effective rights.",
        })
        profile = (
            _source_scope(source, certificate_credentials)
            if source and isinstance(certificate_credentials, dict)
            else None
        )
        source_in_v1_scope = source_in_v1_scope or certified_sharepoint_scope_allowed(
            source.provider if source else "",
            provider_profile=profile[0] if profile else None,
            certificate_verified=certified,
            feature_enabled=settings.microsoft_certified_protect,
        )
    checks.append({
        "code": "V1_PROVIDER_SCOPE",
        "ok": source_in_v1_scope,
        "reason": None if source_in_v1_scope else "This source is not yet eligible for Protect. SharePoint requires independent signed effective-permissions certification and explicit production release enablement.",
    })
    acl_cursor = db.scalar(select(ProviderSyncCursorModel).where(
        ProviderSyncCursorModel.organization_id == organization_id,
        ProviderSyncCursorModel.source_id == source.id,
        ProviderSyncCursorModel.sync_kind == "acl",
    )) if source else None
    directory_cursor = db.scalar(select(ProviderSyncCursorModel).where(
        ProviderSyncCursorModel.organization_id == organization_id,
        ProviderSyncCursorModel.source_id == source.id,
        ProviderSyncCursorModel.sync_kind == "directory",
    )) if source else None

    def sync_healthy(cursor: ProviderSyncCursorModel | None, *, max_age_seconds: int) -> bool:
        if cursor is None or cursor.status != "connected" or cursor.last_success_at is None or cursor.last_error_code:
            return False
        checked = cursor.last_success_at
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        return 0 <= (now - checked).total_seconds() <= max_age_seconds

    acl_trusted = sync_healthy(acl_cursor, max_age_seconds=max(
        60, int(os.getenv("ACCESSPROOF_SOURCE_ACL_MAX_AGE_SECONDS", "900"))
    ))
    directory_trusted = sync_healthy(directory_cursor, max_age_seconds=max(
        60, int(os.getenv("ACCESSPROOF_SOURCE_DIRECTORY_MAX_AGE_SECONDS", "900"))
    ))
    checks.append({"code": "PERMISSION_SOURCE_SYNCED", "ok": acl_trusted,
                   "reason": None if acl_trusted else "Complete a recent, trusted permission synchronization."})
    checks.append({"code": "PERMISSION_DIRECTORY_SYNCED", "ok": directory_trusted,
                   "reason": None if directory_trusted else "Synchronize source employees and groups with the necessary provider directory permissions."})
    unresolved_events = bool(source and db.scalar(select(GuardPermissionEvent.id).where(
        GuardPermissionEvent.organization_id == organization_id,
        GuardPermissionEvent.source_id == source.id,
        GuardPermissionEvent.processing_status != "resolved",
    ).limit(1)) is not None)
    checks.append({
        "code": "PERMISSION_EVENTS_RESOLVED", "ok": not unresolved_events,
        "reason": None if not unresolved_events else "Provider permissions are synchronized but authorization policy events remain unresolved.",
    })
    usable = source_connected and acl_trusted and directory_trusted and not unresolved_events
    checks.append({"code": "PERMISSION_SOURCE_USABLE", "ok": usable,
                   "reason": None if usable else "Connect and synchronize both document permissions and the employee directory."})
    # OIDC is configured on the *customer-side Guard*, not the SaaS API.
    # Only accept its authenticated healthy heartbeat as a configuration
    # signal. Actual token verification is tested separately in the pilot.
    # A Guard heartbeat is not evidence that Alice/Bob legitimately signed in
    # through production Entra issuer/JWKS; never infer it from health. For
    # Microsoft sources that evidence is the independently signed source
    # certificate for this exact scope: it cannot be issued unless real
    # EMPLOYEE_OIDC_POSITIVE_IDENTITY / EMPLOYEE_OIDC_SECOND_IDENTITY /
    # IDENTITY_MAPPING_IMMUTABLE_OBJECT_ID checks passed (D-18: previously no
    # Microsoft source could ever satisfy this check, certified or not).
    oidc_ok = (settings.env != "production" or (
        (not microsoft_preview or microsoft_certified)
        and bool(guard and guard.health == "healthy" and heartbeat_ok)
    ))
    checks.append({"code": "PRODUCTION_OIDC_READY", "ok": oidc_ok,
                   "reason": None if oidc_ok else "Real employee Entra issuer/JWKS identity verification remains incomplete; a healthy Guard alone is not sufficient."})
    evidence = _verified_guard_evidence(db, row)
    machine_route_verified = _valid_route_certificate(db, row)
    # Reference-route machine evidence independently proves attestation
    # tamper rejection and in-flight Layer 2 revocation. These checks are
    # not interchangeable with the metadata-only legacy SDK's manual IDs.
    layer1_ok = machine_route_verified or (row.layer1_verified_at is not None and bool(evidence["positive"]) and bool(evidence["denial"]))
    layer2_ok = machine_route_verified or (row.layer2_verified_at is not None and bool(evidence["positive"]) and bool(evidence["provenance"]))
    checks.append({"code": "LAYER1_INTEGRATION_CONFIRMED", "ok": layer1_ok,
                   "reason": None if layer1_ok else "Recent Guard-audited allow and denial test requests required."})
    checks.append({"code": "LAYER2_INTEGRATION_CONFIRMED", "ok": layer2_ok,
                   "reason": None if layer2_ok else "Recent Guard-audited Layer 2 allow and provenance-block tests required."})
    provenance_ok = machine_route_verified or (row.provenance_verified_at is not None and bool(evidence["provenance"]))
    checks.append({"code": "PROVENANCE_READY", "ok": provenance_ok,
                   "reason": None if provenance_ok else "Submit Guard-audited negative provenance evidence."})
    buffering_ok = machine_route_verified or (row.buffering_verified_at is not None and layer2_ok)
    checks.append({"code": "BUFFERED_RESPONSE_GATE_READY", "ok": buffering_ok,
                   "reason": None if buffering_ok else "Run a real RAG buffering test and supply operator attestation with Guard audit IDs."})
    return checks


@app.post("/api/v1/current/ai-applications", status_code=201)
def create_current_ai_application(
    payload: AIApplicationCreate,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = actor.membership.organization_id
    adapter = next((item for item in adapter_registry() if item["id"] == payload.adapter_type), None)
    if (payload.adapter_type != "accessproof-gateway" or adapter is None
            or adapter["contract_version"] != payload.adapter_contract_version):
        raise HTTPException(422, "GATEWAY_ONLY_V1: Register an AccessProof Gateway deployment; SDK integrations are retired.")
    guard = db.get(GuardRegistration, payload.guard_id) if payload.guard_id else None
    if payload.guard_id and (guard is None or guard.organization_id != org_id):
        raise HTTPException(404, "Guard not found")
    sources = payload.source_ids or ([payload.source_id] if payload.source_id else [])
    if (len(sources) != len(set(sources))
            or (payload.source_id and payload.source_ids and payload.source_id not in sources)):
        raise HTTPException(422, "INVALID_APPLICATION_SOURCE_BINDINGS")
    for selected in sources:
        source = db.get(SourceConnection, selected)
        if source is None or source.organization_id != org_id:
            raise HTTPException(404, "Permission source not found")
    primary = payload.source_id or (sources[0] if sources else None)
    archived = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == org_id,
        AIApplication.application_id == payload.application_id,
        AIApplication.archived_at.is_not(None),
    ))
    if archived is not None:
        # Re-registering an archived application restores it (same ID keeps its
        # audit history linked) with fresh bindings and no inherited Protect.
        row = archived
        row.archived_at = None
        row.name, row.guard_id, row.source_id = payload.name, payload.guard_id, primary
        row.mode = "shadow"
        row.adapter_type = payload.adapter_type
        row.adapter_contract_version = payload.adapter_contract_version
        _audit(db, actor, org_id, "AI_APPLICATION_RESTORED", "ai_application", row.id, {})
    else:
        row = AIApplication(
            organization_id=org_id,
            application_id=payload.application_id,
            name=payload.name,
            guard_id=payload.guard_id,
            source_id=primary,
            adapter_type=payload.adapter_type,
            adapter_contract_version=payload.adapter_contract_version,
        )
        db.add(row)
    try:
        db.flush()
        for source_id in sources:
            db.add(AIApplicationSourceBinding(
                organization_id=org_id, application_row_id=row.id, source_id=source_id,
            ))
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(409, "An application with this ID already exists.") from exc
    return {
        "source_ids": sources,
        "id": row.id,
        "application_id": row.application_id,
        "name": row.name,
        "mode": row.mode,
        "adapter_type": row.adapter_type,
        "adapter_contract_version": row.adapter_contract_version,
    }


def _archive_application(db: OrmSession, actor: Actor | None, row: AIApplication, reason: str) -> None:
    """Unbind an application so its traffic fails closed, keeping all history."""
    now = datetime.now(timezone.utc)
    gateway_presence.revoke(db, row)
    for run in db.scalars(select(VerificationRun).where(
        VerificationRun.organization_id == row.organization_id,
        VerificationRun.application_row_id == row.id,
        VerificationRun.superseded_at.is_(None),
    )):
        run.superseded_at = now
        run.state = "SUPERSEDED"
    db.execute(delete(AIApplicationSourceBinding).where(
        AIApplicationSourceBinding.organization_id == row.organization_id,
        AIApplicationSourceBinding.application_row_id == row.id,
    ))
    row.guard_id = None
    row.source_id = None
    row.mode = "shadow"
    row.archived_at = now
    try:
        gateway_pairing.clear(org_id=row.organization_id, app_row_id=row.id)
    except Exception:
        pass  # Redis pairing keys also expire on their own; never block archival
    _audit(db, actor, row.organization_id, "AI_APPLICATION_ARCHIVED", "ai_application", row.id,
           {"reason": reason, "application_id": row.application_id})


@app.post("/api/v1/current/ai-applications/{application_id}/archive")
def archive_current_ai_application(
    application_id: str,
    body: dict[str, Any],
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Remove an AI application from protection without deleting its evidence.

    The caller must repeat the application ID to confirm. Its Guard binding,
    Gateway credential and pending verification are revoked; its chatbot
    traffic through the Gateway is denied from the next Guard policy sync.
    """
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
        AIApplication.archived_at.is_(None),
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    if set(body) != {"confirm_application_id"} or body["confirm_application_id"] != application_id:
        raise HTTPException(422, "CONFIRM_APPLICATION_ID_REQUIRED")
    _archive_application(db, actor, row, "admin_archive")
    db.commit()
    return {"application_id": application_id, "archived": True,
            "message": "Application removed. Its history is kept; traffic through its Gateway is now denied."}


@app.get("/api/v1/current/ai-applications")
def list_current_ai_applications(
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = db.scalars(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.archived_at.is_(None),
    ).order_by(AIApplication.created_at.desc())).all()
    source_rows = db.execute(select(
        AIApplicationSourceBinding.application_row_id,
        AIApplicationSourceBinding.source_id,
    ).where(
        AIApplicationSourceBinding.organization_id == actor.membership.organization_id,
    )).all()
    source_map: dict[str, list[str]] = {}
    for app_row, source in source_rows:
        source_map.setdefault(str(app_row), []).append(str(source))
    return [{
        "id": row.id,
        "application_id": row.application_id,
        "name": row.name,
        "mode": row.mode,
        "guard_id": row.guard_id,
        "source_id": row.source_id,
        "source_ids": sorted(set(source_map.get(row.id, []) + ([row.source_id] if row.source_id else []))),
        "adapter_type": row.adapter_type,
        "adapter_contract_version": row.adapter_contract_version,
        "readiness": _automatic_activation_checklist(db, row),
    } for row in rows]


@app.get("/api/v1/current/ai-applications/{application_id}/protect-readiness")
def current_ai_application_readiness(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(AIApplication.organization_id == actor.membership.organization_id, AIApplication.application_id == application_id))
    if row is None:
        raise HTTPException(404, "AI application not found")
    checks = _automatic_activation_checklist(db, row)
    return {"application_id": application_id, "ready": all(bool(check["ok"]) for check in checks), "checks": checks, "mode": row.mode}


def _automatic_activation_checklist(db: OrmSession, row: AIApplication) -> list[dict[str, Any]]:
    checks = _application_checks(db, row, row.organization_id)
    # Legacy one-source checks are NOT evidence for a multi-source release.
    bound_source_count = int(db.scalar(select(func.count(AIApplicationSourceBinding.id)).where(
        AIApplicationSourceBinding.organization_id == row.organization_id,
        AIApplicationSourceBinding.application_row_id == row.id,
    )) or 0)
    if bound_source_count > 1:
        checks.append({
            "code": "MULTISOURCE_ROUTE_VALIDATION_REQUIRED", "ok": False,
            "reason": "Run source-qualified V2 Guard, mixed-source cached answer and "
                      "real customer-route cutover challenges before enabling Protect.",
        })
    # This is a *reference-only* machine result, not generic zero-code proof.
    # Challenge verification separately matches all four real-response probes
    # to uploaded authenticated Guard audit decisions. Never count an
    # installer label, manual request IDs, or a stale/changed config.
    reference_tested = _reference_challenge_tested(db, row)
    reference_cutover = _valid_route_certificate(db, row)
    checks.append({
        "code": "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED", "ok": reference_tested,
        "reason": None if reference_tested else
        "An enrolled Guard must upload nonce-bound Gateway HTTP and matching Guard audit evidence.",
    })
    checks.append({
        "code": "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED", "ok": reference_cutover,
        "reason": None if reference_cutover else
        "The employee-facing customer RAG route must be re-tested after its explicitly approved deployment cutover and matched with fresh Guard Layer 1/2 audit events.",
    })
    if row.adapter_type == "accessproof-gateway":
        # D-02: an old installation record is not a running Gateway.
        checks.append(gateway_presence.activation_check(db, row))
    approved = _human_activation_approved(db, row)
    checks.append({
        "code": "HUMAN_ACTIVATION_APPROVAL_REQUIRED", "ok": approved,
        "reason": None if approved else
        "An organization owner must explicitly approve Protect activation after the route is certified.",
    })
    return checks


def _human_activation_approved(db: OrmSession, row: AIApplication) -> bool:
    """D-28: Protect is never activated by automation alone.

    Requires an owner's explicit approval recorded AFTER the latest verified
    customer cutover of the currently certified route; any later re-test or
    re-certification requires a new approval. Machines cannot create it.
    """
    cutover = db.scalar(select(RAGRouteChallenge.cutover_at).where(
        RAGRouteChallenge.organization_id == row.organization_id,
        RAGRouteChallenge.application_row_id == row.id,
        RAGRouteChallenge.status == "cutover_verified",
        RAGRouteChallenge.cutover_at.is_not(None),
    ).order_by(RAGRouteChallenge.cutover_at.desc()).limit(1))
    if cutover is None or not _valid_route_certificate(db, row):
        return False
    return db.scalar(select(AuditEvent.id).where(
        AuditEvent.organization_id == row.organization_id,
        AuditEvent.action == "PROTECT_ACTIVATION_APPROVED",
        AuditEvent.target_type == "ai_application",
        AuditEvent.target_id == row.id,
        AuditEvent.actor_user_id.is_not(None),
        AuditEvent.created_at >= cutover,
    ).limit(1)) is not None


def _activation_status(db: OrmSession, row: AIApplication) -> dict[str, Any]:
    # SessionLocal uses autoflush=False: the verified status must be visible
    # to SQL certification lookups *within this transaction*, before deciding
    # whether Guard Protect acknowledgment is eligible.
    db.flush()
    checks = _automatic_activation_checklist(db, row)
    run = db.scalar(select(ProtectionActivationRun).where(
        ProtectionActivationRun.organization_id == row.organization_id,
        ProtectionActivationRun.application_row_id == row.id,
    ))
    failed = next((check for check in checks if not check["ok"]), None)
    # `mode=protect` is a legacy database state and does not prove the new
    # route-challenge protocol; never present it as certified/active here.
    return {
        "application_id": row.application_id,
        "state": "protection_needs_attention" if row.mode == "protect" and failed else
                 "protected" if row.mode == "protect" else
                 "validating" if row.mode == "protect_pending" else
                 "action_required" if run is not None else "protection_not_enabled",
        "checks": checks,
        "reason_code": str((failed or {}).get("code") or "PROTECTION_NOT_CERTIFIED"),
        "message": str((failed or {}).get("reason") or "Integration verification is incomplete."),
        "last_checked_at": run.last_checked_at.isoformat() if run else None,
        "run_id": run.id if run else None,
        "guard_acknowledged": row.mode == "protect" and failed is None,
        "route_certificate": describe_route_certificate(db, row),
    }


def _utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def _age_seconds(value: datetime | None, now: datetime) -> int | None:
    checked = _utc(value)
    if checked is None:
        return None
    return max(0, int((now - checked).total_seconds()))


def _guard_health_state(guard: GuardRegistration | None, now: datetime) -> str:
    if guard is None:
        return "not_bound"
    if guard.revoked_at is not None:
        return "revoked"
    if guard.enrolled_at is None:
        return "not_enrolled"
    age = _age_seconds(guard.last_heartbeat_at, now)
    if age is not None and age <= settings.guard_offline_seconds:
        return "online"
    return "offline"


def _source_sync_age(
    db: OrmSession, source: SourceConnection | None, sync_kind: str, now: datetime
) -> int | None:
    if source is None:
        return None
    cursor = db.scalar(select(ProviderSyncCursorModel).where(
        ProviderSyncCursorModel.organization_id == source.organization_id,
        ProviderSyncCursorModel.source_id == source.id,
        ProviderSyncCursorModel.sync_kind == sync_kind,
    ))
    if cursor is None or cursor.last_success_at is None:
        return None
    return _age_seconds(cursor.last_success_at, now)


def _acl_freshness_limit() -> int:
    return max(60, int(os.getenv("ACCESSPROOF_SOURCE_ACL_MAX_AGE_SECONDS", "900")))


def _directory_freshness_limit() -> int:
    return max(60, int(os.getenv("ACCESSPROOF_SOURCE_DIRECTORY_MAX_AGE_SECONDS", "900")))


def _route_certification_expired(db: OrmSession, row: AIApplication, now: datetime) -> bool:
    if row.adapter_type != "accessproof-gateway":
        return False
    latest = db.scalar(select(RAGRouteChallenge).where(
        RAGRouteChallenge.organization_id == row.organization_id,
        RAGRouteChallenge.application_row_id == row.id,
        RAGRouteChallenge.verified_at.is_not(None),
        RAGRouteChallenge.status.in_(("tested", "cutover_verified")),
    ).order_by(RAGRouteChallenge.verified_at.desc()))
    if latest is None:
        return False
    verified = _utc(latest.verified_at)
    return bool(verified and verified < now - timedelta(hours=24))


def _decision_telemetry(
    db: OrmSession, organization_id: str, application_ids: list[str], now: datetime
) -> tuple[dict[str, dict[str, Any]], dict[str, datetime]]:
    """Aggregate metadata-only Guard decisions without inventing zero telemetry."""
    counts: dict[str, dict[str, Any]] = {}
    latest: dict[str, datetime] = {}
    if not application_ids:
        return counts, latest
    since = now - timedelta(hours=24)
    grouped = db.execute(select(
        GuardAuditEvent.application_id,
        GuardAuditEvent.layer,
        GuardAuditEvent.result,
        func.count(GuardAuditEvent.id),
    ).where(
        GuardAuditEvent.organization_id == organization_id,
        GuardAuditEvent.application_id.in_(application_ids),
        GuardAuditEvent.created_at >= since,
    ).group_by(
        GuardAuditEvent.application_id, GuardAuditEvent.layer, GuardAuditEvent.result,
    )).all()
    for application_id, layer, result, count in grouped:
        bucket = counts.setdefault(application_id, {
            "telemetry": "OBSERVED", "window_hours": 24,
            "layer1": {"allow": 0, "block": 0, "would_allow": 0, "would_block": 0},
            "layer2": {"allow": 0, "block": 0, "would_allow": 0, "would_block": 0},
        })
        layer_key = "layer2" if layer == "layer2" else "layer1"
        if result in bucket[layer_key]:
            bucket[layer_key][result] += int(count)
    for application_id, last_seen in db.execute(select(
        GuardAuditEvent.application_id, func.max(GuardAuditEvent.created_at),
    ).where(
        GuardAuditEvent.organization_id == organization_id,
        GuardAuditEvent.application_id.in_(application_ids),
    ).group_by(GuardAuditEvent.application_id)).all():
        seen = _utc(last_seen)
        if seen is not None:
            latest[application_id] = seen
    return counts, latest


def _protection_snapshot(db: OrmSession, organization_id: str) -> dict[str, Any]:
    """Tenant-scoped truth surface used by both Protection and Overview."""
    now = datetime.now(timezone.utc)
    rows = list(db.scalars(select(AIApplication).where(
        AIApplication.organization_id == organization_id,
        AIApplication.archived_at.is_(None),
    ).order_by(AIApplication.created_at.desc()).limit(200)).all())
    application_ids = [row.application_id for row in rows]
    decision_counts, latest_decisions = _decision_telemetry(db, organization_id, application_ids, now)
    guards = list(db.scalars(select(GuardRegistration).where(
        GuardRegistration.organization_id == organization_id,
    )).all())
    sources = list(db.scalars(select(SourceConnection).where(
        SourceConnection.organization_id == organization_id,
    )).all())
    guard_by_id = {guard.id: guard for guard in guards}
    source_by_id = {source.id: source for source in sources}
    acl_limit, directory_limit = _acl_freshness_limit(), _directory_freshness_limit()

    applications: list[dict[str, Any]] = []
    for row in rows:
        checks = _automatic_activation_checklist(db, row)
        adapter = next((item for item in adapter_registry() if item["id"] == row.adapter_type), None)
        protect_capable = bool(
            adapter
            and adapter["contract_version"] == row.adapter_contract_version
            and adapter["pre_generation_filtering"]
            and adapter["output_verification"]
            and adapter["protect_mode"]
        )
        guard = guard_by_id.get(row.guard_id) if row.guard_id else None
        source = source_by_id.get(row.source_id) if row.source_id else None
        guard_health = _guard_health_state(guard, now)
        source_connected = bool(source is not None and source.status in {"connected", "validated"})
        acl_age = _source_sync_age(db, source, "acl", now)
        directory_age = _source_sync_age(db, source, "directory", now)
        certification_expired = _route_certification_expired(db, row, now)
        effective_state = classify_protection_state(
            checks,
            row.mode,
            adapter_protect_capable=protect_capable,
            has_guard=guard is not None,
            has_source=source is not None,
            guard_revoked=bool(guard is not None and guard.revoked_at is not None),
            source_disconnected=source is not None and not source_connected,
            certification_expired=certification_expired,
        )
        failed_checks = [
            {"code": check["code"], "reason": check.get("reason")}
            for check in checks if not check.get("ok")
        ]
        telemetry = decision_counts.get(row.application_id)
        revision = latest_revision(db, organization_id, row.application_id)
        applications.append({
            "application_id": row.application_id,
            "name": row.name,
            "mode": row.mode,
            "effective_state": effective_state,
            "state_message": STATE_MESSAGES[effective_state],
            "reason_code": failed_checks[0]["code"] if failed_checks else effective_state,
            "authorization_revision": ({
                "schema": AUTHORIZATION_REVISION_SCHEMA,
                "revision": revision.revision,
                "revision_hash": revision.revision_hash,
                "generated_at": revision.generated_at.isoformat() if revision.generated_at else None,
                "source_observed_at": revision.source_observed_at.isoformat() if revision.source_observed_at else None,
            } if revision else None),
            "adapter": {
                "type": row.adapter_type,
                "contract_version": row.adapter_contract_version,
                "protect_capable": protect_capable,
            },
            "guard": {
                "id": guard.id if guard else None,
                "name": guard.name if guard else None,
                "health": guard_health,
                "heartbeat_age_seconds": _age_seconds(guard.last_heartbeat_at, now) if guard else None,
                "policy_version": guard.active_policy_version if guard else None,
            },
            "source": {
                "id": source.id if source else None,
                "name": source.name if source else None,
                "provider": source.provider if source else None,
                "status": source.status if source else None,
                "acl_sync_age_seconds": acl_age,
                "directory_sync_age_seconds": directory_age,
                "acl_fresh": acl_age is not None and acl_age <= acl_limit,
                "directory_fresh": directory_age is not None and directory_age <= directory_limit,
            },
            "gateway": (gateway_presence.connectivity(db, row, now)
                        if row.adapter_type == "accessproof-gateway" else None),
            "route_certification": {
                "required": row.adapter_type == "accessproof-gateway",
                "expired": certification_expired,
                **describe_route_certificate(db, row, now=now),
            },
            "decision_telemetry": telemetry or {
                "telemetry": "NO_DATA", "window_hours": 24,
                "layer1": None, "layer2": None,
            },
            "latest_decision_at": (
                latest_decisions[row.application_id].isoformat()
                if row.application_id in latest_decisions else None
            ),
            "failed_checks": failed_checks,
            "checks": checks,
        })

    state_counts = {state: 0 for state in PROTECTION_STATES}
    for application in applications:
        state_counts[application["effective_state"]] += 1
    guard_buckets = {"online": 0, "offline": 0, "not_enrolled": 0, "revoked": 0}
    for guard in guards:
        bucket = _guard_health_state(guard, now)
        if bucket in guard_buckets:
            guard_buckets[bucket] += 1
    def source_is_fresh(source: SourceConnection) -> bool:
        if source.status not in {"connected", "validated"}:
            return False
        acl_age = _source_sync_age(db, source, "acl", now)
        directory_age = _source_sync_age(db, source, "directory", now)
        return (
            acl_age is not None and acl_age <= acl_limit
            and directory_age is not None and directory_age <= directory_limit
        )

    sources_fresh = sum(1 for source in sources if source_is_fresh(source))
    return {
        "generated_at": now.isoformat(),
        "state_counts": state_counts,
        "totals": {
            "applications_registered": len(applications),
            "applications_protected_verified": state_counts["PROTECTED_VERIFIED"],
            "applications_not_verified": len(applications) - state_counts["PROTECTED_VERIFIED"],
            "applications_unsupported": state_counts["UNSUPPORTED"],
            "guards_total": len(guards),
            "guards_online": guard_buckets["online"],
            "guards": guard_buckets,
            "sources_total": len(sources),
            "sources_fresh": sources_fresh,
            "sources_stale": len(sources) - sources_fresh,
        },
        "applications": applications,
    }


@app.get("/api/v1/current/protection/overview")
def current_protection_overview(
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Backend-derived per-application protection truth for the active tenant.

    Unknown or missing telemetry is returned as an explicit state; no static UI
    value, mode flag, or Guard-online signal can promote an application here.
    """
    return _protection_snapshot(db, actor.membership.organization_id)


@app.get("/api/v1/current/capabilities")
def current_capabilities(
    _actor: Actor = Depends(require(Permission.RESULT_READ)),
) -> dict[str, Any]:
    """Canonical product support registry; never a per-tenant certificate."""
    return capability_registry_snapshot()


@app.get("/api/v1/current/authorization-revisions")
def current_authorization_revisions(
    application_id: str | None = None,
    limit: int = 50,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Tenant-scoped authorization revision ledger with independent verification."""
    bounded = max(1, min(limit, 200))
    query = select(AuthorizationRevision).where(
        AuthorizationRevision.organization_id == actor.membership.organization_id,
    )
    if application_id:
        query = query.where(AuthorizationRevision.application_id == application_id)
    rows = list(db.scalars(query.order_by(
        AuthorizationRevision.generated_at.desc(),
        AuthorizationRevision.revision.desc(),
    ).limit(bounded)).all())
    revisions = []
    for row in rows:
        envelope = revision_envelope(row)
        revisions.append({
            **envelope,
            "verification": {
                "signature_valid": verify_manifest(envelope["payload"], envelope["signature"]),
                "chain_linked": row.revision == 1 or row.previous_revision_hash is not None,
                "evidence_level": "DIRECTLY_OBSERVED_BY_ACCESSPROOF",
            },
        })
    return {
        "schema": AUTHORIZATION_REVISION_SCHEMA,
        "revisions": revisions,
        "limitations": REVISION_LIMITATIONS,
    }


@app.get("/api/v1/current/revocation-timeline")
def current_revocation_timeline(
    application_id: str,
    limit: int = 20,
    actor: Actor = Depends(require(Permission.AUDIT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Six-timestamp, privacy-safe timeline from retained evidence only."""
    try:
        return build_revocation_timeline(
            db, organization_id=actor.membership.organization_id,
            application_id=application_id, limit=limit,
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/v1/current/ai-applications/{application_id}/protection/status")
def current_ai_application_protection_status(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    return _activation_status(db, row)


@app.post("/api/v1/current/ai-applications/{application_id}/protection/enable", status_code=202)
@app.post("/api/v1/current/ai-applications/{application_id}/protection/retry", status_code=202)
def current_ai_application_automated_preflight(
    application_id: str,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ).with_for_update())
    if row is None:
        raise HTTPException(404, "AI application not found")
    if row.mode == "protect":
        # Do not alter an existing protecting installation while the new
        # verification protocol is incomplete; health is still reported.
        return _activation_status(db, row)
    checks = _automatic_activation_checklist(db, row)
    now = datetime.now(timezone.utc)
    fingerprint = _route_configuration_fingerprint(row)
    run = db.scalar(select(ProtectionActivationRun).where(
        ProtectionActivationRun.organization_id == row.organization_id,
        ProtectionActivationRun.application_row_id == row.id,
    ).with_for_update())
    if run is None:
        run = ProtectionActivationRun(
            organization_id=row.organization_id, application_row_id=row.id,
            requested_by_user_id=actor.user.id, state="action_required",
            guard_id=row.guard_id, source_id=row.source_id,
            configuration_fingerprint=fingerprint,
            checks_json=json.dumps(checks, sort_keys=True),
            reason_code="CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
            created_at=now, last_checked_at=now,
        )
        db.add(run)
    else:
        run.requested_by_user_id = actor.user.id
        run.guard_id, run.source_id = row.guard_id, row.source_id
        run.configuration_fingerprint = fingerprint
        run.checks_json = json.dumps(checks, sort_keys=True)
        run.state = "action_required"
        run.reason_code = "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED"
        run.last_checked_at = now
    if all(check["ok"] for check in checks) and row.mode == "shadow":
        row.mode = "protect_pending"
        run.state = "awaiting_guard_ack"
        run.reason_code = "GUARD_PROTECT_ACK_REQUIRED"
    _audit(db, actor, row.organization_id, "PROTECTION_PREFLIGHT_REQUESTED", "ai_application", row.id, {
        "result": "action_required", "failed_check_codes": [c["code"] for c in checks if not c["ok"]],
    })
    try:
        db.commit()
    except IntegrityError:
        # Concurrent first-click duplicate cannot create multiple runs. The
        # unique tenant/application key is authoritative; retry only the read.
        db.rollback()
    return _activation_status(db, row)


def _automatic_gateway_pairing_verification(
    db: OrmSession, row: AIApplication,
) -> dict[str, Any]:
    """Immediately assess readiness after a tenant-bound Gateway pairing.

    This is a read-only checklist snapshot: no user traffic, Guard challenges,
    source certification, cutover, or Protect state may be altered.
    """
    try:
        checks = _automatic_activation_checklist(db, row)
        if not checks or any(
            not isinstance(check, dict)
            or not isinstance(check.get("code"), str)
            or type(check.get("ok")) is not bool
            for check in checks
        ):
            raise ValueError("Invalid verification result")
        failures = [check["code"] for check in checks if not check["ok"]]
        # A green preflight is NEVER sufficient to approve Protect. Real
        # machine-audited challenges and customer cutover are separate.
        return {
            "state": "checks_passed_requires_independent_review" if not failures else "action_required",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "checks_passed": len(checks) - len(failures),
            "checks_total": len(checks),
            "failed_check_codes": failures,
            "production_certification": False,
            "protect_activated": False,
            "next_action": (
                "Complete independent Guard challenge and customer-approved cutover."
                if not failures else "Resolve the listed prerequisite checks; the dashboard refreshes automatically."
            ),
        }
    except Exception:
        return {
            "state": "verification_unavailable",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "checks_passed": 0,
            "checks_total": 0,
            "failed_check_codes": ["AUTOMATIC_READINESS_CHECK_UNAVAILABLE"],
            "production_certification": False,
            "protect_activated": False,
            "next_action": "Retry the dashboard security preflight; Protect remains blocked.",
        }


@app.post("/api/v1/current/ai-applications/{application_id}/gateway-pairing", status_code=201)
def issue_customer_gateway_pairing(
    application_id: str,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate a 15-minute private, application-scoped customer pairing file."""
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if (row is None or row.adapter_type != "accessproof-gateway"
            or row.source_id is None or not row.guard_id):
        raise HTTPException(409, "APPLICATION_SOURCE_AND_GUARD_BINDING_REQUIRED")
    guard = db.get(GuardRegistration, row.guard_id)
    if (guard is None or guard.organization_id != row.organization_id
            or guard.revoked_at is not None or guard.enrolled_at is None):
        raise HTTPException(409, "ENROLLED_GUARD_REQUIRED")
    try:
        pairing = gateway_pairing.issue(
            org_id=row.organization_id, app_row_id=row.id,
            application_id=row.application_id, api_url=settings.api_public_url,
        )
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_PAIRING_TEMPORARILY_UNAVAILABLE") from exc
    _audit(db, actor, row.organization_id, "GATEWAY_PAIRING_ISSUED", "ai_application", row.id, {})
    db.commit()
    return pairing


def _durable_gateway_installation_status(
    db: OrmSession, row: AIApplication, transient: dict[str, Any],
) -> dict[str, Any]:
    """Recover an *old installation record* without inventing Gateway liveness.

    The authenticated pairing claim already stores a durable verification run,
    scoped to this exact tenant/application/Guard/source. The Redis pairing
    receipt expires after 24 hours and is not a reliable installation history.
    Never use a stale run as evidence for production Protect or live reachability.
    """
    if transient.get("state") not in {"not_started", "pairing_expired"}:
        return transient
    if not row.guard_id or not row.source_id:
        return transient
    set_tenant_context(db, row.organization_id)
    run = db.scalar(select(VerificationRun).where(
        VerificationRun.organization_id == row.organization_id,
        VerificationRun.application_row_id == row.id,
        VerificationRun.guard_id == row.guard_id,
        VerificationRun.source_id == row.source_id,
        VerificationRun.superseded_at.is_(None),
        VerificationRun.state != "SUPERSEDED",
    ).order_by(VerificationRun.created_at.desc()).limit(1))
    if run is None:
        return transient
    return {
        "state": "installation_reported_historical",
        "received_at": run.created_at.isoformat(),
        "verification_run_state": run.state,
        "route_sha256": run.route_sha256,
        "deployment_sha256": run.deployment_sha256,
        "live_gateway_verified": False,
        "production_certification": False,
        "message": (
            "Previously authenticated installation on record. This does not "
            "prove that the Gateway is running or currently protecting traffic."
        ),
    }


@app.get("/api/v1/current/ai-applications/{application_id}/gateway-pairing")
def get_customer_gateway_pairing(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    try:
        status = gateway_pairing.status(org_id=row.organization_id, app_row_id=row.id)
        status = _durable_gateway_installation_status(db, row, status)
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_PAIRING_TEMPORARILY_UNAVAILABLE") from exc
    if status.get("state") == "installation_reported_unverified":
        status["verification"] = _automatic_gateway_pairing_verification(db, row)
    # Live connectivity is separate from (possibly historical) installation.
    status["gateway_connectivity"] = gateway_presence.connectivity(db, row)
    return status


@app.post("/api/v1/gateway-installations/heartbeat")
def gateway_installation_heartbeat(
    payload: gateway_presence.GatewayHeartbeat,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Machine-only Gateway presence. Never activates or certifies Protect."""
    return gateway_presence.record_heartbeat(db, payload, authorization)


@app.get("/api/v1/current/ai-applications/{application_id}/gateway-discovery")
def get_current_gateway_discovery(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Session-scoped listing of sanitized inventory reported by the paired host."""
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None or row.adapter_type != "accessproof-gateway":
        raise HTTPException(404, "AI application not found")
    try:
        return gateway_pairing.discovery_status(org_id=row.organization_id, app_row_id=row.id)
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_DISCOVERY_TEMPORARILY_UNAVAILABLE") from exc


@app.post("/api/v1/current/ai-applications/{application_id}/gateway-discovery/select")
def select_current_gateway_chatbot(
    application_id: str,
    body: dict[str, Any],
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """An organization admin chooses exactly ONE compatible chatbot.

    Selection grants no remote execution capability and NEVER enables Protect.
    """
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None or row.adapter_type != "accessproof-gateway":
        raise HTTPException(404, "AI application not found")
    if set(body) != {"stable_id"}:
        raise HTTPException(422, "SELECT_EXACTLY_ONE_CHATBOT")
    try:
        result = gateway_pairing.select_discovered(
            org_id=row.organization_id, app_row_id=row.id, stable_id=body["stable_id"],
        )
    except gateway_pairing.PairingError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_DISCOVERY_TEMPORARILY_UNAVAILABLE") from exc
    _audit(db, actor, row.organization_id, "GATEWAY_CHATBOT_SELECTED", "ai_application", row.id,
           {"selected_discovery_id": result["selected_id"]})
    db.commit()
    return result


@app.post("/api/v1/gateway-pairings/discovery")
def submit_customer_gateway_discovery(
    body: dict[str, Any], authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "PAIRING_TOKEN_REQUIRED")
    if set(body) != {"applications"}:
        raise HTTPException(422, "DISCOVERY_INVALID_FIELDS")
    try:
        return gateway_pairing.publish_discovery(
            token=authorization.removeprefix("Bearer "), applications=body["applications"],
        )
    except gateway_pairing.PairingError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_DISCOVERY_TEMPORARILY_UNAVAILABLE") from exc


@app.get("/api/v1/gateway-pairings/discovery/selection")
def customer_gateway_selected_chatbot(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "PAIRING_TOKEN_REQUIRED")
    try:
        return gateway_pairing.selected_for_host(token=authorization.removeprefix("Bearer "))
    except gateway_pairing.PairingError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_DISCOVERY_TEMPORARILY_UNAVAILABLE") from exc


@app.post("/api/v1/gateway-pairings/claim", status_code=202)
def claim_customer_gateway_pairing(
    installation: dict[str, Any],
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """One-time customer-side installation report, not Protect evidence."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "PAIRING_TOKEN_REQUIRED")
    validated_application: list[AIApplication] = []

    def eligible(org_id: str, row_id: str, application_id: str) -> bool:
        # org_id comes from the server-side pairing record matched by the
        # one-use token, never from the caller; scope RLS reads to it.
        set_tenant_context(db, org_id)
        row = db.get(AIApplication, row_id)
        if (row is None or row.organization_id != org_id
                or row.application_id != application_id
                or row.adapter_type != "accessproof-gateway"
                or row.source_id is None or not row.guard_id):
            return False
        guard = db.get(GuardRegistration, row.guard_id)
        valid = bool(guard and guard.organization_id == org_id
                     and guard.enrolled_at is not None and guard.revoked_at is None)
        if valid:
            validated_application.append(row)
        return valid
    try:
        result = gateway_pairing.receive(
            token=authorization.removeprefix("Bearer "), installation=installation,
            application_is_valid=eligible,
        )
        # This runs only after successful one-use token validation and
        # application/source/Guard binding checks. Never act on caller IDs.
        if len(validated_application) != 1:
            raise RuntimeError("Authenticated pairing lacks a unique application")
        result["verification"] = _automatic_gateway_pairing_verification(
            db, validated_application[0],
        )
        # The authorized one-use pairing claim is the automatic trigger.
        # If the API crashes between Redis acceptance and DB commit, the
        # worker safely reconstructs this same run from pairing status.
        row = validated_application[0]
        # Pairing is machine-authenticated without a browser actor. The new
        # forced-RLS verification tables need the tenant from the validated
        # server-side application binding, never a caller supplied org ID.
        set_tenant_context(db, row.organization_id)
        run = verification_engine.start_or_resume(
            db, row, deployment=installation["deployment_sha256"],
            route=installation["route_sha256"],
        )
        # D-02: a durable, rotatable machine identity for authenticated
        # heartbeats. Returned exactly once; only its hash is stored.
        record, gateway_credential = gateway_presence.issue_installation(
            db, row, deployment_sha256=installation["deployment_sha256"],
            route_sha256=installation["route_sha256"],
        )
        _audit(db, None, row.organization_id, "GATEWAY_INSTALLATION_CREDENTIAL_ISSUED",
               "ai_application", row.id, {"installation_id": record.id})
        db.commit()
        result["verification_run_id"] = run.id
        result["gateway_presence"] = {
            "control_plane_url": settings.api_public_url.rstrip("/"),
            "organization_id": row.organization_id,
            "installation_id": record.id,
            "credential": gateway_credential,
            "application_id": row.application_id,
            "route_sha256": installation["route_sha256"],
        }
        return result
    except gateway_pairing.PairingError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "GATEWAY_PAIRING_TEMPORARILY_UNAVAILABLE") from exc


@app.get("/api/v1/current/ai-applications/{application_id}/verification-run")
def current_verification_run(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Read durable server-side verification state, without initiating Protect."""
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    run = verification_engine.newest_run(db, row)
    if run is None:
        return {"state": "NOT_STARTED", "run_id": None, "steps": [],
                "checks_passed": 0, "checks_total": 0,
                "protect_activated": False, "production_certification": False}
    result = verification_engine.describe(db, run)
    guard = db.get(GuardRegistration, row.guard_id) if row.guard_id else None
    heartbeat_age = _age_seconds(guard.last_heartbeat_at, datetime.now(timezone.utc)) if guard else None
    online = guard is not None and guard.revoked_at is None and (
        heartbeat_age is not None and heartbeat_age <= settings.guard_offline_seconds
    )
    result["guard"] = {
        "connectivity": "CONNECTED" if online else "OFFLINE",
        "security_readiness": "DEGRADED" if online and guard is not None and guard.health != "healthy" else (
            "READY" if online else "UNKNOWN"),
        "heartbeat_age_seconds": heartbeat_age,
        "offline_threshold_seconds": settings.guard_offline_seconds,
    }
    return result


@app.post("/api/v1/current/ai-applications/{application_id}/verification-approvals", status_code=201)
def approve_current_verification_scope(
    application_id: str,
    payload: dict[str, Any],
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Record an explicitly acknowledged customer scope, NOT provider admin consent."""
    if set(payload) != {"approval_type", "scope_fingerprint", "acknowledge"} or payload["acknowledge"] is not True:
        raise HTTPException(422, "EXPLICIT_APPROVAL_AND_EXACT_FINGERPRINT_REQUIRED")
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ).with_for_update())
    if row is None:
        raise HTTPException(404, "AI application not found")
    run = verification_engine.newest_run(db, row)
    if run is None:
        raise HTTPException(409, "VERIFICATION_RUN_NOT_STARTED")
    try:
        approval = verification_engine.record_scoped_approval(
            db, run, actor_id=actor.user.id,
            approval_type=str(payload["approval_type"]),
            acknowledged_fingerprint=str(payload["scope_fingerprint"]),
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    return {
        "id": approval.id, "approval_type": approval.approval_type,
        "expires_at": approval.expires_at.isoformat(),
        "state": "OWNER_APPROVED_PENDING_INDEPENDENT_VERIFICATION",
        "protect_activated": False, "production_certification": False,
    }


@app.get("/api/v1/current/ai-applications/{application_id}/verification-approvals")
def list_current_verification_approvals(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    run = verification_engine.newest_run(db, row)
    if not run:
        return {"approvals": []}
    records = db.scalars(select(VerificationApproval).where(
        VerificationApproval.organization_id == row.organization_id,
        VerificationApproval.run_id == run.id,
    ).order_by(VerificationApproval.approved_at.desc())).all()
    return {"approvals": [{
        "type": a.approval_type,
        "state": "RECORDED" if a.consumed_at is None and (a.expires_at.replace(tzinfo=timezone.utc) if a.expires_at.tzinfo is None else a.expires_at) > datetime.now(timezone.utc) else "EXPIRED_OR_CONSUMED",
        "expires_at": a.expires_at.isoformat(),
    } for a in records]}


@app.get("/api/v1/current/ai-applications/{application_id}/verification-events")
def current_verification_events(
    application_id: str,
    limit: int = 40,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Tenant-scoped append-only event summaries; never expose secrets or source content."""
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    run = verification_engine.newest_run(db, row)
    if not run:
        return {"events": []}
    events = db.scalars(select(VerificationEvent).where(
        VerificationEvent.organization_id == row.organization_id,
        VerificationEvent.run_id == run.id,
    ).order_by(VerificationEvent.created_at.desc(), VerificationEvent.id.desc()).limit(min(max(limit, 1), 100))).all()
    return {"events": [
        {"id": item.id, "code": item.code, "state": item.state,
         "detail": item.detail, "created_at": item.created_at.isoformat()}
        for item in events
    ]}


@app.get("/api/v1/current/ai-applications/{application_id}/verification-stream")
async def stream_verification_events(
    application_id: str,
    request: Request,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> StreamingResponse:
    """Authenticated SSE with bounded replay, tenant binding and reconnect."""
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    org_id, app_row_id = row.organization_id, row.id
    # Authentication has already happened. Do not hold its transaction across
    # streaming; separate read-only scoped transactions are short lived.
    db.rollback()

    async def generate() -> AsyncIterator[str]:
        after = request.headers.get("last-event-id", "")
        # Unknown user-controlled cursors cannot select another tenant or
        # inject SSE control characters; invalid cursor simply starts fresh.
        if len(after) > 80 or any(c not in "0123456789abcdef-" for c in after):
            after = ""
        last_emit = time.monotonic()
        last_presence = ""
        for _ in range(150):  # ~5 min max; browsers reconnect automatically.
            if await request.is_disconnected():
                break
            with SessionLocal() as stream_db:
                set_tenant_context(stream_db, org_id)
                run = stream_db.scalar(select(VerificationRun).where(
                    VerificationRun.organization_id == org_id,
                    VerificationRun.application_row_id == app_row_id,
                    VerificationRun.superseded_at.is_(None),
                ).order_by(VerificationRun.created_at.desc()).limit(1))
                # Connectivity is a separate, read-only live channel; it does
                # not promote the application or certify the source/route.
                application = stream_db.get(AIApplication, app_row_id)
                guard = stream_db.get(GuardRegistration, application.guard_id) if application and application.guard_id else None
                age = _age_seconds(guard.last_heartbeat_at, datetime.now(timezone.utc)) if guard else None
                connected = bool(guard and guard.revoked_at is None and age is not None
                                 and age <= settings.guard_offline_seconds)
                presence = "CONNECTED" if connected else "OFFLINE"
                security = ("READY" if connected and guard is not None and guard.health == "healthy"
                            else "DEGRADED" if connected else "UNKNOWN")
                marker = presence + ":" + security
                if marker != last_presence:
                    yield "event: presence\ndata: " + json.dumps(
                        {"connectivity": presence, "security_readiness": security},
                        separators=(",", ":")) + "\n\n"
                    last_presence = marker
                    last_emit = time.monotonic()
                # Bounded event read. Run changes send a fresh snapshot.
                if run:
                    recent = stream_db.scalars(select(VerificationEvent).where(
                        VerificationEvent.organization_id == org_id,
                        VerificationEvent.run_id == run.id,
                    ).order_by(VerificationEvent.created_at.desc(), VerificationEvent.id.desc()).limit(40)).all()
                    ordered = list(reversed(recent))
                    if after in {event.id for event in ordered}:
                        ordered = ordered[[event.id for event in ordered].index(after) + 1:]
                    elif after:
                        # A cursor from a superseded run is not an access grant.
                        ordered = ordered[-1:]
                    for event in ordered:
                        payload = json.dumps({
                            "run_id": run.id, "code": event.code,
                            "state": event.state,
                        }, separators=(",", ":"))
                        yield f"id: {event.id}\nevent: verification\ndata: {payload}\n\n"
                        after = event.id
                        last_emit = time.monotonic()
            if time.monotonic() - last_emit >= 12:
                yield ": keepalive\n\n"
                last_emit = time.monotonic()
            await asyncio.sleep(2)
    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache, no-store",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/v1/current/ai-applications/{application_id}/protection/challenge", status_code=201)
def issue_current_reference_rag_challenge(
    application_id: str,
    payload: RouteChallengeStart,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Issue one use, operator-bound nonce for the enrolled customer-side agent.

    The challenge is only defined for an explicit signed-manifest Gateway
    reference route. Issuing it does not certify installation or enable any
    customer application automatically.
    """
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ).with_for_update())
    if row is None:
        raise HTTPException(404, "AI application not found")
    guard = db.get(GuardRegistration, row.guard_id) if row.guard_id else None
    if (row.adapter_type != "accessproof-gateway" or row.source_id is None
            or guard is None or guard.organization_id != row.organization_id
            or guard.revoked_at is not None or guard.enrolled_at is None
            or guard.active_policy_version < 1):
        raise HTTPException(409, "REGISTERED_REFERENCE_GATEWAY_WITH_ENROLLED_GUARD_REQUIRED")
    if row.mode == "protect":
        raise HTTPException(409, "ACTIVE_PROTECT_REQUIRES_CONTROLLED_RECERTIFICATION")
    now = datetime.now(timezone.utc)
    # Mark previous unconsumed nonce unusable. A new issue invalidates it.
    for prior in db.scalars(select(RAGRouteChallenge).where(
        RAGRouteChallenge.organization_id == row.organization_id,
        RAGRouteChallenge.application_row_id == row.id,
        RAGRouteChallenge.status == "issued",
    )):
        prior.status = "superseded"
    nonce = secrets.token_urlsafe(40)
    while True:
        digest = hashlib.sha256(nonce.encode()).hexdigest()
        if db.scalar(select(RAGRouteChallenge.id).where(RAGRouteChallenge.nonce_digest == digest)) is None:
            break
        nonce = secrets.token_urlsafe(40)
    record = RAGRouteChallenge(
        organization_id=row.organization_id,
        application_row_id=row.id,
        guard_id=guard.id,
        source_id=row.source_id,
        nonce_digest=digest,
        configuration_fingerprint=_route_configuration_fingerprint(row),
        deployment_sha256=payload.deployment_sha256,
        route_sha256=payload.route_sha256,
        expires_at=now + timedelta(minutes=10),
        created_at=now,
        status="issued",
        result_json="{}",
    )
    db.add(record)
    db.flush()
    # Pending mode enforces Guard protect on the test route. However a Guard
    # heartbeat MUST NOT mark this protected until the evidence gate passes.
    if row.mode == "shadow":
        row.mode = "protect_pending"
    _audit(db, actor, row.organization_id, "RAG_ROUTE_CHALLENGE_ISSUED", "ai_application", row.id, {
        "challenge_id": record.id, "guard_id": guard.id,
    })
    db.commit()
    return {
        "challenge_id": record.id, "nonce": nonce,
        "guard_id": guard.id, "application_id": row.application_id,
        "expires_at": record.expires_at.isoformat(),
        "request_ids": request_ids(nonce),
        "state": "issued", "production_certification": False,
        "message": "Run only against the approved, isolated synthetic reference route; Guard machine audit evidence is required.",
    }


@app.get("/api/v1/current/ai-applications/{application_id}/protection/challenge")
def latest_current_reference_rag_challenge(
    application_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ))
    if row is None:
        raise HTTPException(404, "AI application not found")
    record = db.scalar(select(RAGRouteChallenge).where(
        RAGRouteChallenge.organization_id == row.organization_id,
        RAGRouteChallenge.application_row_id == row.id,
    ).order_by(RAGRouteChallenge.created_at.desc(), RAGRouteChallenge.id.desc()))
    return {
        "application_id": row.application_id,
        "state": record.status if record is not None else "not_requested",
        "challenge_id": record.id if record is not None else None,
        "verified_at": record.verified_at.isoformat() if record is not None and record.verified_at else None,
        "certified_for_reference_route": _valid_route_certificate(db, row),
        "production_certification": False,
    }


@app.post("/api/v1/current/ai-applications/{application_id}/protection/approve", status_code=201)
def approve_protect_activation(
    application_id: str,
    payload: dict[str, Any],
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """D-28: explicit, owner-only human approval for Protect activation.

    Accepted only from an interactive OWNER session (never an API key or a
    machine), only after the route certificate is valid, and only with the
    exact confirmation text. It approves; the Guard acknowledgment and every
    other activation check still apply.
    """
    if actor.api_key_scopes is not None or actor.membership.role != Role.OWNER.value:
        raise HTTPException(403, "OWNER_SESSION_REQUIRED")
    if not isinstance(payload, dict) or set(payload) != {"confirm_text", "reviewer"}:
        raise HTTPException(422, "INVALID_APPROVAL")
    reviewer = payload.get("reviewer")
    if not isinstance(reviewer, str) or not 3 <= len(reviewer.strip()) <= 200:
        raise HTTPException(422, "REVIEWER_NAME_REQUIRED")
    if payload.get("confirm_text") != f"APPROVE PROTECT {application_id}":
        raise HTTPException(422, "CONFIRMATION_TEXT_MISMATCH")
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == actor.membership.organization_id,
        AIApplication.application_id == application_id,
    ).with_for_update())
    if row is None:
        raise HTTPException(404, "AI application not found")
    if not _valid_route_certificate(db, row):
        raise HTTPException(409, "ROUTE_CERTIFICATE_REQUIRED_BEFORE_APPROVAL")
    pending = [c["code"] for c in _automatic_activation_checklist(db, row)
               if not c["ok"] and c["code"] != "HUMAN_ACTIVATION_APPROVAL_REQUIRED"]
    if pending:
        raise HTTPException(409, {"code": "ACTIVATION_CHECKS_INCOMPLETE", "pending": pending})
    _audit(db, actor, row.organization_id, "PROTECT_ACTIVATION_APPROVED", "ai_application", row.id, {
        "reviewer": reviewer.strip(), "route_certificate": describe_route_certificate(db, row).get("certificate_id"),
    })
    db.commit()
    return {"state": "approved_awaiting_guard_ack", "application_id": application_id,
            "guard_acknowledgment_required": True}


@app.post("/api/v1/guards/{guard_id}/rag-challenges/{challenge_id}/submit", status_code=202)
def submit_enrolled_guard_rag_challenge(
    guard_id: str,
    challenge_id: str,
    payload: RouteChallengeResult,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Replay-resistant, bound machine results corroborated by Guard audits.

    A mere client-reported success is not enough: all four Guard decision
    sequences must exist and agree with the observed HTTP responses. This
    certifies only the declared Gateway reference boundary, not arbitrary RAG.
    """
    guard = _authenticate_guard(db, guard_id, authorization)
    if payload.guard_id != guard.id or payload.challenge_id != challenge_id:
        raise HTTPException(403, "GUARD_CHALLENGE_BINDING_MISMATCH")
    record = db.scalar(select(RAGRouteChallenge).where(
        RAGRouteChallenge.id == challenge_id,
        RAGRouteChallenge.guard_id == guard.id,
        RAGRouteChallenge.organization_id == guard.organization_id,
    ).with_for_update())
    if record is None:
        raise HTTPException(404, "Reference challenge not found")
    now = datetime.now(timezone.utc)
    expires_at = record.expires_at.replace(tzinfo=timezone.utc) if record.expires_at.tzinfo is None else record.expires_at
    if record.status != "issued" or now >= expires_at:
        raise HTTPException(409, "CHALLENGE_EXPIRED_CONSUMED_OR_SUPERSEDED")
    if hashlib.sha256(payload.nonce.encode()).hexdigest() != record.nonce_digest:
        raise HTTPException(403, "INVALID_CHALLENGE_NONCE")
    row = db.get(AIApplication, record.application_row_id)
    if (row is None or row.organization_id != guard.organization_id
            or row.guard_id != guard.id or row.source_id != record.source_id
            or row.adapter_type != "accessproof-gateway"
            or guard.revoked_at or guard.active_policy_version < 1
            or _route_configuration_fingerprint(row)
            != record.configuration_fingerprint):
        raise HTTPException(409, "CHALLENGE_DEPLOYMENT_OR_POLICY_CHANGED")
    if (payload.deployment_sha256 != record.deployment_sha256
            or payload.route_sha256 != record.route_sha256):
        raise HTTPException(409, "CHALLENGE_DEPLOYMENT_FINGERPRINT_MISMATCH")
    # This Guard-bound agent must actually have probed each boundary. An
    # arbitrary remote browser cannot submit the results with an admin cookie.
    if not all((
        payload.customer_route_verified, payload.ingress_boundary_verified,
        payload.retrieval_boundary_verified, payload.output_boundary_verified,
        payload.alternate_route_blocked,
    )):
        raise HTTPException(409, "COMPLETE_CUSTOMER_BOUNDARY_EVIDENCE_REQUIRED")
    requested = list(request_ids(payload.nonce).values())
    events = list(db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == guard.organization_id,
        GuardAuditEvent.guard_id == guard.id,
        GuardAuditEvent.application_id == row.application_id,
        GuardAuditEvent.request_id.in_(requested),
        GuardAuditEvent.created_at >= record.created_at,
        GuardAuditEvent.policy_version > 0,
    )).all())
    verified, reason = verify_reference_evidence(
        nonce=payload.nonce, observations=payload.observations,
        guard_events=events, source_id=record.source_id,
        guard_policy_version=guard.active_policy_version,
    )
    if not verified:
        raise HTTPException(409, {"code": reason})
    record.status = "tested"
    record.verified_at = now
    record.result_json = json.dumps({
        "contract": payload.contract,
        "route_sha256": payload.route_sha256,
        "deployment_sha256": payload.deployment_sha256,
        "observations": [
            {"name": item["name"], "request_id": item["request_id"],
             "http_status": item["http_status"], "response_sha256": item["response_sha256"]}
            for item in payload.observations
        ],
        "matched_guard_events": len(events),
        # D-26: rollback protection (see route_certification.verified_policy_version).
        "guard_policy_version_at_verification": int(guard.active_policy_version),
    }, sort_keys=True)
    # SessionLocal uses autoflush=False: the verified status must be visible
    # to SQL certification lookups *within this transaction*, before deciding
    # whether Guard Protect acknowledgment is eligible.
    db.flush()
    checks = _automatic_activation_checklist(db, row)
    run = db.scalar(select(ProtectionActivationRun).where(
        ProtectionActivationRun.organization_id == row.organization_id,
        ProtectionActivationRun.application_row_id == row.id,
    ))
    if run:
        run.last_checked_at = now
        run.checks_json = json.dumps(checks, sort_keys=True)
        if all(check["ok"] for check in checks):
            run.state = "awaiting_guard_ack"
            run.reason_code = "GUARD_PROTECT_ACK_REQUIRED"
            row.mode = "protect_pending"
        else:
            run.state = "action_required"
            run.reason_code = next(check["code"] for check in checks if not check["ok"])
    _audit(db, None, guard.organization_id, "RAG_ROUTE_CHALLENGE_VERIFIED", "ai_application", row.id, {
        "challenge_id": record.id, "guard_id": guard.id, "guard_event_count": len(events),
        "result": "reference_verified", "pending_source_or_guard_checks": not all(check["ok"] for check in checks),
    })
    db.commit()
    return {
        "state": "tested_awaiting_customer_cutover", "challenge_id": record.id,
        "guard_audits_matched": len(events),
        "protection_ready": all(check["ok"] for check in checks),
        "production_certification": False,
        "pending_guard_acknowledgment": False,
    }


@app.get("/api/v1/guards/{guard_id}/rag-challenges/{challenge_id}")
def get_enrolled_guard_rag_challenge(
    guard_id: str, challenge_id: str,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Machine-only, bounded reference challenge state; no source secrets."""
    guard = _authenticate_guard(db, guard_id, authorization)
    record = db.scalar(select(RAGRouteChallenge).where(
        RAGRouteChallenge.id == challenge_id,
        RAGRouteChallenge.guard_id == guard.id,
        RAGRouteChallenge.organization_id == guard.organization_id,
    ))
    if record is None:
        raise HTTPException(404, "Reference challenge not found")
    row = db.get(AIApplication, record.application_row_id)
    if row is None or row.organization_id != guard.organization_id:
        raise HTTPException(404, "Bound application not found")
    return {
        "challenge_id": record.id, "state": record.status,
        "guard_id": guard.id, "application_id": row.application_id,
        "deployment_sha256": record.deployment_sha256,
        "route_sha256": record.route_sha256,
        "verified_at": record.verified_at.isoformat() if record.verified_at else None,
        "production_certification": False,
    }


@app.post("/api/v1/guards/{guard_id}/rag-challenges/{challenge_id}/cutover", status_code=202)
def acknowledge_enrolled_guard_customer_cutover(
    guard_id: str,
    challenge_id: str,
    payload: RouteCutoverEvidence,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Do not label Protect active until the actual employee-facing route was tested.

    Only the bound enrolled machine may submit; corroborate a distinct,
    post-cutover Guard allow/allow sequence with the caller's observed
    employee-route response decision ID. Still requires all provider
    freshness/identity readiness checks and a subsequent Guard acknowledgment.
    """
    guard = _authenticate_guard(db, guard_id, authorization)
    if payload.guard_id != guard.id or payload.challenge_id != challenge_id:
        raise HTTPException(403, "CUTOVER_MACHINE_BINDING_MISMATCH")
    record = db.scalar(select(RAGRouteChallenge).where(
        RAGRouteChallenge.id == challenge_id,
        RAGRouteChallenge.organization_id == guard.organization_id,
        RAGRouteChallenge.guard_id == guard.id,
    ).with_for_update())
    if record is None:
        raise HTTPException(404, "Gateway reference challenge not found")
    now = datetime.now(timezone.utc)
    checked = record.verified_at
    if checked and checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    if record.status != "tested" or checked is None or now - checked > timedelta(minutes=30):
        raise HTTPException(409, "CUTOVER_REQUIRES_FRESH_SUCCESSFUL_TEST")
    if hashlib.sha256(payload.nonce.encode()).hexdigest() != record.nonce_digest:
        raise HTTPException(403, "CUTOVER_NONCE_INVALID")
    if (payload.deployment_sha256 != record.deployment_sha256
            or payload.route_sha256 != record.route_sha256):
        raise HTTPException(409, "CUTOVER_DEPLOYMENT_MISMATCH")
    row = db.get(AIApplication, record.application_row_id)
    if (row is None or row.organization_id != guard.organization_id
            or row.guard_id != guard.id or row.source_id != record.source_id
            or guard.revoked_at or guard.active_policy_version < 1
            or _route_configuration_fingerprint(row)
            != record.configuration_fingerprint):
        raise HTTPException(409, "CUTOVER_SOURCE_GUARD_OR_POLICY_CHANGED")
    expected_request_id = "ap-cutover-" + record.nonce_digest[:24]
    denied_request_id = expected_request_id + "-deny"
    tamper_request_id = expected_request_id + "-tamper"
    if (payload.application_request_id != expected_request_id
            or payload.negative_request_id != denied_request_id
            or payload.tamper_request_id != tamper_request_id):
        raise HTTPException(409, "CUSTOMER_ROUTE_REQUEST_ID_NOT_BOUND")
    events = list(db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == guard.organization_id,
        GuardAuditEvent.guard_id == guard.id,
        GuardAuditEvent.application_id == row.application_id,
        GuardAuditEvent.request_id == expected_request_id,
        GuardAuditEvent.created_at >= record.verified_at,
        GuardAuditEvent.policy_version > 0,
    )).all())
    layer1 = [item for item in events if item.layer == "layer1" and item.result == "allow"]
    layer2 = [item for item in events if item.layer == "layer2" and item.result == "allow"
              and item.reason == "TRUSTED_PROVENANCE_VALID"]
    if (not payload.decision_id or not any(
        a.decision_id == b.decision_id == payload.decision_id
        and a.subject_id == b.subject_id
        for a in layer1 for b in layer2
    )):
        raise HTTPException(409, "CUSTOMER_CUTOVER_GUARD_AUDIT_MISMATCH")
    # Independently corroborate the denied employee-facing request from the
    # same enrolled Guard. A working positive route is not bypass resistance.
    negative_events = list(db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == guard.organization_id,
        GuardAuditEvent.guard_id == guard.id,
        GuardAuditEvent.application_id == row.application_id,
        GuardAuditEvent.request_id == denied_request_id,
        GuardAuditEvent.created_at >= record.verified_at,
        GuardAuditEvent.policy_version > 0,
    )).all())
    if not any(e.layer == "layer1" and e.result == "block"
               and e.decision_id and e.subject_id for e in negative_events):
        raise HTTPException(409, "CUSTOMER_CUTOVER_DENIED_USER_NOT_GUARD_AUDITED")
    tamper_events = list(db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == guard.organization_id,
        GuardAuditEvent.guard_id == guard.id,
        GuardAuditEvent.application_id == row.application_id,
        GuardAuditEvent.request_id == tamper_request_id,
        GuardAuditEvent.created_at >= record.verified_at,
        GuardAuditEvent.policy_version > 0,
    )).all())
    # The tampered manifest must be rejected *after* authenticated Layer 1
    # allowed the synthetic resource; a disconnected Guard or generic 503
    # must not count as attestation enforcement proof.
    if (not any(e.layer == "layer1" and e.result == "allow"
                and e.decision_id and e.subject_id for e in tamper_events)
            or any(e.layer == "layer2" and e.result == "allow"
                   for e in tamper_events)):
        raise HTTPException(409, "CUSTOMER_CUTOVER_TAMPER_NOT_GUARD_AUDITED")
    record.status = "cutover_verified"
    record.cutover_at = now
    previous = json.loads(record.result_json or "{}")
    previous["customer_cutover"] = {
        "request_id": expected_request_id,
        "response_sha256": payload.application_response_sha256,
        "decision_id": payload.decision_id,
        "http_status": payload.application_http_status,
        "verified_guard_events": len(events),
        "negative_request_id": denied_request_id,
        "negative_response_sha256": payload.negative_response_sha256,
        "negative_guard_events": len(negative_events),
        "tamper_request_id": tamper_request_id,
        "tamper_response_sha256": payload.tamper_response_sha256,
        "tamper_guard_events": len(tamper_events),
    }
    record.result_json = json.dumps(previous, sort_keys=True)
    db.flush()
    checks = _automatic_activation_checklist(db, row)
    current_run = db.scalar(select(ProtectionActivationRun).where(
        ProtectionActivationRun.organization_id == row.organization_id,
        ProtectionActivationRun.application_row_id == row.id,
    ))
    if current_run:
        current_run.checks_json = json.dumps(checks, sort_keys=True)
        current_run.last_checked_at = now
        if all(check["ok"] for check in checks):
            current_run.state = "awaiting_guard_ack"
            current_run.reason_code = "GUARD_PROTECT_ACK_REQUIRED"
            row.mode = "protect_pending"
        else:
            current_run.state = "action_required"
            current_run.reason_code = next(check["code"] for check in checks if not check["ok"])
    _audit(db, None, row.organization_id, "RAG_CUSTOMER_ROUTE_CUTOVER_VERIFIED", "ai_application", row.id, {
        "challenge_id": record.id, "guard_id": guard.id, "matched_events": len(events),
        "result": "customer_reference_route_verified",
    })
    db.commit()
    return {
        "state": "customer_cutover_verified",
        "challenge_id": record.id,
        "guard_audits_matched": len(events),
        "guard_acknowledgment_required": True,
        "protection_ready": all(check["ok"] for check in checks),
        "production_certification": False,
    }


@app.get("/api/v1/current/adapters")
def list_current_adapters(
    actor: Actor = Depends(require(Permission.RESULT_READ)),
) -> list[dict[str, object]]:
    """Return the single supported customer Gateway integration profile."""
    return adapter_registry()


@app.post("/api/v1/current/ai-applications/{application_id}/verification")
def verify_current_ai_application(
    application_id: str,
    payload: AIApplicationVerification,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(AIApplication.organization_id == actor.membership.organization_id, AIApplication.application_id == application_id))
    if row is None:
        raise HTTPException(404, "AI application not found")
    evidence = _verified_guard_evidence(db, row)
    request_sets = evidence["requests"]
    valid = (
        row.guard_id is not None
        and row.source_id is not None
        and payload.buffering_test_passed
        and payload.positive_request_id in request_sets["positive"]
        and payload.denial_request_id in request_sets["denial"]
        and payload.provenance_request_id in request_sets["provenance"]
        and len({payload.positive_request_id, payload.denial_request_id,
                 payload.provenance_request_id}) == 3
    )
    if not valid:
        raise HTTPException(409, {
            "code": "VERIFICATION_EVIDENCE_REQUIRED",
            "message": "Run distinct positive-control, denial and provenance-block tests through the actual Guard, then attest that the customer RAG buffers responses before release.",
        })
    now = datetime.now(timezone.utc)
    if payload.layer1:
        row.layer1_verified_at = now
    if payload.layer2:
        row.layer2_verified_at = now
    if payload.provenance:
        row.provenance_verified_at = now
    if payload.buffering:
        row.buffering_verified_at = now
    db.commit()
    return current_ai_application_readiness(application_id, actor, db)


@app.patch("/api/v1/current/ai-applications/{application_id}/mode")
def update_current_ai_application_mode(
    application_id: str,
    payload: AIApplicationModeUpdate,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(select(AIApplication).where(AIApplication.organization_id == actor.membership.organization_id, AIApplication.application_id == application_id))
    if row is None:
        raise HTTPException(404, "AI application not found")
    if payload.mode == "protect":
        # A legacy browser-submitted trio of audit IDs is not proof that the
        # registered RAG route buffers output. Require the new challenge
        # protocol even when old manual evidence fields are populated.
        readiness = _automatic_activation_checklist(db, row)
        failed = [check["code"] for check in readiness if not check["ok"]]
        if failed:
            raise HTTPException(409, {"code": "PROTECT_NOT_READY", "failed_checks": failed})
    previous = row.mode
    row.mode = "protect_pending" if payload.mode == "protect" else "shadow"
    _audit(db, actor, row.organization_id,
           "PROTECT_REQUESTED" if payload.mode == "protect" else "PROTECT_DISABLED",
           "ai_application", row.id, {"previous_mode": previous})
    db.commit()
    return {"application_id": row.application_id, "mode": row.mode}


@app.get("/api/v1/projects")
def list_projects(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(Project)
        .where(Project.organization_id == actor.membership.organization_id)
        .order_by(Project.created_at.desc())
    )
    return [{"id": p.id, "name": p.name, "paused": p.paused} for p in rows]


_SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
_SCIM_GROUP_ROLE_SCHEMA = "urn:accessproof:params:scim:schemas:extension:role:2.0:Group"
_SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
_SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def _validate_scim_role(value: str) -> str:
    try:
        role = Role(value)
    except ValueError as exc:
        raise HTTPException(422, f"Invalid SCIM default role: {value}") from exc
    if role is Role.OWNER:
        raise HTTPException(422, "SCIM auto-provisioning cannot assign OWNER")
    return str(role.value)


def _scim_error(status: int, detail: str, *, scim_type: str | None = None) -> JSONResponse:
    payload: dict[str, object] = {
        "schemas": [_SCIM_ERROR_SCHEMA],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        payload["scimType"] = scim_type
    return JSONResponse(status_code=status, content=payload)


def _scim_group_role_from_payload(payload: dict[str, Any]) -> str | None:
    extension = payload.get(_SCIM_GROUP_ROLE_SCHEMA)
    if not isinstance(extension, dict):
        return None
    value = extension.get("role")
    if value in {None, ""}:
        return None
    return _validate_scim_role(str(value))


def _scim_group_role_conflict(
    db: OrmSession,
    *,
    organization_id: str,
    identity_id: str,
    desired_role: str,
    excluding_group_id: str | None = None,
) -> ScimGroup | None:
    query = (
        select(ScimGroup)
        .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
        .where(
            ScimGroup.organization_id == organization_id,
            ScimGroupMember.organization_id == organization_id,
            ScimGroupMember.scim_identity_id == identity_id,
            ScimGroup.active.is_(True),
            ScimGroup.mapped_role.is_not(None),
            ScimGroup.mapped_role != desired_role,
        )
    )
    if excluding_group_id:
        query = query.where(ScimGroup.id != excluding_group_id)
    return db.scalar(query.limit(1))


def _reconcile_scim_identity_role(
    db: OrmSession, config: ScimConfiguration, identity: ScimIdentity
) -> None:
    membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == config.organization_id,
            Membership.user_id == identity.user_id,
        )
    )
    if not identity.active:
        if membership is not None:
            db.delete(membership)
        return

    roles = list(
        db.scalars(
            select(ScimGroup.mapped_role)
            .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
            .where(
                ScimGroup.organization_id == config.organization_id,
                ScimGroupMember.organization_id == config.organization_id,
                ScimGroupMember.scim_identity_id == identity.id,
                ScimGroup.active.is_(True),
                ScimGroup.mapped_role.is_not(None),
            )
            .distinct()
        )
    )
    if len(roles) > 1:
        # This should be prevented by mutation-time conflict checks. Fail closed
        # rather than inventing a privilege precedence if legacy data violates it.
        raise HTTPException(409, "SCIM identity belongs to conflicting role-mapped groups")
    resolved_role = str(roles[0]) if roles else config.default_role
    if membership is None:
        db.add(
            Membership(
                user_id=identity.user_id, organization_id=config.organization_id, role=resolved_role
            )
        )
    elif membership.role == Role.OWNER.value and resolved_role != Role.OWNER.value:
        # SCIM group mappings may never silently demote the workspace owner.
        # Ownership remains an explicit human transfer operation.
        raise HTTPException(409, "SCIM cannot change an OWNER role")
    else:
        membership.role = resolved_role


def _scim_group_members(
    db: OrmSession, config: ScimConfiguration, group: ScimGroup
) -> list[ScimIdentity]:
    return list(
        db.scalars(
            select(ScimIdentity)
            .join(ScimGroupMember, ScimGroupMember.scim_identity_id == ScimIdentity.id)
            .where(
                ScimGroupMember.organization_id == config.organization_id,
                ScimGroupMember.group_id == group.id,
                ScimIdentity.organization_id == config.organization_id,
            )
            .order_by(ScimIdentity.user_name.asc())
        )
    )


def _scim_group_payload(
    db: OrmSession, config: ScimConfiguration, group: ScimGroup
) -> dict[str, Any]:
    members = _scim_group_members(db, config, group)
    payload: dict[str, object] = {
        "schemas": [_SCIM_GROUP_SCHEMA],
        "id": group.id,
        "externalId": group.external_id,
        "displayName": group.display_name,
        "members": [
            {
                "value": identity.id,
                "display": identity.user_name,
                "$ref": f"/scim/v2/Users/{identity.id}",
            }
            for identity in members
        ],
        "meta": {
            "resourceType": "Group",
            "created": group.created_at.isoformat(),
            "lastModified": group.updated_at.isoformat(),
            "location": f"/scim/v2/Groups/{group.id}",
        },
    }
    if group.mapped_role:
        payload["schemas"] = [_SCIM_GROUP_SCHEMA, _SCIM_GROUP_ROLE_SCHEMA]
        payload[_SCIM_GROUP_ROLE_SCHEMA] = {"role": group.mapped_role}
    return payload


def _scim_identity_for_member_value(
    db: OrmSession, config: ScimConfiguration, value: object
) -> ScimIdentity | None:
    identity_id = str(value or "").strip()
    if not identity_id:
        return None
    return db.scalar(
        select(ScimIdentity).where(
            ScimIdentity.id == identity_id,
            ScimIdentity.organization_id == config.organization_id,
        )
    )


def _scim_add_group_member(
    db: OrmSession, config: ScimConfiguration, group: ScimGroup, identity: ScimIdentity
) -> JSONResponse | None:
    if group.mapped_role:
        conflict = _scim_group_role_conflict(
            db,
            organization_id=config.organization_id,
            identity_id=identity.id,
            desired_role=group.mapped_role,
            excluding_group_id=group.id,
        )
        if conflict:
            return _scim_error(
                409,
                f"User is already in role-mapped group '{conflict.display_name}' with role {conflict.mapped_role}",
                scim_type="mutability",
            )
    existing = db.scalar(
        select(ScimGroupMember).where(
            ScimGroupMember.organization_id == config.organization_id,
            ScimGroupMember.group_id == group.id,
            ScimGroupMember.scim_identity_id == identity.id,
        )
    )
    if existing is None:
        db.add(
            ScimGroupMember(
                organization_id=config.organization_id,
                group_id=group.id,
                scim_identity_id=identity.id,
            )
        )
        db.flush()
    _reconcile_scim_identity_role(db, config, identity)
    return None


def _scim_remove_group_member(
    db: OrmSession, config: ScimConfiguration, group: ScimGroup, identity: ScimIdentity
) -> None:
    row = db.scalar(
        select(ScimGroupMember).where(
            ScimGroupMember.organization_id == config.organization_id,
            ScimGroupMember.group_id == group.id,
            ScimGroupMember.scim_identity_id == identity.id,
        )
    )
    if row is not None:
        db.delete(row)
        db.flush()
    _reconcile_scim_identity_role(db, config, identity)


@app.get("/api/v1/auth/scim/config")
def get_scim_config(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    row = db.get(ScimConfiguration, actor.membership.organization_id)
    if not row:
        return {"configured": False}
    return {
        "configured": True,
        "enabled": row.enabled,
        "default_role": row.default_role,
        "updated_at": row.updated_at.isoformat(),
    }


@app.put("/api/v1/auth/scim/config")
def put_scim_config(
    payload: ScimConfigurationUpdate,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    default_role = _validate_scim_role(payload.default_role)
    token = secrets.token_urlsafe(48)
    org_id = actor.membership.organization_id
    row = db.get(ScimConfiguration, org_id)
    if row is None:
        row = ScimConfiguration(
            organization_id=org_id,
            token_hash=hash_token(token),
            default_role=default_role,
            enabled=payload.enabled,
        )
        db.add(row)
    else:
        row.token_hash = hash_token(token)
        row.default_role = default_role
        row.enabled = payload.enabled
        row.updated_at = datetime.now(timezone.utc)
    _audit(
        db,
        actor,
        org_id,
        "scim.configuration.rotated",
        "organization",
        org_id,
        {"enabled": payload.enabled, "default_role": default_role},
    )
    db.commit()
    return {
        "configured": True,
        "enabled": row.enabled,
        "default_role": row.default_role,
        "scim_token": token,
    }


@app.delete("/api/v1/auth/scim/config", status_code=204)
def delete_scim_config(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db)
) -> Response:
    org_id = actor.membership.organization_id
    row = db.get(ScimConfiguration, org_id)
    if row:
        db.delete(row)
        _audit(db, actor, org_id, "scim.configuration.deleted", "organization", org_id)
        db.commit()
    return Response(status_code=204)


def _scim_context(authorization: str | None, db: OrmSession) -> ScimConfiguration:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "SCIM bearer token required")
    digest = hash_token(authorization[7:])
    row = db.scalar(
        select(ScimConfiguration).where(
            ScimConfiguration.token_hash == digest, ScimConfiguration.enabled.is_(True)
        )
    )
    if not row:
        raise HTTPException(401, "Invalid SCIM bearer token")
    set_tenant_context(db, row.organization_id)
    return row


def _scim_user_payload(
    db: OrmSession, config: ScimConfiguration, identity: ScimIdentity
) -> dict[str, Any]:
    membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == config.organization_id,
            Membership.user_id == identity.user_id,
        )
    )
    return {
        "schemas": [_SCIM_USER_SCHEMA],
        "id": identity.id,
        "externalId": identity.external_id,
        "userName": identity.user_name,
        "active": bool(identity.active and membership is not None),
        "roles": [{"value": membership.role}] if membership else [],
        "meta": {
            "resourceType": "User",
            "created": identity.created_at.isoformat(),
            "lastModified": identity.updated_at.isoformat(),
            "location": f"/scim/v2/Users/{identity.id}",
        },
    }


@app.get("/scim/v2/ServiceProviderConfig")
def scim_service_provider_config(
    authorization: str | None = Header(default=None), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _scim_context(authorization, db)
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer Token",
                "description": "Organization-scoped SCIM bearer token",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            }
        ],
    }


@app.get("/scim/v2/ResourceTypes")
def scim_resource_types(
    authorization: str | None = Header(default=None), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _scim_context(authorization, db)
    resources = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": _SCIM_USER_SCHEMA,
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": _SCIM_GROUP_SCHEMA,
            "schemaExtensions": [{"schema": _SCIM_GROUP_ROLE_SCHEMA, "required": False}],
        },
    ]
    return {
        "schemas": [_SCIM_LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@app.get("/scim/v2/Schemas")
def scim_schemas(
    authorization: str | None = Header(default=None), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    _scim_context(authorization, db)
    resources = [
        {
            "id": _SCIM_USER_SCHEMA,
            "name": "User",
            "description": "AccessProof SCIM user",
            "attributes": [],
            "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{_SCIM_USER_SCHEMA}"},
        },
        {
            "id": _SCIM_GROUP_SCHEMA,
            "name": "Group",
            "description": "AccessProof SCIM group",
            "attributes": [],
            "meta": {
                "resourceType": "Schema",
                "location": f"/scim/v2/Schemas/{_SCIM_GROUP_SCHEMA}",
            },
        },
        {
            "id": _SCIM_GROUP_ROLE_SCHEMA,
            "name": "AccessProofGroupRole",
            "description": "Optional mapping from one SCIM group to one non-OWNER AccessProof role",
            "attributes": [
                {
                    "name": "role",
                    "type": "string",
                    "multiValued": False,
                    "required": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "none",
                    "canonicalValues": ["ADMIN", "ENGINEER", "VIEWER", "AUDITOR"],
                }
            ],
            "meta": {
                "resourceType": "Schema",
                "location": f"/scim/v2/Schemas/{_SCIM_GROUP_ROLE_SCHEMA}",
            },
        },
    ]
    return {
        "schemas": [_SCIM_LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@app.get("/scim/v2/Users", response_model=None)
def scim_list_users(
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    query = select(ScimIdentity).where(ScimIdentity.organization_id == config.organization_id)
    if filter:
        import re

        match = re.fullmatch(r'\s*userName\s+eq\s+"([^"]+)"\s*', filter, flags=re.IGNORECASE)
        if not match:
            return JSONResponse(
                status_code=400,
                content={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "400",
                    "scimType": "invalidFilter",
                    "detail": "Only userName eq filters are supported",
                },
            )
        query = query.where(func.lower(ScimIdentity.user_name) == match.group(1).lower())
    rows = db.scalars(query.order_by(ScimIdentity.created_at.asc())).all()
    start = max(0, startIndex - 1)
    page = rows[start : start + min(max(count, 0), 200)]
    return {
        "schemas": [_SCIM_LIST_SCHEMA],
        "totalResults": len(rows),
        "startIndex": startIndex,
        "itemsPerPage": len(page),
        "Resources": [_scim_user_payload(db, config, row) for row in page],
    }


@app.get("/scim/v2/Users/{scim_id}", response_model=None)
def scim_get_user(
    scim_id: str, authorization: str | None = Header(default=None), db: OrmSession = Depends(get_db)
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    row = db.scalar(
        select(ScimIdentity).where(
            ScimIdentity.id == scim_id, ScimIdentity.organization_id == config.organization_id
        )
    )
    if not row:
        return JSONResponse(
            status_code=404,
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "404",
                "detail": "User not found",
            },
        )
    return _scim_user_payload(db, config, row)


@app.post("/scim/v2/Users", status_code=201, response_model=None)
def scim_create_user(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    user_name = str(payload.get("userName") or "").strip().lower()
    if not user_name or "@" not in user_name:
        return JSONResponse(
            status_code=400,
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "400",
                "scimType": "invalidValue",
                "detail": "userName must be an email address",
            },
        )
    existing_identity = db.scalar(
        select(ScimIdentity).where(
            ScimIdentity.organization_id == config.organization_id,
            func.lower(ScimIdentity.user_name) == user_name,
        )
    )
    if existing_identity:
        return JSONResponse(
            status_code=409,
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "409",
                "scimType": "uniqueness",
                "detail": "SCIM user already exists",
            },
        )
    user = db.scalar(select(User).where(func.lower(User.email) == user_name))
    if user is None:
        user = User(
            email=user_name,
            password_hash=hash_password(secrets.token_urlsafe(48)),
            email_verified=True,
        )
        db.add(user)
        db.flush()
    membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == config.organization_id, Membership.user_id == user.id
        )
    )
    active = bool(payload.get("active", True))
    if active and membership is None:
        db.add(
            Membership(
                user_id=user.id, organization_id=config.organization_id, role=config.default_role
            )
        )
    identity = ScimIdentity(
        organization_id=config.organization_id,
        user_id=user.id,
        user_name=user_name,
        external_id=(
            str(payload.get("externalId")) if payload.get("externalId") is not None else None
        ),
        active=active,
    )
    db.add(identity)
    db.flush()
    _audit(
        db,
        None,
        config.organization_id,
        "scim.user.provisioned",
        "scim_identity",
        identity.id,
        {"active": active},
    )
    db.commit()
    return _scim_user_payload(db, config, identity)


@app.patch("/scim/v2/Users/{scim_id}", response_model=None)
def scim_patch_user(
    scim_id: str,
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    row = db.scalar(
        select(ScimIdentity).where(
            ScimIdentity.id == scim_id, ScimIdentity.organization_id == config.organization_id
        )
    )
    if not row:
        return JSONResponse(
            status_code=404,
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "404",
                "detail": "User not found",
            },
        )
    operations = payload.get("Operations") or payload.get("operations") or []
    changed = False
    for operation in operations:
        if str(operation.get("op", "")).lower() not in {"replace", "add"}:
            return JSONResponse(
                status_code=400,
                content={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "400",
                    "scimType": "invalidValue",
                    "detail": "Only add/replace active operations are supported",
                },
            )
        path = str(operation.get("path") or "").lower()
        value = operation.get("value")
        if path != "active":
            return JSONResponse(
                status_code=400,
                content={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "400",
                    "scimType": "invalidPath",
                    "detail": "Only the active attribute is mutable",
                },
            )
        active = bool(value)
        row.active = active
        row.updated_at = datetime.now(timezone.utc)
        db.flush()
        _reconcile_scim_identity_role(db, config, row)
        changed = True
    if changed:
        _audit(
            db,
            None,
            config.organization_id,
            "scim.user.updated",
            "scim_identity",
            row.id,
            {"active": row.active},
        )
        db.commit()
    return _scim_user_payload(db, config, row)


@app.delete("/scim/v2/Users/{scim_id}", status_code=204)
def scim_delete_user(
    scim_id: str, authorization: str | None = Header(default=None), db: OrmSession = Depends(get_db)
) -> Response:
    config = _scim_context(authorization, db)
    row = db.scalar(
        select(ScimIdentity).where(
            ScimIdentity.id == scim_id, ScimIdentity.organization_id == config.organization_id
        )
    )
    if not row:
        return Response(status_code=204)
    membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == config.organization_id, Membership.user_id == row.user_id
        )
    )
    if membership is not None:
        db.delete(membership)
    row.active = False
    row.updated_at = datetime.now(timezone.utc)
    _audit(db, None, config.organization_id, "scim.user.deactivated", "scim_identity", row.id)
    db.commit()
    return Response(status_code=204)


@app.get("/scim/v2/Groups", response_model=None)
def scim_list_groups(
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    query = select(ScimGroup).where(
        ScimGroup.organization_id == config.organization_id, ScimGroup.active.is_(True)
    )
    if filter:
        import re

        display = re.fullmatch(r'\s*displayName\s+eq\s+"([^"]+)"\s*', filter, flags=re.IGNORECASE)
        external = re.fullmatch(r'\s*externalId\s+eq\s+"([^"]+)"\s*', filter, flags=re.IGNORECASE)
        if display:
            query = query.where(func.lower(ScimGroup.display_name) == display.group(1).lower())
        elif external:
            query = query.where(ScimGroup.external_id == external.group(1))
        else:
            return _scim_error(
                400,
                "Only displayName eq and externalId eq filters are supported",
                scim_type="invalidFilter",
            )
    rows = list(db.scalars(query.order_by(ScimGroup.created_at.asc())))
    start = max(0, startIndex - 1)
    page = rows[start : start + min(max(count, 0), 200)]
    return {
        "schemas": [_SCIM_LIST_SCHEMA],
        "totalResults": len(rows),
        "startIndex": startIndex,
        "itemsPerPage": len(page),
        "Resources": [_scim_group_payload(db, config, row) for row in page],
    }


@app.get("/scim/v2/Groups/{group_id}", response_model=None)
def scim_get_group(
    group_id: str,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    row = db.scalar(
        select(ScimGroup).where(
            ScimGroup.id == group_id,
            ScimGroup.organization_id == config.organization_id,
            ScimGroup.active.is_(True),
        )
    )
    if not row:
        return _scim_error(404, "Group not found")
    return _scim_group_payload(db, config, row)


@app.post("/scim/v2/Groups", status_code=201, response_model=None)
def scim_create_group(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    config = _scim_context(authorization, db)
    display_name = str(payload.get("displayName") or "").strip()
    if not display_name:
        return _scim_error(400, "displayName is required", scim_type="invalidValue")
    existing = db.scalar(
        select(ScimGroup).where(
            ScimGroup.organization_id == config.organization_id,
            func.lower(ScimGroup.display_name) == display_name.lower(),
            ScimGroup.active.is_(True),
        )
    )
    if existing:
        return _scim_error(409, "SCIM group already exists", scim_type="uniqueness")
    mapped_role = _scim_group_role_from_payload(payload)
    group = ScimGroup(
        organization_id=config.organization_id,
        display_name=display_name,
        external_id=(
            str(payload.get("externalId")) if payload.get("externalId") is not None else None
        ),
        mapped_role=mapped_role,
        active=True,
    )
    db.add(group)
    db.flush()
    for member in payload.get("members") or []:
        identity = _scim_identity_for_member_value(
            db, config, member.get("value") if isinstance(member, dict) else None
        )
        if identity is None:
            return _scim_error(
                400, "Group member must reference an existing SCIM user", scim_type="invalidValue"
            )
        conflict = _scim_add_group_member(db, config, group, identity)
        if conflict:
            db.rollback()
            return conflict
    _audit(
        db,
        None,
        config.organization_id,
        "scim.group.provisioned",
        "scim_group",
        group.id,
        {
            "display_name": display_name,
            "mapped_role": mapped_role,
            "member_count": len(payload.get("members") or []),
        },
    )
    db.commit()
    return _scim_group_payload(db, config, group)


def _scim_group_member_ids(value: object) -> list[str]:
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    ids: list[str] = []
    for item in value:
        if isinstance(item, dict) and item.get("value"):
            ids.append(str(item["value"]))
    return ids


def _scim_member_id_from_remove_path(path: str) -> str | None:
    import re

    match = re.fullmatch(
        r'\s*members\s*\[\s*value\s+eq\s+"([^"]+)"\s*\]\s*', path, flags=re.IGNORECASE
    )
    return match.group(1) if match else None


@app.patch("/scim/v2/Groups/{group_id}", response_model=None)
def scim_patch_group(
    group_id: str,
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any] | JSONResponse:
    identity: ScimIdentity | None
    config = _scim_context(authorization, db)
    group = db.scalar(
        select(ScimGroup).where(
            ScimGroup.id == group_id,
            ScimGroup.organization_id == config.organization_id,
            ScimGroup.active.is_(True),
        )
    )
    if not group:
        return _scim_error(404, "Group not found")
    operations = payload.get("Operations") or payload.get("operations") or []
    if not isinstance(operations, list):
        return _scim_error(400, "Operations must be a list", scim_type="invalidValue")

    for operation in operations:
        op_name = str(operation.get("op") or "").lower()
        path = str(operation.get("path") or "")
        value = operation.get("value")
        if op_name not in {"add", "remove", "replace"}:
            return _scim_error(
                400,
                "Only add/remove/replace group operations are supported",
                scim_type="invalidValue",
            )

        if path.lower() == "displayname" and op_name in {"add", "replace"}:
            candidate = str(value or "").strip()
            if not candidate:
                return _scim_error(400, "displayName cannot be empty", scim_type="invalidValue")
            duplicate = db.scalar(
                select(ScimGroup).where(
                    ScimGroup.organization_id == config.organization_id,
                    func.lower(ScimGroup.display_name) == candidate.lower(),
                    ScimGroup.id != group.id,
                    ScimGroup.active.is_(True),
                )
            )
            if duplicate:
                return _scim_error(
                    409, "SCIM group displayName already exists", scim_type="uniqueness"
                )
            group.display_name = candidate
            group.updated_at = datetime.now(timezone.utc)
            continue

        normalized_role_path = path.lower()
        role_paths = {"role", f"{_SCIM_GROUP_ROLE_SCHEMA}:role".lower()}
        if normalized_role_path in role_paths:
            if op_name == "remove":
                new_role = None
            elif value is None or value == "":
                new_role = None
            else:
                new_role = _validate_scim_role(str(value))
            if new_role:
                for identity in _scim_group_members(db, config, group):
                    conflict = _scim_group_role_conflict(
                        db,
                        organization_id=config.organization_id,
                        identity_id=identity.id,
                        desired_role=new_role,
                        excluding_group_id=group.id,
                    )
                    if conflict:
                        return _scim_error(
                            409,
                            f"User {identity.user_name} is already in role-mapped group '{conflict.display_name}'",
                            scim_type="mutability",
                        )
            group.mapped_role = new_role
            group.updated_at = datetime.now(timezone.utc)
            db.flush()
            for identity in _scim_group_members(db, config, group):
                _reconcile_scim_identity_role(db, config, identity)
            continue

        if path.lower() == "members":
            member_ids = _scim_group_member_ids(value)
            if op_name == "replace":
                desired = set(member_ids)
                current = {
                    identity.id: identity for identity in _scim_group_members(db, config, group)
                }
                for identity in current.values():
                    if identity.id not in desired:
                        _scim_remove_group_member(db, config, group, identity)
                for identity_id in desired:
                    identity = _scim_identity_for_member_value(db, config, identity_id)
                    if identity is None:
                        return _scim_error(
                            400,
                            "Group member must reference an existing SCIM user",
                            scim_type="invalidValue",
                        )
                    member_error = _scim_add_group_member(db, config, group, identity)
                    if member_error:
                        return member_error
            elif op_name == "add":
                for identity_id in member_ids:
                    identity = _scim_identity_for_member_value(db, config, identity_id)
                    if identity is None:
                        return _scim_error(
                            400,
                            "Group member must reference an existing SCIM user",
                            scim_type="invalidValue",
                        )
                    member_error = _scim_add_group_member(db, config, group, identity)
                    if member_error:
                        return member_error
            elif op_name == "remove":
                for identity_id in member_ids:
                    identity = _scim_identity_for_member_value(db, config, identity_id)
                    if identity is not None:
                        _scim_remove_group_member(db, config, group, identity)
            continue

        removed_member_id = _scim_member_id_from_remove_path(path) if op_name == "remove" else None
        if removed_member_id:
            identity = _scim_identity_for_member_value(db, config, removed_member_id)
            if identity is not None:
                _scim_remove_group_member(db, config, group, identity)
            continue

        return _scim_error(400, "Unsupported SCIM Group patch path", scim_type="invalidPath")

    _audit(
        db,
        None,
        config.organization_id,
        "scim.group.updated",
        "scim_group",
        group.id,
        {"display_name": group.display_name, "mapped_role": group.mapped_role},
    )
    db.commit()
    return _scim_group_payload(db, config, group)


@app.delete("/scim/v2/Groups/{group_id}", status_code=204)
def scim_delete_group(
    group_id: str,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> Response:
    config = _scim_context(authorization, db)
    group = db.scalar(
        select(ScimGroup).where(
            ScimGroup.id == group_id,
            ScimGroup.organization_id == config.organization_id,
            ScimGroup.active.is_(True),
        )
    )
    if not group:
        return Response(status_code=204)
    members = _scim_group_members(db, config, group)
    db.execute(
        delete(ScimGroupMember).where(
            ScimGroupMember.organization_id == config.organization_id,
            ScimGroupMember.group_id == group.id,
        )
    )
    group.active = False
    group.updated_at = datetime.now(timezone.utc)
    db.flush()
    for identity in members:
        _reconcile_scim_identity_role(db, config, identity)
    _audit(db, None, config.organization_id, "scim.group.deactivated", "scim_group", group.id)
    db.commit()
    return Response(status_code=204)


@app.post("/api/v1/projects", status_code=201)
def create_project(
    payload: ProjectCreate,
    actor: Actor = Depends(require(Permission.PROJECT_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = actor.membership.organization_id
    count = db.scalar(select(func.count(Project.id)).where(Project.organization_id == org_id)) or 0
    _enforce_count_entitlement(db, org_id, "projects", int(count))
    p = Project(organization_id=org_id, name=payload.name)
    db.add(p)
    db.flush()
    _audit(db, actor, p.organization_id, "project.created", "project", p.id)
    db.commit()
    return {"id": p.id, "name": p.name}


@app.post("/api/v1/projects/{project_id}/pause")
def pause_project(
    project_id: str,
    actor: Actor = Depends(require(Permission.PROJECT_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    p = _project_for_actor(db, actor, project_id)
    p.paused = True
    _audit(db, actor, p.organization_id, "project.paused", "project", p.id)
    db.commit()
    return {"paused": True}


@app.delete("/api/v1/projects/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    payload: ProjectDeleteRequest,
    actor: Actor = Depends(require(Permission.PROJECT_DELETE)),
    db: OrmSession = Depends(get_db),
) -> Response:
    project = _project_for_actor(db, actor, project_id)
    if payload.confirmation != project.name:
        raise HTTPException(422, "Project confirmation does not match project name")
    _assert_project_deletable(db, project)
    org_id = project.organization_id
    project_name = project.name
    _audit(db, actor, org_id, "project.deleted", "project", project.id, {"name": project_name})
    _delete_project_records(db, project)
    db.commit()
    return Response(status_code=204)


@app.get("/api/v1/organization")
def get_organization(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    org = db.get(Organization, actor.membership.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    return {
        "id": org.id,
        "name": org.name,
        "mutations_disabled": org.mutations_disabled,
        "role": actor.membership.role,
    }


@app.patch("/api/v1/organization")
def rename_organization(
    payload: OrganizationRename,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Rename the active workspace (admins only, audited)."""
    org = db.get(Organization, actor.membership.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    name = " ".join(payload.name.split())
    if len(name) < 2:
        raise HTTPException(422, "Workspace name must contain at least 2 characters")
    previous = org.name
    org.name = name
    _audit(db, actor, org.id, "ORGANIZATION_RENAMED", "organization", org.id,
           {"previous_name": previous, "name": name})
    db.commit()
    return {"id": org.id, "name": org.name, "mutations_disabled": org.mutations_disabled,
            "role": actor.membership.role}


@app.get("/api/v1/auth/me")
def current_account(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """The signed-in person and the workspaces they can switch between.

    Only the caller's own memberships are returned; never other users' data.
    """
    memberships = list(db.scalars(select(Membership).where(Membership.user_id == actor.user.id)))
    org_ids = [m.organization_id for m in memberships]
    names = {o.id: o.name for o in db.scalars(select(Organization).where(Organization.id.in_(org_ids)))} if org_ids else {}
    mfa_enabled = db.scalar(select(MfaMethod.id).where(
        MfaMethod.user_id == actor.user.id, MfaMethod.enabled.is_(True),
    ).limit(1)) is not None
    return {
        "user": {"id": actor.user.id, "email": actor.user.email,
                 "email_verified": bool(actor.user.email_verified), "mfa_enabled": mfa_enabled},
        "active_organization_id": actor.membership.organization_id,
        "role": actor.membership.role,
        "organizations": sorted(
            ({"id": m.organization_id, "name": names.get(m.organization_id, "Workspace"), "role": m.role}
             for m in memberships),
            key=lambda item: item["name"].lower(),
        ),
    }


def _onboarding_reset_scope(db: OrmSession, org_id: str) -> dict[str, list[str]]:
    scope = {
        "ai_applications": sorted(db.scalars(select(AIApplication.application_id).where(
            AIApplication.organization_id == org_id, AIApplication.archived_at.is_(None)))),
        "guards": sorted(db.scalars(select(GuardRegistration.id).where(
            GuardRegistration.organization_id == org_id, GuardRegistration.revoked_at.is_(None)))),
        "guard_enrollments": sorted(db.scalars(select(GuardEnrollment.id).where(
            GuardEnrollment.organization_id == org_id, GuardEnrollment.used_at.is_(None),
            GuardEnrollment.revoked_at.is_(None)))),
        "sources": sorted(db.scalars(select(SourceConnection.id).where(
            SourceConnection.organization_id == org_id, SourceConnection.status != "disconnected"))),
    }
    return scope


def _scope_digest(org_id: str, scope: dict[str, list[str]]) -> str:
    return hashlib.sha256(json.dumps({"organization_id": org_id, **scope}, sort_keys=True).encode()).hexdigest()


@app.get("/api/v1/organization/onboarding-reset/preview")
def preview_onboarding_reset(
    actor: Actor = Depends(require(Permission.ORG_DELETE)), db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Owner-only: show exactly what a fresh-start reset would change (O-04)."""
    org = db.get(Organization, actor.membership.organization_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    scope = _onboarding_reset_scope(db, org.id)
    return {
        "organization_name": org.name,
        "will_archive_ai_applications": scope["ai_applications"],
        "will_revoke_guards": len(scope["guards"]),
        "will_revoke_pending_guard_enrollments": len(scope["guard_enrollments"]),
        "will_disconnect_sources": len(scope["sources"]),
        "kept": ["your account, password and two-factor settings", "workspace and members",
                 "audit history and Guard decision records", "reports and verification evidence"],
        "scope_digest": _scope_digest(org.id, scope),
        "confirm_text": f"RESET {org.name}",
    }


@app.post("/api/v1/organization/onboarding-reset")
def execute_onboarding_reset(
    body: dict[str, Any],
    actor: Actor = Depends(require(Permission.ORG_DELETE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Owner-only fresh start. Revokes and disconnects; never deletes history."""
    org = db.get(Organization, actor.membership.organization_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    if not set(body) <= {"scope_digest", "confirm_text", "totp_code"} or not {"scope_digest", "confirm_text"} <= set(body):
        raise HTTPException(422, "SCOPE_DIGEST_AND_CONFIRM_TEXT_REQUIRED")
    scope = _onboarding_reset_scope(db, org.id)
    if not secrets.compare_digest(str(body["scope_digest"]), _scope_digest(org.id, scope)):
        # Something changed since the owner reviewed the preview.
        raise HTTPException(409, "RESET_SCOPE_CHANGED_REVIEW_AGAIN")
    if body["confirm_text"] != f"RESET {org.name}":
        raise HTTPException(422, "CONFIRM_TEXT_MISMATCH")
    mfa = db.scalar(select(MfaMethod).where(MfaMethod.user_id == actor.user.id, MfaMethod.enabled.is_(True)).with_for_update())
    if mfa is not None and not _consume_totp(mfa, str(body.get("totp_code") or "")):
        raise HTTPException(401, "MFA_CODE_REQUIRED")
    now = datetime.now(timezone.utc)
    for row in db.scalars(select(AIApplication).where(
            AIApplication.organization_id == org.id, AIApplication.archived_at.is_(None))):
        _archive_application(db, actor, row, "onboarding_reset")
    for guard in db.scalars(select(GuardRegistration).where(
            GuardRegistration.organization_id == org.id, GuardRegistration.revoked_at.is_(None))):
        guard.revoked_at = now
        guard.credential_hash = None
        guard.health = "revoked"
    for enrollment in db.scalars(select(GuardEnrollment).where(
            GuardEnrollment.organization_id == org.id, GuardEnrollment.used_at.is_(None),
            GuardEnrollment.revoked_at.is_(None))):
        enrollment.revoked_at = now
    for source in db.scalars(select(SourceConnection).where(
            SourceConnection.organization_id == org.id, SourceConnection.status != "disconnected")):
        source.encrypted_credentials = None
        source.status = "disconnected"
        source.capabilities_json = "{}"
        source.provider_identity_json = "{}"
        source.granted_scopes_json = "[]"
        source.missing_scopes_json = "[]"
        source.last_error = None
    _audit(db, actor, org.id, "ONBOARDING_RESET", "organization", org.id,
           {key: len(value) for key, value in scope.items()})
    db.commit()
    return {"reset": True, **{key: len(value) for key, value in scope.items()},
            "next_step": "Open Get Started to connect a source again."}


@app.post("/api/v1/organization/enable-mutations")
def enable_mutations(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    org = db.get(Organization, actor.membership.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    org.mutations_disabled = False
    _audit(db, actor, org.id, "organization.mutations_enabled", "organization", org.id)
    db.commit()
    return {"mutations_disabled": False}


@app.get("/api/v1/organization/retention")
def get_retention(
    actor: Actor = Depends(require(Permission.RETENTION_MANAGE)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    policy = get_or_create_policy(db, actor.membership.organization_id)
    db.commit()
    return {
        "detailed_evidence_days": policy.detailed_evidence_days,
        "report_days": policy.report_days,
        "audit_days": policy.audit_days,
    }


@app.patch("/api/v1/organization/retention")
def update_retention(
    payload: RetentionPolicyUpdate,
    actor: Actor = Depends(require(Permission.RETENTION_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    policy = get_or_create_policy(db, actor.membership.organization_id)
    policy.detailed_evidence_days = payload.detailed_evidence_days
    policy.report_days = payload.report_days
    policy.audit_days = payload.audit_days
    _audit(
        db,
        actor,
        actor.membership.organization_id,
        "retention.updated",
        "retention_policy",
        actor.membership.organization_id,
        payload.model_dump(),
    )
    db.commit()
    return payload.model_dump()


@app.post("/api/v1/organization/retention/purge")
def purge_retention(
    actor: Actor = Depends(require(Permission.RETENTION_MANAGE)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    counts = apply_retention(db, actor.membership.organization_id)
    _audit(
        db,
        actor,
        actor.membership.organization_id,
        "retention.purged",
        "retention_policy",
        actor.membership.organization_id,
        counts,
    )
    db.commit()
    return counts


@app.delete("/api/v1/organization", status_code=204)
def delete_organization(
    payload: OrganizationDeleteRequest,
    actor: Actor = Depends(require(Permission.ORG_DELETE)),
    db: OrmSession = Depends(get_db),
) -> Response:
    org_id = actor.membership.organization_id
    org = db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    if payload.confirmation != org.name:
        raise HTTPException(422, "Organization confirmation does not match organization name")
    projects = list(db.scalars(select(Project).where(Project.organization_id == org_id)))
    for project in projects:
        _assert_project_deletable(db, project)
    # Create a non-secret, non-reversible deletion receipt before tenant rows disappear.
    receipt = DeletionReceipt(
        organization_id_hash=hashlib.sha256(org_id.encode()).hexdigest(),
        actor_user_id_hash=hashlib.sha256(actor.user.id.encode()).hexdigest(),
        organization_name_hash=hashlib.sha256(org.name.encode()).hexdigest(),
    )
    db.add(receipt)
    db.flush()
    for project in projects:
        _delete_project_records(db, project)
    endpoint_ids = list(
        db.scalars(select(WebhookEndpoint.id).where(WebhookEndpoint.organization_id == org_id))
    )
    if endpoint_ids:
        db.execute(delete(WebhookDelivery).where(WebhookDelivery.endpoint_id.in_(endpoint_ids)))
    for model in (
        WebhookEndpoint,
        EmailOutbox,
        AlertRecord,
        ApiKey,
        Invitation,
        Entitlement,
        UsageRecord,
        RetentionPolicy,
        AuditEvent,
        Membership,
    ):
        db.execute(delete(model).where(model.organization_id == org_id))
    db.delete(org)
    db.commit()
    return Response(status_code=204)


@app.post("/api/v1/organization/disable-mutations")
def disable_mutations(
    actor: Actor = Depends(require(Permission.ORG_ADMIN)), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    org = db.get(Organization, actor.membership.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    org.mutations_disabled = True
    _audit(db, actor, org.id, "organization.mutations_disabled", "organization", org.id)
    db.commit()
    return {"mutations_disabled": True}


def _enforce_microsoft_tenant_boundary(
    db: OrmSession, organization_id: str, provider: str,
    credentials: dict[str, Any], *, replace_source_id: str | None = None,
) -> None:
    """Reject ambiguous Microsoft source identity graphs across Entra tenants.

    GuardSubject / GuardGroup IDs are scoped to (organization, provider) in
    this schema, not per Entra tenant. Until a fully migrated multi-tenant
    identity graph exists, mixing Microsoft tenants in one organization is
    unsafe and must not be silently allowed.
    """
    if provider.lower() not in {"microsoft365", "sharepoint", "onedrive"}:
        return
    # Legacy source records may be created as unconfigured drafts. They are
    # never eligible for authorization until valid credentials are supplied.
    if not credentials:
        return
    from uuid import UUID
    raw = credentials.get("tenant_id") or credentials.get("tenant_hint")
    try:
        tenant = str(UUID(str(raw)))
        if tenant == "00000000-0000-0000-0000-000000000000":
            raise ValueError("Null tenant")
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, "Microsoft Entra tenant UUID is required") from exc
    if credentials.get("tenant_id") and credentials.get("tenant_hint"):
        if str(credentials["tenant_hint"]).lower() != str(credentials["tenant_id"]).lower():
            raise HTTPException(422, "Conflicting Microsoft Entra tenant IDs")
    credentials["tenant_id"] = tenant
    credentials["tenant_hint"] = tenant
    # Graph driveItem permissions are not a complete SharePoint effective-ACL
    # oracle. Bind each explicit provider profile to the identifiers needed
    # for independent effective-permission certification. Legacy microsoft365
    # drafts remain possible, but cannot enter Protect without these bindings.
    if provider.lower() == "sharepoint":
        site = credentials.get("site_id")
        library = credentials.get("list_id")
        if (not isinstance(site, str) or not 0 < len(site) <= 512
                or any(ch in site for ch in "/?\\#\r\n")
                or not isinstance(library, str)):
            raise HTTPException(422, "SharePoint requires site_id and list_id")
        site_components = site.split(",")
        if len(site_components) != 3 or not site_components[0].lower().endswith(".sharepoint.com"):
            raise HTTPException(422, "SharePoint site_id must be hostname,site-collection-GUID,web-GUID")
        try:
            UUID(site_components[1])
            UUID(site_components[2])
        except (ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(422, "Invalid SharePoint site GUID") from exc
        try:
            credentials["list_id"] = str(UUID(library))
        except (TypeError, ValueError, AttributeError) as exc:
            raise HTTPException(422, "SharePoint list_id must be a GUID") from exc
        credentials["site_id"] = site
    elif provider.lower() == "onedrive":
        try:
            owner = str(UUID(str(credentials.get("owner_object_id"))))
        except (TypeError, ValueError, AttributeError) as exc:
            raise HTTPException(422, "OneDrive requires an Entra owner_object_id UUID") from exc
        if owner == "00000000-0000-0000-0000-000000000000":
            raise HTTPException(422, "OneDrive owner_object_id must not be empty")
        credentials["owner_object_id"] = owner
    if replace_source_id:
        previous_source = db.scalar(select(SourceConnection).where(
            SourceConnection.id == replace_source_id,
            SourceConnection.organization_id == organization_id,
        ))
        if previous_source is None:
            raise HTTPException(404, "Source not found")
        if credentials.get("test_root_item_id") != previous_source.boundary:
            raise HTTPException(409, "Cannot silently change an approved Microsoft folder boundary")
        previous = (json.loads(_secret_box.decrypt(previous_source.encrypted_credentials))
                    if previous_source.encrypted_credentials else {})
        if previous.get("drive_id") and previous.get("drive_id") != credentials.get("drive_id"):
            raise HTTPException(409, "Cannot silently switch the Microsoft drive")
        for scope_field in ("site_id", "list_id", "owner_object_id"):
            if previous.get(scope_field) != credentials.get(scope_field):
                raise HTTPException(409, "Cannot silently change the Microsoft certification scope")
    for source in db.scalars(select(SourceConnection).where(
        SourceConnection.organization_id == organization_id,
        SourceConnection.provider.in_(["microsoft365", "sharepoint", "onedrive"]),
    )):
        if source.id == replace_source_id:
            previous = json.loads(_secret_box.decrypt(source.encrypted_credentials)) if source.encrypted_credentials else {}
            original_tenant = previous.get("tenant_id") or previous.get("tenant_hint")
            if original_tenant and str(original_tenant).lower() != tenant:
                raise HTTPException(409, "Changing the Microsoft tenant would invalidate mapped employee identities")
            continue
        if not source.encrypted_credentials:
            continue
        old = json.loads(_secret_box.decrypt(source.encrypted_credentials))
        old_tenant = old.get("tenant_id") or old.get("tenant_hint")
        # Existing tenant-less sources must be explicitly reconciled rather
        # than trusting potentially colliding previously synchronized IDs.
        if not old_tenant or str(old_tenant).lower() != tenant:
            raise HTTPException(409, "Microsoft tenant conflicts with an existing source in this organization")


@app.post("/api/v1/sources", status_code=201)
def create_source(
    payload: SourceCreate,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        enforce_source_onboarding_provider(payload.provider, settings)
        enforce_v1_browser_credential_policy(payload.provider, payload.credentials, settings)
    except V1ProviderScopeError as exc:
        message = str(exc)
        raise HTTPException(422, {"code": message.split(":", 1)[0], "message": message}) from exc
    project = _project_for_actor(db, actor, payload.project_id)
    _enforce_connector_entitlement(db, project.organization_id, payload.provider)
    count = (
        db.scalar(
            select(func.count(SourceConnection.id)).where(
                SourceConnection.organization_id == project.organization_id
            )
        )
        or 0
    )
    _enforce_count_entitlement(db, project.organization_id, "source_connections", int(count))
    credentials = dict(payload.credentials)
    _enforce_microsoft_tenant_boundary(db, project.organization_id, payload.provider, credentials)
    row = SourceConnection(
        organization_id=project.organization_id,
        project_id=project.id,
        provider=payload.provider,
        name=payload.name,
        boundary=payload.boundary,
        mutation_acknowledged=payload.mutation_acknowledged,
        encrypted_credentials=_secret_box.encrypt(json.dumps(credentials))
        if credentials
        else None,
    )
    db.add(row)
    db.flush()
    _audit(
        db,
        actor,
        project.organization_id,
        "source.created",
        "source",
        row.id,
        {"provider": payload.provider},
    )
    db.commit()
    return _source_payload(row)


@app.post("/api/v1/current/sources", status_code=201)
def create_current_source(
    payload: CurrentSourceCreate,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Connect a source for Guard enforcement without exposing Projects.

    ``source_connections`` retains its project foreign key for legacy
    diagnostics.  The current product places each organization’s sources in
    one hidden compatibility workspace instead of asking an administrator to
    create or select a project.
    """
    try:
        enforce_source_onboarding_provider(payload.provider, settings)
        enforce_v1_browser_credential_policy(payload.provider, payload.credentials, settings)
    except V1ProviderScopeError as exc:
        message = str(exc)
        raise HTTPException(422, {"code": message.split(":", 1)[0], "message": message}) from exc
    organization_id = actor.membership.organization_id
    _enforce_connector_entitlement(db, organization_id, payload.provider)
    count = db.scalar(select(func.count(SourceConnection.id)).where(
        SourceConnection.organization_id == organization_id
    )) or 0
    _enforce_count_entitlement(db, organization_id, "source_connections", int(count))
    workspace = _current_product_workspace(db, organization_id)
    # The current UI expresses the approved boundary as one field.  Retain the
    # connector-specific value internally so the established source adapters
    # still receive their explicit safety boundary at validation time.
    credentials = dict(payload.credentials)
    if payload.provider == "google-drive":
        credentials.setdefault("test_root_folder_id", payload.boundary)
    elif payload.provider in {"microsoft365", "sharepoint", "onedrive"}:
        if (not credentials.get("drive_id")
                or credentials.get("test_root_item_id", payload.boundary) != payload.boundary):
            raise HTTPException(422, "Microsoft source requires drive_id and matching root item")
        credentials.setdefault("test_root_item_id", payload.boundary)
    _enforce_microsoft_tenant_boundary(db, organization_id, payload.provider, credentials)
    row = SourceConnection(
        organization_id=organization_id,
        project_id=workspace.id,
        provider=payload.provider,
        name=payload.name,
        boundary=payload.boundary,
        encrypted_credentials=_secret_box.encrypt(json.dumps(credentials))
        if credentials
        else None,
    )
    db.add(row)
    db.flush()
    _audit(db, actor, organization_id, "source.created", "source", row.id, {"provider": payload.provider})
    db.commit()
    return _source_payload(row)


def _google_consent_fingerprint(source: SourceConnection) -> str:
    """Never accept a token for a source whose approved boundary changed."""
    return hashlib.sha256(json.dumps({
        "source_id": source.id, "organization_id": source.organization_id,
        "provider": source.provider, "root": source.boundary,
    }, sort_keys=True).encode("utf-8")).hexdigest()


@app.get("/api/v1/current/sources/google-oauth/status")
def google_source_oauth_status(
    actor: Actor = Depends(current_actor),
) -> dict[str, Any]:
    """Expose OAuth readiness without exposing the server-owned OAuth credentials.

    Normal customers authorize through Google's consent screen. They must
    never supply NeuralMatrix's OAuth client secret in the dashboard.
    """
    configured = bool(
        os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID", "").strip()
        and os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    )
    return {
        "configured": configured,
        "message": "Google Workspace connection is available."
        if configured else "Google Workspace connection is not configured by the AccessProof operator.",
    }


@app.post("/api/v1/current/sources/{source_id}/google-oauth/begin")
def begin_google_source_oauth(
    source_id: str,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, str]:
    source = db.scalar(select(SourceConnection).where(
        SourceConnection.id == source_id,
        SourceConnection.organization_id == actor.membership.organization_id,
        SourceConnection.provider == "google-drive",
    ))
    if source is None:
        raise HTTPException(404, "Google Drive source not found")
    client_id = os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID", "").strip()
    client_secret = os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise HTTPException(503, "Google OAuth is not configured on the control plane")
    raw_state = secrets.token_urlsafe(48)
    verifier = secrets.token_urlsafe(64)
    redirect_uri = f"{settings.api_public_url.rstrip('/')}/api/v1/current/sources/google-oauth/callback"
    try:
        url = google_consent_url(
            client_id=client_id, redirect_uri=redirect_uri,
            state=raw_state, verifier=verifier,
        )
    except GoogleConsentError as exc:
        raise HTTPException(503, str(exc)) from exc
    db.add(GoogleSourceOAuthState(
        organization_id=source.organization_id, source_id=source.id,
        initiated_by_user_id=actor.user.id,
        state_hash=hash_token(raw_state),
        encrypted_verifier=_secret_box.encrypt(verifier),
        config_fingerprint=_google_consent_fingerprint(source),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    ))
    _audit(db, actor, source.organization_id, "source.google_oauth_started", "source", source.id)
    db.commit()
    return {"authorization_url": url}


@app.get("/api/v1/current/sources/google-oauth/callback")
async def complete_google_source_oauth(
    state: str = "", code: str = "", error: str | None = None,
    db: OrmSession = Depends(get_db),
) -> RedirectResponse:
    failure = f"{settings.public_app_url.rstrip('/')}/sources?google=consent-failed"
    success = f"{settings.public_app_url.rstrip('/')}/sources?google=consent-complete"
    if not state or len(state) > 256:
        raise HTTPException(400, "Google OAuth state missing or invalid")
    now = datetime.now(timezone.utc)
    claim = db.scalar(select(GoogleSourceOAuthState).where(
        GoogleSourceOAuthState.state_hash == hash_token(state),
    ).with_for_update())
    if claim is None or claim.consumed_at is not None:
        raise HTTPException(400, "Google OAuth state invalid or already consumed")
    expiry = claim.expires_at.replace(tzinfo=claim.expires_at.tzinfo or timezone.utc)
    if expiry <= now:
        raise HTTPException(400, "Google OAuth state expired")
    # Tenant derived from the matched one-time secret, never from the caller.
    set_tenant_context(db, claim.organization_id)
    # Always consume even failed callbacks, before any outbound credential exchange.
    claim.consumed_at = now
    db.commit()
    source = db.scalar(select(SourceConnection).where(
        SourceConnection.id == claim.source_id,
        SourceConnection.organization_id == claim.organization_id,
        SourceConnection.provider == "google-drive",
    ))
    admin = db.scalar(select(Membership).where(
        Membership.organization_id == claim.organization_id,
        Membership.user_id == claim.initiated_by_user_id,
        Membership.role.in_(["OWNER", "ADMIN"]),
    ))
    if (source is None or admin is None or error or not code or len(code) > 4096
            or _google_consent_fingerprint(source) != claim.config_fingerprint):
        return RedirectResponse(failure, status_code=303)
    try:
        tokens = await asyncio.to_thread(
            exchange_google_code,
            code=code,
            client_id=os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID", "").strip(),
            client_secret=os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET", "").strip(),
            redirect_uri=f"{settings.api_public_url.rstrip('/')}/api/v1/current/sources/google-oauth/callback",
            verifier=_secret_box.decrypt(claim.encrypted_verifier),
        )
        adapter = GoogleDriveAdapter(
            access_token=tokens["access_token"], test_root_folder_id=source.boundary,
        )
        try:
            identity = await adapter.validate_connection()
        finally:
            await adapter._client.aclose()
        # Root-bound validation is necessary but does not certify all employee
        # and Google Group ACL semantics. Directory/ACL sync remains required.
        existing = json.loads(_secret_box.decrypt(source.encrypted_credentials)) if source.encrypted_credentials else {}
        # OAuth client credentials belong to the NeuralMatrix deployment, not
        # individual customer-source records. Persist only source-bound tokens;
        # the worker obtains the operator client secret from its own runtime
        # secret configuration when performing an authorized refresh.
        existing.update({key: value for key, value in tokens.items() if key not in {
            "client_secret", "oauth_client_secret", "client_id", "oauth_client_id",
        }})
        existing.pop("client_secret", None)
        existing.pop("oauth_client_secret", None)
        existing.pop("oauth_client_id", None)
        existing["oauth_credential_mode"] = "server_managed"
        existing["client_id"] = os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID", "").strip()
        existing["test_root_folder_id"] = source.boundary
        source.encrypted_credentials = _secret_box.encrypt(json.dumps(existing, sort_keys=True))
        source.status, source.last_error, source.last_validated_at = "connected", None, now
        source.provider_identity_json = json.dumps({
            "provider": identity.provider, "tenant": identity.tenant,
            "boundary": identity.boundary, "metadata": identity.metadata,
        }, sort_keys=True)
        # Durable post-consent bootstrap: the worker resumes these source-
        # scoped cursors even if the administrator closes their browser.
        # Previously cached policy health becomes untrusted immediately;
        # neither the old directory nor old ACL cursor certifies this login.
        for kind in ("directory", "acl"):
            cursor = db.scalar(select(ProviderSyncCursorModel).where(
                ProviderSyncCursorModel.organization_id == source.organization_id,
                ProviderSyncCursorModel.source_id == source.id,
                ProviderSyncCursorModel.sync_kind == kind,
            ).with_for_update())
            if cursor is None:
                cursor = ProviderSyncCursorModel(
                    organization_id=source.organization_id,
                    source_id=source.id, provider="google-drive", sync_kind=kind,
                )
                db.add(cursor)
            cursor.status = "queued"
            cursor.cursor = None
            cursor.last_provider_revision = None
            cursor.last_success_at = None
            cursor.last_started_at = None
            cursor.last_error_at = None
            cursor.last_error_code = None
        db.commit()
    except Exception:
        db.rollback()
        # Never persist an unvalidated provider token or partial consent state.
        return RedirectResponse(failure, status_code=303)
    # Source-scoped return enables an authenticated, one-time directory sync
    # after OAuth without requiring the customer to find another manual button.
    # This identifier is a public source UUID, not a credential or OAuth state.
    return RedirectResponse(f"{success}&source_id={source.id}", status_code=303)


def _microsoft_consent_fingerprint(source: SourceConnection, credentials: dict[str, Any]) -> str:
    """Bind consent to the exact currently approved source resource."""
    fields = {
        "source_id": source.id,
        "organization_id": source.organization_id,
        "provider": source.provider.lower(),
        "tenant_id": credentials.get("tenant_id"),
        "drive_id": credentials.get("drive_id"),
        "root_item_id": credentials.get("test_root_item_id"),
        "site_id": credentials.get("site_id"),
        "list_id": credentials.get("list_id"),
        "owner_object_id": credentials.get("owner_object_id"),
    }
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode("utf-8")).hexdigest()


@app.get("/api/v1/current/sources/microsoft-admin-consent/status")
def microsoft_source_consent_status(
    actor: Actor = Depends(current_actor),
) -> dict[str, Any]:
    """Allow the UI to prevent unusable Microsoft consent drafts."""
    configured = bool(
        os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "").strip()
        and os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "").strip()
    )
    return {
        "configured": configured,
        "message": "Microsoft admin consent is available."
        if configured else "Microsoft admin consent is not configured by the AccessProof operator.",
    }


@app.post("/api/v1/current/sources/{source_id}/microsoft-admin-consent/begin")
def begin_microsoft_source_admin_consent(
    source_id: str,
    actor: Actor = Depends(require(Permission.ORG_ADMIN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, str]:
    """Start a short-lived, trusted Microsoft admin-consent redirect."""
    row = db.scalar(select(SourceConnection).where(
        SourceConnection.id == source_id,
        SourceConnection.organization_id == actor.membership.organization_id,
        SourceConnection.provider.in_(["microsoft365", "sharepoint", "onedrive"]),
    ))
    if row is None:
        raise HTTPException(404, "Microsoft source not found")
    client_id = os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "").strip()
    if not client_id or not os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "").strip():
        raise HTTPException(503, "Microsoft administrator consent is not configured on the control plane")
    config = json.loads(_secret_box.decrypt(row.encrypted_credentials)) if row.encrypted_credentials else {}
    try:
        tenant = tenant_uuid(config.get("tenant_id"))
    except MicrosoftConsentError as exc:
        raise HTTPException(422, str(exc)) from exc
    raw_state = secrets.token_urlsafe(48)
    redirect_uri = f"{settings.api_public_url.rstrip('/')}/api/v1/current/sources/microsoft-admin-consent/callback"
    try:
        url = microsoft_consent_url(
            tenant_id=tenant, client_id=client_id,
            redirect_uri=redirect_uri, state=raw_state,
        )
    except MicrosoftConsentError as exc:
        raise HTTPException(503, str(exc)) from exc
    db.add(MicrosoftConsentState(
        organization_id=row.organization_id,
        source_id=row.id,
        initiated_by_user_id=actor.user.id,
        state_hash=hash_token(raw_state),
        config_fingerprint=_microsoft_consent_fingerprint(row, config),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    ))
    _audit(db, actor, row.organization_id, "source.microsoft_consent_started", "source", row.id)
    db.commit()
    return {"authorization_url": url}


@app.get("/api/v1/current/sources/microsoft-admin-consent/callback")
async def complete_microsoft_source_admin_consent(
    state: str = "",
    tenant: str = "",
    admin_consent: str = "",
    error: str | None = None,
    db: OrmSession = Depends(get_db),
) -> RedirectResponse:
    """One-time state, exact tenant, Graph drive preflight, then encrypted save."""
    failure = f"{settings.public_app_url.rstrip('/')}/sources?microsoft=consent-failed"
    success = f"{settings.public_app_url.rstrip('/')}/sources?microsoft=consent-complete"
    if not state or len(state) > 256:
        raise HTTPException(400, "Invalid Microsoft consent state")
    now = datetime.now(timezone.utc)
    claim = db.scalar(select(MicrosoftConsentState).where(
        MicrosoftConsentState.state_hash == hash_token(state),
    ).with_for_update())
    if claim is None or claim.consumed_at is not None:
        raise HTTPException(400, "Microsoft consent state was already consumed or is invalid")
    expiry = claim.expires_at.replace(tzinfo=claim.expires_at.tzinfo or timezone.utc)
    if expiry <= now:
        raise HTTPException(400, "Microsoft consent state has expired")
    # Tenant derived from the matched one-time secret, never from the caller.
    set_tenant_context(db, claim.organization_id)
    source = db.scalar(select(SourceConnection).where(
        SourceConnection.id == claim.source_id,
        SourceConnection.organization_id == claim.organization_id,
    ))
    # Consume even failure callbacks to block replay and state fixation.
    claim.consumed_at = now
    db.commit()
    if source is None or error or admin_consent.lower() != "true":
        return RedirectResponse(failure, status_code=303)
    prior = json.loads(_secret_box.decrypt(source.encrypted_credentials)) if source.encrypted_credentials else {}
    consent_admin = db.scalar(select(Membership).where(
        Membership.organization_id == claim.organization_id,
        Membership.user_id == claim.initiated_by_user_id,
        Membership.role.in_(["OWNER", "ADMIN"]),
    ))
    if (consent_admin is None
            or source.provider.lower() not in {"microsoft365", "sharepoint", "onedrive"}
            or _microsoft_consent_fingerprint(source, prior) != claim.config_fingerprint):
        return RedirectResponse(failure, status_code=303)
    try:
        expected_tenant = tenant_uuid(prior.get("tenant_id"))
        if tenant_uuid(tenant) != expected_tenant:
            return RedirectResponse(failure, status_code=303)
        client_id = os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "").strip()
        client_secret = os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "").strip()
        token, token_expiry = graph_app_token(
            tenant_id=expected_tenant, client_id=client_id, client_secret=client_secret,
        )
        adapter = Microsoft365Adapter(
            access_token=token, drive_id=str(prior["drive_id"]),
            test_root_item_id=str(prior["test_root_item_id"]),
            tenant_hint=expected_tenant,
            sharepoint_site_id=prior.get("site_id") if source.provider.lower() in {"microsoft365", "sharepoint"} else None,
            sharepoint_list_id=prior.get("list_id") if source.provider.lower() in {"microsoft365", "sharepoint"} else None,
            onedrive_owner_object_id=prior.get("owner_object_id") if source.provider.lower() in {"microsoft365", "onedrive"} else None,
        )
        # Microsoft application consent creates a tenant-local service
        # principal. Sites.Selected still requires an independent, explicitly
        # scoped site grant from the customer's administrator. Persist the
        # tenant-bound short-lived token but never mark the source connected.
        # This allows the customer to complete the site grant and click
        # Validate without another round of Microsoft admin consent.
        site_grant_pending = False
        try:
            identity = await adapter.validate_connection()
        except AuthorizationError:
            site_grant_pending = True
            identity = None
        finally:
            await adapter._client.aclose()
    except Exception as exc:
        # Consent does not establish that an app can read the configured drive.
        # Keep Microsoft error bodies and tokens private, but distinguish the
        # reproducible Business Basic SharePoint service/provisioning blocker
        # from credentials or source-boundary validation failures.
        source.status = "not_configured"
        source.last_error = (
            "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY"
            if isinstance(exc, ProviderUnavailableError)
            and str(exc) == "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY"
            else "MICROSOFT_CONSENT_OR_DRIVE_VALIDATION_FAILED"
        )
        db.commit()
        return RedirectResponse(failure, status_code=303)
    prior.update({
        "tenant_id": expected_tenant, "tenant_hint": expected_tenant,
        "access_token": token, "expires_at": token_expiry.isoformat(),
        # The operator's app secret belongs only in control-plane/worker
        # runtime configuration. A source record carries its tenant binding
        # and short-lived token, never a reusable customer application secret.
        "client_id": client_id, "oauth_credential_mode": "server_managed",
        "token_endpoint": f"https://login.microsoftonline.com/{expected_tenant}/oauth2/v2.0/token",
        "grant_type": "client_credentials",
    })
    prior.pop("client_secret", None)
    prior.pop("oauth_client_secret", None)
    prior.pop("oauth_client_id", None)
    source.encrypted_credentials = _secret_box.encrypt(json.dumps(prior, sort_keys=True))
    source.status = "not_configured" if site_grant_pending else "connected"
    source.last_validated_at = now if not site_grant_pending else None
    source.last_error = "MICROSOFT_SITE_ACCESS_GRANT_REQUIRED" if site_grant_pending else None
    source.provider_identity_json = ("{}" if identity is None else json.dumps({
        "provider": identity.provider, "tenant": expected_tenant,
        "boundary": identity.boundary, "metadata": identity.metadata,
    }, sort_keys=True))
    # Consent establishes a new provider credential boundary. Existing ACL and
    # directory observations cannot certify it; durable worker jobs rebuild
    # both snapshots even if the browser closes immediately after redirect.
    for kind in ("directory", "acl"):
        cursor = db.scalar(select(ProviderSyncCursorModel).where(
            ProviderSyncCursorModel.organization_id == source.organization_id,
            ProviderSyncCursorModel.source_id == source.id,
            ProviderSyncCursorModel.sync_kind == kind,
        ).with_for_update())
        if cursor is None:
            cursor = ProviderSyncCursorModel(
                organization_id=source.organization_id, source_id=source.id,
                provider="microsoft365", sync_kind=kind,
            )
            db.add(cursor)
        cursor.status = "not_configured" if site_grant_pending else "queued"
        cursor.cursor = None
        cursor.last_provider_revision = None
        cursor.last_success_at = None
        cursor.last_started_at = None
        cursor.last_error_at = None
        cursor.last_error_code = None
    db.commit()
    if site_grant_pending:
        return RedirectResponse(
            f"{settings.public_app_url.rstrip('/')}/sources?microsoft=site-grant-required&source_id={source.id}",
            status_code=303,
        )
    return RedirectResponse(success, status_code=303)


@app.get("/api/v1/current/sources")
def list_current_sources(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(select(SourceConnection).where(
        SourceConnection.organization_id == actor.membership.organization_id
    ).order_by(SourceConnection.name.asc(), SourceConnection.id.asc())).all()
    cursors = list(db.scalars(select(ProviderSyncCursorModel).where(
        ProviderSyncCursorModel.organization_id == actor.membership.organization_id,
        ProviderSyncCursorModel.sync_kind.in_(["acl", "directory"]),
        ProviderSyncCursorModel.source_id.in_([row.id for row in rows]),
    ))) if rows else []
    by_source = {(cursor.source_id, cursor.sync_kind): cursor for cursor in cursors}
    now = datetime.now(timezone.utc)
    thresholds = {
        "acl": max(60, int(os.getenv("ACCESSPROOF_SOURCE_ACL_MAX_AGE_SECONDS", "900"))),
        "directory": max(60, int(os.getenv("ACCESSPROOF_SOURCE_DIRECTORY_MAX_AGE_SECONDS", "900"))),
    }
    result = []
    for row in rows:
        payload = _source_payload(row)
        for kind in ("directory", "acl"):
            cursor = by_source.get((row.id, kind))
            last_success = cursor.last_success_at if cursor else None
            if last_success is not None and last_success.tzinfo is None:
                last_success = last_success.replace(tzinfo=timezone.utc)
            age = (now - last_success).total_seconds() if last_success is not None else None
            fresh = bool(
                row.status == "connected" and not row.last_error and cursor
                and cursor.status == "connected" and not cursor.last_error_code
                and age is not None and 0 <= age <= thresholds[kind]
            )
            payload[f"{kind}_sync"] = {
                "status": cursor.status if cursor else "never_synced",
                "fresh": fresh,
                "last_success_at": last_success.isoformat() if last_success else None,
                "last_error_code": cursor.last_error_code if cursor else None,
            }
        result.append(payload)
    return result


@app.post("/api/v1/current/sources/{source_id}/sync-directory")
async def sync_current_source_directory(
    source_id: str,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Read a complete provider directory into the tenant identity graph.

    The synchronizer fetches every page before altering the graph.  A failed
    or incomplete provider read therefore leaves the most recent trusted
    directory data intact and marks the source degraded instead of denying
    access based on absence.
    """
    row = db.scalar(select(SourceConnection).where(
        SourceConnection.id == source_id,
        SourceConnection.organization_id == actor.membership.organization_id,
    ))
    if row is None:
        raise HTTPException(404, "Source not found")
    def record_failed_sync(error_code: str) -> None:
        # An exception can occur *after* a directory adapter has created
        # users, groups or queued ALLOW events. Never commit those partial
        # graph mutations just to record an error on the source.
        db.rollback()
        failed = db.scalar(select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        ))
        if failed is None:
            return
        code = error_code[:100]
        status = "reauthorization_required" if code == "REAUTHORIZATION_REQUIRED" else "degraded"
        failed.status, failed.last_error = status, code
        cursor = db.scalar(select(ProviderSyncCursorModel).where(
            ProviderSyncCursorModel.organization_id == failed.organization_id,
            ProviderSyncCursorModel.source_id == failed.id,
            ProviderSyncCursorModel.sync_kind == "directory",
        ))
        if cursor is None:
            cursor = ProviderSyncCursorModel(
                organization_id=failed.organization_id, source_id=failed.id,
                provider=failed.provider, sync_kind="directory",
            )
            db.add(cursor)
        cursor.status, cursor.last_error_code, cursor.last_error_at = (
            status, code, datetime.now(timezone.utc),
        )
        _audit(db, actor, failed.organization_id, "directory.sync_degraded", "source", failed.id, {"code": code})
        db.commit()

    try:
        credentials = json.loads(_secret_box.decrypt(row.encrypted_credentials)) if row.encrypted_credentials else {}
        result = await synchronize_directory(db, row, credentials)
    except DirectorySyncError as exc:
        record_failed_sync(exc.code)
        raise HTTPException(424, f"Directory synchronization failed: {exc.code}") from exc
    except Exception as exc:
        record_failed_sync("DIRECTORY_SYNC_INCOMPLETE")
        logger.warning("directory_sync_failed source_id=%s error=%s", source_id, type(exc).__name__)
        raise HTTPException(502, "Directory synchronization could not complete") from exc
    row.status = "connected"
    row.last_error = None
    row.last_validated_at = datetime.now(timezone.utc)
    _audit(db, actor, row.organization_id, "directory.sync_completed", "source", row.id, result)
    db.commit()
    return {"source": _source_payload(row), "synchronized": result}


@app.post("/api/v1/current/sources/{source_id}/sync-permissions", status_code=202)
def queue_current_source_permission_sync(
    source_id: str,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, str]:
    """Durably request a fresh ACL inventory without accepting browser tokens.

    The worker owns provider access and performs the authoritative read. Reset
    the cursor rather than treating an older completed snapshot as fresh while
    a customer explicitly asks for a new permissions synchronization.
    """
    source = db.scalar(select(SourceConnection).where(
        SourceConnection.id == source_id,
        SourceConnection.organization_id == actor.membership.organization_id,
    ))
    if source is None:
        raise HTTPException(404, "Source not found")
    if source.status == "disconnected" or not source.encrypted_credentials:
        raise HTTPException(409, "Connect or reauthorize the source before synchronizing permissions")
    cursor = db.scalar(select(ProviderSyncCursorModel).where(
        ProviderSyncCursorModel.organization_id == source.organization_id,
        ProviderSyncCursorModel.source_id == source.id,
        ProviderSyncCursorModel.sync_kind == "acl",
    ).with_for_update())
    if cursor is None:
        cursor = ProviderSyncCursorModel(
            organization_id=source.organization_id, source_id=source.id,
            provider="microsoft365" if source.provider.lower() in {"microsoft365", "sharepoint", "onedrive"} else source.provider,
            sync_kind="acl",
        )
        db.add(cursor)
    cursor.status = "queued"
    cursor.cursor = None
    cursor.last_provider_revision = None
    cursor.last_success_at = None
    cursor.last_started_at = None
    cursor.last_error_at = None
    cursor.last_error_code = None
    _audit(db, actor, source.organization_id, "source.permission_sync_queued", "source", source.id)
    db.commit()
    return {"status": "queued"}


@app.get("/api/v1/current/employees")
def list_current_employees(
    actor: Actor = Depends(require(Permission.RESULT_READ)), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    """Return tenant-scoped, provider-stable identities and active groups."""
    org_id = actor.membership.organization_id
    subjects = list(db.scalars(select(GuardSubject).where(
        GuardSubject.organization_id == org_id
    ).order_by(GuardSubject.display_name.asc(), GuardSubject.primary_email.asc(), GuardSubject.id.asc())))
    memberships = list(db.execute(select(GuardGroupMembership, GuardGroup).join(
        GuardGroup, GuardGroup.id == GuardGroupMembership.group_id
    ).where(
        GuardGroupMembership.organization_id == org_id,
        GuardGroupMembership.active.is_(True),
        GuardGroup.organization_id == org_id,
    )))
    groups_by_subject: dict[str, list[dict[str, Any]]] = {}
    for membership, group in memberships:
        groups_by_subject.setdefault(membership.subject_id, []).append({
            "id": group.id, "name": group.display_name or group.provider_group_id,
            "provider": group.provider, "stable_id": group.provider_group_id,
        })
    return [{
        "id": subject.id, "name": subject.display_name or subject.primary_email or subject.provider_subject_id,
        "email": subject.primary_email, "provider": subject.provider,
        "stable_id": subject.provider_subject_id, "status": subject.status,
        "last_synced_at": subject.last_synced_at.isoformat() if subject.last_synced_at else None,
        "groups": groups_by_subject.get(subject.id, []),
    } for subject in subjects]


@app.get("/api/v1/sources")
def list_sources(
    project_id: str, actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    _project_for_actor(db, actor, project_id)
    rows = db.scalars(
        select(SourceConnection).where(
            SourceConnection.project_id == project_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        )
    )
    return [_source_payload(r) for r in rows]


async def _validate_source_record(
    row: SourceConnection, actor: Actor, db: OrmSession, *, capability_refresh: bool
) -> dict[str, Any]:
    credentials = (
        json.loads(_secret_box.decrypt(row.encrypted_credentials))
        if row.encrypted_credentials
        else {}
    )
    now = datetime.now(timezone.utc)
    row.last_validated_at = now
    if capability_refresh:
        row.last_capability_refresh_at = now
    try:
        adapter = create_source_adapter(row.provider, credentials)
        identity = await adapter.validate_connection()
        caps = await adapter.discover_capabilities()
        cap_values = {k.value: v.value for k, v in caps.capabilities.items()}
        missing = sorted(
            [
                k.value
                for k, v in caps.capabilities.items()
                if v.value in {"MISSING_SCOPE", "PLAN_RESTRICTED"}
            ]
        )
        # The first successful validation after a selected-site assignment
        # must reset potentially stale observations and start both sync jobs.
        previously_awaiting_site_grant = (
            row.provider.lower() in {"microsoft365", "sharepoint", "onedrive"}
            and row.last_error == "MICROSOFT_SITE_ACCESS_GRANT_REQUIRED"
        )
        row.status = "connected"
        if previously_awaiting_site_grant:
            for kind in ("directory", "acl"):
                cursor = db.scalar(select(ProviderSyncCursorModel).where(
                    ProviderSyncCursorModel.organization_id == row.organization_id,
                    ProviderSyncCursorModel.source_id == row.id,
                    ProviderSyncCursorModel.sync_kind == kind,
                ).with_for_update())
                if cursor is None:
                    cursor = ProviderSyncCursorModel(
                        organization_id=row.organization_id, source_id=row.id,
                        provider="microsoft365", sync_kind=kind,
                    )
                    db.add(cursor)
                cursor.status = "queued"
                cursor.cursor = None
                cursor.last_provider_revision = None
                cursor.last_success_at = None
                cursor.last_started_at = None
                cursor.last_error_at = None
                cursor.last_error_code = None
        row.capabilities_json = json.dumps(cap_values, sort_keys=True)
        row.provider_identity_json = json.dumps(
            {
                "provider": identity.provider,
                "tenant": identity.tenant,
                "account": identity.account,
                "boundary": identity.boundary,
                "metadata": identity.metadata,
            },
            sort_keys=True,
        )
        row.granted_scopes_json = json.dumps(_configured_scopes(credentials), sort_keys=True)
        row.missing_scopes_json = json.dumps(missing, sort_keys=True)
        row.provider_api_version = _provider_api_version(adapter)
        row.last_error = None
        _audit(
            db,
            actor,
            row.organization_id,
            "source.capabilities_refreshed" if capability_refresh else "source.validated",
            "source",
            row.id,
            {"provider": row.provider, "missing": missing},
        )
        db.commit()
        return _source_payload(row) | {"details": caps.details}
    except KeyError as exc:
        row.status = "not_configured"
        row.last_error = f"Missing provider configuration: {exc.args[0]}"
        db.commit()
        raise HTTPException(422, row.last_error) from exc
    except Exception as exc:
        row.status = "error"
        if row.provider.lower() in {"microsoft365", "sharepoint", "onedrive"}:
            # Graph may include continuation URLs and opaque credentials in
            # provider errors. Persist a stable code, never arbitrary text.
            row.last_error = (
                "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY"
                if isinstance(exc, ProviderUnavailableError)
                and str(exc) == "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY"
                else "MICROSOFT_SITE_ACCESS_GRANT_REQUIRED"
                if isinstance(exc, AuthorizationError)
                else "MICROSOFT_SOURCE_VALIDATION_INCOMPLETE"
            )
        else:
            row.last_error = f"{type(exc).__name__}: {exc}"[:2000]
        queue_alert(
            db,
            organization_id=row.organization_id,
            project_id=row.project_id,
            kind="source_connection_failure",
            severity="critical",
            dedupe_key=f"source_connection_failure:{row.id}:{now.isoformat()}",
            subject=f"{settings.product_name}: source connection validation failed",
            detail=f"Source {row.name} ({row.provider}) failed validation: {type(exc).__name__}.",
        )
        db.commit()
        raise HTTPException(502, f"Provider validation failed: {type(exc).__name__}") from exc
    finally:
        client = locals().get("adapter")
        http_client = getattr(client, "_client", None) if client is not None else None
        if http_client is not None:
            try:
                await http_client.aclose()
            except Exception as exc:
                logger.warning(
                    "provider_client_close_failed provider=%s error=%s",
                    row.provider,
                    type(exc).__name__,
                )


@app.post("/api/v1/sources/{source_id}/validate")
async def validate_source(
    source_id: str,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Source not found")
    return await _validate_source_record(row, actor, db, capability_refresh=False)


@app.post("/api/v1/sources/{source_id}/refresh-capabilities")
async def refresh_source_capabilities(
    source_id: str,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Source not found")
    return await _validate_source_record(row, actor, db, capability_refresh=True)


@app.post("/api/v1/sources/{source_id}/rotate-credential")
def rotate_source_credential(
    source_id: str,
    payload: SourceCredentialUpdate,
    actor: Actor = Depends(require(Permission.SECRET_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Source not found")
    credentials = dict(payload.credentials)
    try:
        enforce_v1_browser_credential_policy(row.provider, credentials, settings)
    except V1ProviderScopeError as exc:
        raise HTTPException(422, {"code": "V1_BROWSER_CREDENTIALS_NOT_ALLOWED", "message": str(exc)}) from exc
    _enforce_microsoft_tenant_boundary(
        db, row.organization_id, row.provider, credentials, replace_source_id=row.id
    )
    row.encrypted_credentials = (
        _secret_box.encrypt(json.dumps(credentials, sort_keys=True))
        if credentials
        else None
    )
    row.status = "not_configured"
    row.last_error = None
    row.capabilities_json = "{}"
    row.provider_identity_json = "{}"
    row.missing_scopes_json = "[]"
    row.granted_scopes_json = json.dumps(_configured_scopes(payload.credentials), sort_keys=True)
    _audit(db, actor, row.organization_id, "source.credential_rotated", "source", row.id)
    db.commit()
    return _source_payload(row)


@app.post("/api/v1/sources/{source_id}/reauthorize")
async def reauthorize_source(
    source_id: str,
    payload: SourceCredentialUpdate,
    actor: Actor = Depends(require(Permission.SECRET_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Source not found")
    if not payload.credentials:
        raise HTTPException(422, "Replacement credentials are required")
    credentials = dict(payload.credentials)
    try:
        enforce_v1_browser_credential_policy(row.provider, credentials, settings)
    except V1ProviderScopeError as exc:
        raise HTTPException(422, {"code": "V1_BROWSER_CREDENTIALS_NOT_ALLOWED", "message": str(exc)}) from exc
    _enforce_microsoft_tenant_boundary(
        db, row.organization_id, row.provider, credentials, replace_source_id=row.id
    )
    # Validate the replacement before changing the encrypted record. A failed
    # reauthorization therefore preserves the known working credential.
    try:
        candidate = create_source_adapter(row.provider, credentials)
        identity = await candidate.validate_connection()
        capabilities = await candidate.discover_capabilities()
    except Exception as exc:
        raise HTTPException(422, f"Replacement credential validation failed: {type(exc).__name__}") from exc
    finally:
        http_client = getattr(locals().get("candidate"), "_client", None) or getattr(locals().get("candidate"), "client", None)
        if http_client is not None:
            await http_client.aclose()
    row.encrypted_credentials = _secret_box.encrypt(json.dumps(credentials, sort_keys=True))
    row.status = "connected"
    row.last_validated_at = datetime.now(timezone.utc)
    row.last_capability_refresh_at = row.last_validated_at
    row.capabilities_json = json.dumps({key.value: value.value for key, value in capabilities.capabilities.items()}, sort_keys=True)
    row.provider_identity_json = json.dumps({"provider": identity.provider, "tenant": identity.tenant, "account": identity.account, "boundary": identity.boundary, "metadata": identity.metadata}, sort_keys=True)
    row.granted_scopes_json = json.dumps(_configured_scopes(credentials), sort_keys=True)
    row.missing_scopes_json = json.dumps([key.value for key, value in capabilities.capabilities.items() if value.value in {"MISSING_SCOPE", "PLAN_RESTRICTED"}], sort_keys=True)
    row.last_error = None
    _audit(db, actor, row.organization_id, "source.reauthorized", "source", row.id)
    db.commit()
    return _source_payload(row)


@app.post("/api/v1/sources/{source_id}/disconnect")
def disconnect_source(
    source_id: str,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Source not found")
    active = db.scalar(
        select(TestRun.id)
        .where(TestRun.source_connection_id == row.id, TestRun.outcome.is_(None))
        .limit(1)
    )
    if active:
        raise HTTPException(409, "Source has an active test run")
    row.encrypted_credentials = None
    row.status = "disconnected"
    row.capabilities_json = "{}"
    row.provider_identity_json = "{}"
    row.granted_scopes_json = "[]"
    row.missing_scopes_json = "[]"
    row.last_error = None
    _audit(db, actor, row.organization_id, "source.disconnected", "source", row.id)
    db.commit()
    return _source_payload(row)


@app.post("/api/v1/targets", status_code=201)
def create_target(
    payload: TargetCreate,
    actor: Actor = Depends(require(Permission.TARGET_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    project = _project_for_actor(db, actor, payload.project_id)
    if not payload.runner_mode:
        try:
            validate_cloud_url(payload.url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    row = AITarget(
        organization_id=project.organization_id,
        project_id=project.id,
        name=payload.name,
        url=payload.url,
        runner_mode=payload.runner_mode,
        config_json=json.dumps(payload.config),
        encrypted_credentials=_secret_box.encrypt(json.dumps(payload.credentials))
        if payload.credentials
        else None,
    )
    db.add(row)
    db.flush()
    _audit(db, actor, project.organization_id, "target.created", "ai_target", row.id)
    db.commit()
    return {"id": row.id, "name": row.name, "url": row.url, "runner_mode": row.runner_mode}


@app.get("/api/v1/targets")
def list_targets(project_id: str, actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)) -> list[dict[str, Any]]:
    _project_for_actor(db, actor, project_id)
    rows = db.scalars(select(AITarget).where(AITarget.project_id == project_id, AITarget.organization_id == actor.membership.organization_id).order_by(AITarget.name))
    return [{"id": row.id, "project_id": row.project_id, "name": row.name, "url": row.url, "runner_mode": row.runner_mode, "config": json.loads(row.config_json or "{}"), "auth_configured": bool(row.encrypted_credentials)} for row in rows]


def _test_identity_payload(row: TestIdentity) -> dict[str, Any]:
    """Deliberately omit encrypted credential material from every control-plane response."""
    return {
        "id": row.id, "project_id": row.project_id, "display_name": row.display_name,
        "provider_type": row.provider_type, "provider_name": row.provider_name,
        "subject_id": row.subject_id, "email": row.email, "tenant_id": row.tenant_id,
        "issuer": row.issuer, "audience": row.audience,
        "required_scopes": json.loads(row.required_scopes_json or "[]"), "status": row.status,
        "last_validated_at": row.last_validated_at.isoformat() if row.last_validated_at else None,
        "last_error": row.last_error, "metadata": json.loads(row.metadata_json or "{}"),
    }


@app.post("/api/v1/test-identities", status_code=201)
def create_test_identity(payload: TestIdentityCreate, actor: Actor = Depends(require(Permission.SECRET_MANAGE)), db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    project = _project_for_actor(db, actor, payload.project_id)
    existing = db.scalar(
        select(TestIdentity).where(
            TestIdentity.project_id == project.id,
            TestIdentity.organization_id == project.organization_id,
            TestIdentity.provider_type == payload.provider_type,
            TestIdentity.subject_id == payload.subject_id,
        )
    )
    if existing:
        raise HTTPException(
            409,
            "A test identity with this provider and stable subject already exists; rotate its credential instead",
        )
    row = TestIdentity(
        organization_id=project.organization_id, project_id=project.id,
        display_name=payload.display_name, provider_type=payload.provider_type,
        provider_name=payload.provider_name, subject_id=payload.subject_id, email=payload.email,
        tenant_id=payload.tenant_id, issuer=payload.issuer, audience=payload.audience,
        required_scopes_json=json.dumps(sorted(set(payload.required_scopes))),
        encrypted_credentials=_secret_box.encrypt(json.dumps(payload.credentials, sort_keys=True)) if payload.credentials else None,
        metadata_json=json.dumps(payload.metadata, sort_keys=True),
    )
    db.add(row)
    db.flush()
    _audit(db, actor, project.organization_id, "test_identity.created", "test_identity", row.id, {"provider_type": row.provider_type})
    db.commit()
    return _test_identity_payload(row)


@app.get("/api/v1/test-identities")
def list_test_identities(project_id: str, actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)) -> list[dict[str, Any]]:
    _project_for_actor(db, actor, project_id)
    rows = db.scalars(select(TestIdentity).where(TestIdentity.project_id == project_id, TestIdentity.organization_id == actor.membership.organization_id).order_by(TestIdentity.display_name))
    return [_test_identity_payload(row) for row in rows]


@app.post("/api/v1/test-identities/{identity_id}/rotate-credential")
def rotate_test_identity_credential(identity_id: str, payload: TestIdentityCredentialUpdate, actor: Actor = Depends(require(Permission.SECRET_MANAGE)), db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    row = db.scalar(select(TestIdentity).where(TestIdentity.id == identity_id, TestIdentity.organization_id == actor.membership.organization_id))
    if not row:
        raise HTTPException(404, "Test identity not found")
    row.encrypted_credentials = _secret_box.encrypt(json.dumps(payload.credentials, sort_keys=True)) if payload.credentials else None
    row.status, row.last_error = "configured", None
    _audit(db, actor, row.organization_id, "test_identity.credential_rotated", "test_identity", row.id)
    db.commit()
    return _test_identity_payload(row)


@app.post("/api/v1/test-identities/{identity_id}/validate")
def validate_test_identity(identity_id: str, actor: Actor = Depends(require(Permission.SECRET_MANAGE)), db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    row = db.scalar(select(TestIdentity).where(TestIdentity.id == identity_id, TestIdentity.organization_id == actor.membership.organization_id))
    if not row:
        raise HTTPException(404, "Test identity not found")
    credentials = json.loads(_secret_box.decrypt(row.encrypted_credentials)) if row.encrypted_credentials else {}
    if row.provider_type == "static_bearer" and not isinstance(credentials.get("access_token") or credentials.get("bearer_token"), str):
        row.status, row.last_error = "invalid_configuration", "A bearer token is required for this identity"
    else:
        row.status, row.last_error = "validated", None
    row.last_validated_at = datetime.now(timezone.utc)
    _audit(db, actor, row.organization_id, "test_identity.validated", "test_identity", row.id, {"status": row.status})
    db.commit()
    return _test_identity_payload(row)


@app.post("/api/v1/test-identities/{identity_id}/disconnect")
def disconnect_test_identity(identity_id: str, actor: Actor = Depends(require(Permission.SECRET_MANAGE)), db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    row = db.scalar(select(TestIdentity).where(TestIdentity.id == identity_id, TestIdentity.organization_id == actor.membership.organization_id))
    if not row:
        raise HTTPException(404, "Test identity not found")
    row.encrypted_credentials, row.status, row.last_error = None, "disconnected", None
    _audit(db, actor, row.organization_id, "test_identity.disconnected", "test_identity", row.id)
    db.commit()
    return _test_identity_payload(row)


@app.delete("/api/v1/test-identities/{identity_id}", status_code=204)
def delete_test_identity(identity_id: str, actor: Actor = Depends(require(Permission.SECRET_MANAGE)), db: OrmSession = Depends(get_db)) -> None:
    row = db.scalar(select(TestIdentity).where(TestIdentity.id == identity_id, TestIdentity.organization_id == actor.membership.organization_id))
    if not row:
        raise HTTPException(404, "Test identity not found")
    active = db.scalar(select(TestRun.id).where(or_(TestRun.allowed_identity_id == row.id, TestRun.denied_identity_id == row.id), TestRun.outcome.is_(None)).limit(1))
    if active:
        raise HTTPException(409, "Test identity is used by an active run")
    _audit(db, actor, row.organization_id, "test_identity.deleted", "test_identity", row.id)
    db.delete(row)
    db.commit()


@app.post("/api/v1/suites", status_code=201)
def create_suite(
    payload: SuiteCreate,
    actor: Actor = Depends(require(Permission.TEST_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    project = _project_for_actor(db, actor, payload.project_id)
    scenario = ScenarioDefinition.model_validate(payload.scenario)
    row = TestSuite(
        organization_id=project.organization_id,
        project_id=project.id,
        name=payload.name,
        scenario_json=scenario.model_dump_json(),
    )
    db.add(row)
    db.flush()
    _audit(db, actor, project.organization_id, "suite.created", "test_suite", row.id)
    db.commit()
    return {"id": row.id, "name": row.name, "scenario": scenario.model_dump()}


@app.get("/api/v1/suites")
def list_suites(project_id: str, actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)) -> list[dict[str, Any]]:
    _project_for_actor(db, actor, project_id)
    rows = db.scalars(select(TestSuite).where(TestSuite.project_id == project_id, TestSuite.organization_id == actor.membership.organization_id).order_by(TestSuite.name))
    return [{"id": row.id, "project_id": row.project_id, "name": row.name, "scenario": json.loads(row.scenario_json)} for row in rows]


@app.post("/api/v1/releases", status_code=201)
def create_release(
    payload: ReleaseCreate,
    actor: Actor = Depends(require(Permission.TEST_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    project = _project_for_actor(db, actor, payload.project_id)
    row = Release(
        organization_id=project.organization_id,
        project_id=project.id,
        **payload.model_dump(exclude={"project_id"}),
    )
    db.add(row)
    db.flush()
    _audit(
        db, actor, project.organization_id, "release.created", "release", row.id, {"name": row.name}
    )
    db.commit()
    return {"id": row.id, "name": row.name, "git_sha": row.git_sha, "environment": row.environment}


@app.get("/api/v1/releases")
def list_releases(
    project_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    _project_for_actor(db, actor, project_id)
    rows = db.scalars(
        select(Release)
        .where(
            Release.project_id == project_id,
            Release.organization_id == actor.membership.organization_id,
        )
        .order_by(Release.created_at.desc())
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "git_sha": r.git_sha,
            "branch": r.branch,
            "environment": r.environment,
            "connector_version": r.connector_version,
            "retrieval_version": r.retrieval_version,
            "model_version": r.model_version,
            "reranker_version": r.reranker_version,
        }
        for r in rows
    ]


@app.post("/api/v1/releases/compare")
def compare_releases(
    payload: ReleaseComparisonRequest,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    project = _project_for_actor(db, actor, payload.project_id)
    try:
        baseline_policy = BaselinePolicy(payload.baseline_policy)
    except ValueError as exc:
        raise HTTPException(422, "Invalid baseline_policy") from exc
    if (
        baseline_policy in {BaselinePolicy.PINNED, BaselinePolicy.MANUAL}
        and not payload.baseline_release
    ):
        raise HTTPException(422, "baseline_release is required for pinned/manual policy")

    suites = db.scalars(
        select(TestSuite).where(
            TestSuite.project_id == project.id, TestSuite.organization_id == project.organization_id
        )
    ).all()
    comparisons = []
    for suite in suites:
        candidate = db.scalar(
            select(TestRun)
            .where(
                TestRun.project_id == project.id,
                TestRun.organization_id == project.organization_id,
                TestRun.suite_id == suite.id,
                TestRun.release == payload.candidate_release,
                TestRun.outcome.is_not(None),
            )
            .order_by(TestRun.created_at.desc())
            .limit(1)
        )
        scenario = ScenarioDefinition.model_validate_json(suite.scenario_json)
        if candidate is None:
            # A release decision must account for every configured suite.  A
            # missing REQUIRED run is never silently removed from the gate,
            # even when callers choose not to block on ordinary inconclusives.
            candidate_measurement = ScenarioMeasurement(
                suite_id=suite.id,
                suite_name=suite.name,
                severity=scenario.severity.value,
                release=payload.candidate_release,
                outcome="INCONCLUSIVE",
                stable_latency_seconds=None,
            )
            comparisons.append(
                compare_measurements(
                    None,
                    candidate_measurement,
                    maximum_absolute_regression_seconds=payload.maximum_absolute_regression_seconds,
                    maximum_percentage_regression=payload.maximum_percentage_regression,
                    block_on_inconclusive=(
                        payload.block_on_inconclusive
                        or scenario.severity.value == "REQUIRED"
                    ),
                )
            )
            continue
        candidate_result = json.loads(candidate.result_json or "{}")
        c_derived = candidate_result.get("derived") or {}
        candidate_measurement = ScenarioMeasurement(
            suite_id=suite.id,
            suite_name=suite.name,
            severity=scenario.severity.value,
            release=candidate.release,
            outcome=candidate.outcome or "ERROR",
            stable_latency_seconds=c_derived.get("stable_propagation_latency_seconds"),
            source_capabilities=tuple(candidate_result.get("source_capabilities") or ()),
        )

        baseline = None
        if baseline_policy is BaselinePolicy.PREVIOUS_SUCCESSFUL:
            baseline = db.scalar(
                select(TestRun)
                .where(
                    TestRun.project_id == project.id,
                    TestRun.organization_id == project.organization_id,
                    TestRun.suite_id == suite.id,
                    TestRun.outcome == "PASS",
                    TestRun.release != payload.candidate_release,
                    TestRun.created_at < candidate.created_at,
                )
                .order_by(TestRun.created_at.desc())
                .limit(1)
            )
        else:
            baseline = db.scalar(
                select(TestRun)
                .where(
                    TestRun.project_id == project.id,
                    TestRun.organization_id == project.organization_id,
                    TestRun.suite_id == suite.id,
                    TestRun.release == payload.baseline_release,
                    TestRun.outcome.is_not(None),
                )
                .order_by(TestRun.created_at.desc())
                .limit(1)
            )
        baseline_measurement = None
        if baseline is not None:
            baseline_result = json.loads(baseline.result_json or "{}")
            b_derived = baseline_result.get("derived") or {}
            baseline_measurement = ScenarioMeasurement(
                suite_id=suite.id,
                suite_name=suite.name,
                severity=scenario.severity.value,
                release=baseline.release,
                outcome=baseline.outcome or "ERROR",
                stable_latency_seconds=b_derived.get("stable_propagation_latency_seconds"),
                source_capabilities=tuple(baseline_result.get("source_capabilities") or ()),
            )
        regression = compare_measurements(
            baseline_measurement,
            candidate_measurement,
            maximum_absolute_regression_seconds=payload.maximum_absolute_regression_seconds,
            maximum_percentage_regression=payload.maximum_percentage_regression,
            block_on_inconclusive=payload.block_on_inconclusive,
        )
        comparisons.append(regression)

    if not comparisons:
        raise HTTPException(404, "No completed candidate runs found for this release")
    decision = decide_release(comparisons, block_on_inconclusive=payload.block_on_inconclusive)
    return {
        "project_id": project.id,
        "candidate_release": payload.candidate_release,
        "baseline_policy": baseline_policy.value,
        "baseline_release": payload.baseline_release,
        "decision": decision.value,
        "scenarios": [asdict(item) for item in comparisons],
    }


@app.post("/api/v1/runs", status_code=202)
def create_run(
    payload: RunCreate,
    actor: Actor = Depends(require(Permission.TEST_RUN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    # Caller tokens belong only in TestIdentity.encrypted_credentials.  Keeping them out
    # of run JSON prevents accidental inclusion in reports, checkpoints, and audit data.
    if "access_token" in payload.allowed_principal or "access_token" in payload.denied_principal:
        raise HTTPException(422, "Store caller tokens in a test identity, not a run payload")
    if bool(payload.allowed_identity_id) != bool(payload.denied_identity_id):
        raise HTTPException(422, "Allowed and denied test identities must be selected together")
    project = _project_for_actor(db, actor, payload.project_id)
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_count = (
        db.scalar(
            select(func.count(TestRun.id)).where(
                TestRun.organization_id == project.organization_id,
                TestRun.created_at >= month_start,
            )
        )
        or 0
    )
    _enforce_count_entitlement(db, project.organization_id, "monthly_test_runs", int(monthly_count))
    org = db.get(Organization, project.organization_id)
    if project.paused or (org and org.mutations_disabled):
        raise HTTPException(409, "Mutations are paused")
    suite = db.scalar(
        select(TestSuite).where(
            TestSuite.id == payload.suite_id,
            TestSuite.organization_id == project.organization_id,
            TestSuite.project_id == project.id,
        )
    )
    if not suite:
        raise HTTPException(404, "Suite not found")
    if payload.source_connection_id:
        source = db.scalar(
            select(SourceConnection).where(
                SourceConnection.id == payload.source_connection_id,
                SourceConnection.project_id == project.id,
                SourceConnection.organization_id == project.organization_id,
            )
        )
        if not source:
            raise HTTPException(404, "Source connection not found")
        if not source.mutation_acknowledged:
            raise HTTPException(409, "Source mutation acknowledgement is required")
    if payload.ai_target_id:
        target = db.scalar(
            select(AITarget).where(
                AITarget.id == payload.ai_target_id,
                AITarget.project_id == project.id,
                AITarget.organization_id == project.organization_id,
            )
        )
        if not target:
            raise HTTPException(404, "AI target not found")
    identities: list[TestIdentity] = []
    if payload.allowed_identity_id and payload.denied_identity_id:
        identities = list(db.scalars(select(TestIdentity).where(
            TestIdentity.id.in_([payload.allowed_identity_id, payload.denied_identity_id]),
            TestIdentity.project_id == project.id,
            TestIdentity.organization_id == project.organization_id,
        )))
        if len(identities) != 2:
            raise HTTPException(404, "Test identity not found")
        if any(identity.status not in {"configured", "validated"} for identity in identities):
            raise HTTPException(409, "Test identity is not ready for use")
        allowed_row = next(item for item in identities if item.id == payload.allowed_identity_id)
        denied_row = next(item for item in identities if item.id == payload.denied_identity_id)
        payload.allowed_principal = {"external_id": allowed_row.subject_id, "email": allowed_row.email}
        payload.denied_principal = {"external_id": denied_row.subject_id, "email": denied_row.email}
    run = TestRun(
        organization_id=project.organization_id,
        project_id=project.id,
        suite_id=suite.id,
        source_connection_id=payload.source_connection_id,
        ai_target_id=payload.ai_target_id,
        allowed_identity_id=payload.allowed_identity_id,
        denied_identity_id=payload.denied_identity_id,
        allowed_principal_json=json.dumps(payload.allowed_principal, sort_keys=True),
        denied_principal_json=json.dumps(payload.denied_principal, sort_keys=True),
        release=payload.release,
        git_sha=payload.git_sha,
        oracle_canary=f"AP-CANARY-{uuid4()}",
    )
    db.add(run)
    db.flush()
    _audit(
        db,
        actor,
        project.organization_id,
        "run.created",
        "test_run",
        run.id,
        {"release": payload.release},
    )
    db.commit()
    return {"id": run.id, "state": run.state, "status_url": f"/api/v1/runs/{run.id}"}


@app.post("/api/v1/runs/{run_id}/cancel")
def cancel_run(
    run_id: str,
    actor: Actor = Depends(require(Permission.TEST_RUN)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run:
        raise HTTPException(404, "Run not found")
    if run.outcome:
        return {"id": run.id, "cancel_requested": False, "already_terminal": True}
    run.cancel_requested = True
    if run.state == "CREATED":
        run.state = "CANCELED"
        run.outcome = "CANCELED"
        run.result_json = json.dumps(
            {"run_id": run.id, "outcome": "CANCELED", "reason": "Canceled before runner lease"}
        )
    _audit(db, actor, actor.membership.organization_id, "run.cancel_requested", "test_run", run.id)
    db.commit()
    return {"id": run.id, "cancel_requested": True, "state": run.state}


@app.get("/api/v1/runners/runs/{run_id}/cancel-status")
def runner_cancel_status(
    run_id: str,
    runner_id: str,
    authorization: str | None = Header(default=None),
    runner_secret: str | None = None,
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    # Credentials are accepted only from Authorization for this endpoint. Query-string
    # secrets are deliberately rejected because access logs and proxies retain URLs.
    if runner_secret is not None:
        raise HTTPException(400, "runner_secret must be sent as an Authorization bearer token")
    runner = _authenticate_runner(db, runner_id, _runner_secret_from_auth(authorization, None))
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id,
            TestRun.organization_id == runner.organization_id,
            TestRun.project_id == runner.project_id,
        )
    )
    if not run:
        raise HTTPException(404, "Run not found")
    return {"cancel_requested": run.cancel_requested}


@app.get("/api/v1/runs/{run_id}")
def get_run(
    run_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run:
        raise HTTPException(404, "Run not found")
    transitions = list(
        db.scalars(
            select(RunStateTransition)
            .where(RunStateTransition.run_id == run.id)
            .order_by(RunStateTransition.occurred_at.asc())
        )
    )
    evidence = list(
        db.scalars(
            select(EvidenceItem)
            .where(EvidenceItem.run_id == run.id)
            .order_by(EvidenceItem.observed_at.asc())
        )
    )
    checkpoint = db.get(RunnerCheckpoint, run.id)
    runner = db.get(Runner, run.lease_owner) if run.lease_owner else None
    started_at = transitions[0].occurred_at if transitions else None
    terminal_states = {"PASSED", "FAILED", "INCONCLUSIVE", "ERROR", "CANCELED", "PRECONDITION_FAILURE"}
    completed_at = next(
        (event.occurred_at for event in reversed(transitions) if event.state in terminal_states),
        None,
    )
    if completed_at is None and run.outcome and run.result_json:
        completed_at = json.loads(run.result_json).get("metrics", {}).get("completed_at")
    return {
        "id": run.id,
        "project_id": run.project_id,
        "suite_id": run.suite_id,
        "source_connection_id": run.source_connection_id,
        "ai_target_id": run.ai_target_id,
        "allowed_identity_id": run.allowed_identity_id,
        "denied_identity_id": run.denied_identity_id,
        "state": run.state,
        "outcome": run.outcome,
        "release": run.release,
        "git_sha": run.git_sha,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": started_at,
        "completed_at": completed_at,
        "lease_owner": run.lease_owner,
        "cancel_requested": run.cancel_requested,
        "runner": {"id": runner.id, "name": runner.name, "version": runner.version}
        if runner
        else None,
        "checkpoint": {
            "phase": checkpoint.phase,
            "updated_at": checkpoint.updated_at.isoformat() if checkpoint.updated_at else None,
        }
        if checkpoint
        else None,
        "events": [
            {"state": row.state, "at": row.occurred_at, "detail": row.detail}
            for row in transitions
        ],
        "evidence": [
            {
                "observed_at": row.observed_at,
                "exposed": row.exposed,
                "evidence_level": row.evidence_level,
                "matched_signal": row.matched_signal,
                "response_hash": row.response_hash,
            }
            for row in evidence
        ],
        "result": json.loads(run.result_json) if run.result_json else None,
    }


@app.get("/api/v1/runs")
def list_runs(
    project_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    project = _project_for_actor(db, actor, project_id)
    rows = list(
        db.scalars(
            select(TestRun)
            .where(
                TestRun.project_id == project.id,
                TestRun.organization_id == project.organization_id,
            )
            .order_by(TestRun.created_at.desc())
            .limit(100)
        )
    )
    result: list[dict[str, Any]] = []
    for run in rows:
        suite = db.get(TestSuite, run.suite_id)
        source = db.get(SourceConnection, run.source_connection_id) if run.source_connection_id else None
        target = db.get(AITarget, run.ai_target_id) if run.ai_target_id else None
        allowed = db.get(TestIdentity, run.allowed_identity_id) if run.allowed_identity_id else None
        denied = db.get(TestIdentity, run.denied_identity_id) if run.denied_identity_id else None
        runner = db.get(Runner, run.lease_owner) if run.lease_owner else None
        result.append({
            "id": run.id,
            "project_id": run.project_id,
            "suite_id": run.suite_id,
            "suite_name": suite.name if suite else None,
            "source_name": source.name if source else "Local mock",
            "target_name": target.name if target else "Local mock",
            "allowed_identity": allowed.display_name if allowed else "Alice / local mock",
            "denied_identity": denied.display_name if denied else "Bob / local mock",
            "release": run.release,
            "state": run.state,
            "outcome": run.outcome,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "runner": {"id": runner.id, "name": runner.name} if runner else None,
            "runner_required": bool(target and target.runner_mode),
            "reason": (json.loads(run.result_json).get("reason") if run.result_json else None),
        })
    return result


# Register the more specific SARIF route before the generic ``{run_id}.json``
# route. Starlette evaluates routes in declaration order, and otherwise a request
# for ``<id>.sarif.json`` is consumed by the generic JSON route as run_id
# ``<id>.sarif`` and incorrectly returns 404.
_CONTROL_PLANE_REPORT_TTL_DAYS = 30
_CONTROL_PLANE_REPORT_STORAGE_LIMIT = 200
_CONTROL_PLANE_REPORT_SCHEMA = "accessproof.control_plane_report/v1"


def _subject_reference(subject_id: str) -> str:
    """Pseudo-reference for report correlation without exporting raw identities."""
    return hashlib.sha256(subject_id.encode("utf-8")).hexdigest()[:16]


def _provider_evidence_by_source(
    db: OrmSession, sources: list[SourceConnection]
) -> dict[str, str]:
    evidence: dict[str, str] = {}
    for source in sources:
        if (source.provider or "").lower() not in {"microsoft365", "sharepoint", "onedrive"}:
            evidence[source.id] = "NOT_OBSERVED"
            continue
        try:
            credentials = json.loads(_secret_box.decrypt(source.encrypted_credentials or ""))
            certified = effective_source_certified(db, source, credentials)
        except Exception:
            certified = False
        evidence[source.id] = (
            "CONFIRMED_INDEPENDENTLY_AGAINST_PROVIDER" if certified else "NOT_OBSERVED"
        )
    return evidence


def _build_control_plane_report(
    db: OrmSession,
    *,
    organization_id: str,
    report_type: str,
    report_id: str,
    generated_by_user_id: str,
    now: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Assemble an evidence export from persisted tenant state only.

    The payload deliberately distinguishes control-plane observations,
    machine-asserted Guard evidence, provider-confirmed permission evidence,
    and facts that were never observed.
    """
    snapshot = _protection_snapshot(db, organization_id)
    guards = list(db.scalars(select(GuardRegistration).where(
        GuardRegistration.organization_id == organization_id,
    ).order_by(GuardRegistration.created_at.desc()).limit(200)).all())
    sources = list(db.scalars(select(SourceConnection).where(
        SourceConnection.organization_id == organization_id,
    ).order_by(SourceConnection.name.asc()).limit(200)).all())
    provider_evidence = _provider_evidence_by_source(db, sources)
    decision_since = now - timedelta(hours=24)
    decision_counts = {
        "layer1": {"allow": 0, "block": 0, "would_allow": 0, "would_block": 0},
        "layer2": {"allow": 0, "block": 0, "would_allow": 0, "would_block": 0},
    }
    observed_decisions = 0
    for layer, result, count in db.execute(select(
        GuardAuditEvent.layer, GuardAuditEvent.result, func.count(GuardAuditEvent.id),
    ).where(
        GuardAuditEvent.organization_id == organization_id,
        GuardAuditEvent.created_at >= decision_since,
    ).group_by(GuardAuditEvent.layer, GuardAuditEvent.result)).all():
        layer_key = "layer2" if layer == "layer2" else "layer1"
        if result in decision_counts[layer_key]:
            decision_counts[layer_key][result] += int(count)
            observed_decisions += int(count)
    recent_decisions = []
    if report_type == "AUTHORIZATION_ACTIVITY":
        for event in db.scalars(select(GuardAuditEvent).where(
            GuardAuditEvent.organization_id == organization_id,
        ).order_by(GuardAuditEvent.created_at.desc()).limit(100)).all():
            recent_decisions.append({
                "id": event.id,
                "decision_id": event.decision_id,
                "application_id": event.application_id,
                "subject_ref": _subject_reference(event.subject_id),
                "layer": event.layer,
                "result": event.result,
                "reason": event.reason,
                "policy_version": event.policy_version,
                "authorization_revision": event.authorization_revision,
                "authorization_revision_hash": event.authorization_revision_hash,
                "resource_count": len(json.loads(event.resources_json or "[]")),
                "occurred_at": (event.occurred_at or event.created_at).isoformat(),
            })
    all_provider_confirmed = bool(sources) and all(
        level == "CONFIRMED_INDEPENDENTLY_AGAINST_PROVIDER"
        for level in provider_evidence.values()
    )
    applications = snapshot["applications"] if report_type in {
        "APPLICATION_COVERAGE", "GUARD_HEALTH",
    } else []
    evidence_levels = {
        "control_plane_state": "DIRECTLY_OBSERVED_BY_ACCESSPROOF",
        "guard_decisions": "ASSERTED_BY_CUSTOMER_MACHINE" if observed_decisions else "NOT_OBSERVED",
        "provider_effective_permissions": (
            "CONFIRMED_INDEPENDENTLY_AGAINST_PROVIDER" if all_provider_confirmed
            else "NOT_OBSERVED"
        ),
        "revocation_to_first_denial_timing": "NOT_OBSERVED",
    }
    payload: dict[str, Any] = {
        "schema": _CONTROL_PLANE_REPORT_SCHEMA,
        "report_id": report_id,
        "report_type": report_type,
        "organization_id": organization_id,
        "generated_by_user_id": generated_by_user_id,
        "generated_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "product": settings.product_name,
        "signer_role": "accessproof-control-plane",
        "data_cutoff": now.isoformat(),
        "scope": {
            "tenant_scoped": True,
            "applications": [row["application_id"] for row in snapshot["applications"]],
            "guards": [guard.id for guard in guards],
            "sources": [source.id for source in sources],
        },
        "evidence_levels": evidence_levels,
        "summary": {
            "applications_registered": snapshot["totals"]["applications_registered"],
            "applications_protected_verified": snapshot["totals"]["applications_protected_verified"],
            "applications_not_verified": snapshot["totals"]["applications_not_verified"],
            "guards_online": snapshot["totals"]["guards_online"],
            "guards_total": snapshot["totals"]["guards_total"],
            "sources_fresh": snapshot["totals"]["sources_fresh"],
            "sources_total": snapshot["totals"]["sources_total"],
            "decisions_24h": {
                **decision_counts,
                "telemetry": "OBSERVED" if observed_decisions else "NO_DATA",
                "total": observed_decisions,
            },
        },
        "applications": applications,
        "guards": [{
            "id": guard.id,
            "name": guard.name,
            "environment": guard.environment,
            "version": guard.version,
            "health": _guard_health_state(guard, now),
            "active_policy_version": guard.active_policy_version,
            "heartbeat_age_seconds": _age_seconds(guard.last_heartbeat_at, now),
            "enrolled_at": guard.enrolled_at.isoformat() if guard.enrolled_at else None,
            "revoked_at": guard.revoked_at.isoformat() if guard.revoked_at else None,
        } for guard in guards],
        "sources": [{
            "id": source.id,
            "name": source.name,
            "provider": source.provider,
            "status": source.status,
            "last_validated_at": source.last_validated_at.isoformat() if source.last_validated_at else None,
            "acl_sync_age_seconds": _source_sync_age(db, source, "acl", now),
            "directory_sync_age_seconds": _source_sync_age(db, source, "directory", now),
            "provider_access_evidence": provider_evidence[source.id],
        } for source in sources],
        "decisions": {
            "aggregate_24h": {
                **decision_counts,
                "telemetry": "OBSERVED" if observed_decisions else "NO_DATA",
                "total": observed_decisions,
            },
            "recent": recent_decisions,
        },
        "limitations": [
            "Control-plane observations are directly recorded by AccessProof for this tenant only.",
            "Guard decisions are asserted by the enrolled customer-side Guard; the control plane has not independently replayed them.",
            "Provider effective permissions are confirmed only for sources explicitly labelled CONFIRMED_INDEPENDENTLY_AGAINST_PROVIDER.",
            "Revocation-to-first-denial timing is not measured unless a separate measured experiment is attached.",
            "No prompts, document contents, answers, tokens, raw employee identifiers, or source boundaries are included.",
            "An APPLICATION_COVERAGE entry is not a route certificate; PROTECTED_VERIFIED reflects current backend checks and expires.",
        ],
    }
    return payload


def _control_plane_report_summary(row: ControlPlaneReport) -> dict[str, Any]:
    payload = json.loads(row.payload_json)
    return {
        "id": row.id,
        "report_type": row.report_type,
        "generated_at": row.generated_at.isoformat(),
        "expires_at": row.expires_at.isoformat(),
        "report_hash": row.report_hash,
        "key_id": row.signing_key_id,
        "evidence_levels": payload.get("evidence_levels", {}),
        "summary": payload.get("summary", {}),
    }


def _control_plane_report_or_404(
    db: OrmSession, report_id: str, organization_id: str
) -> ControlPlaneReport:
    row = db.scalar(select(ControlPlaneReport).where(
        ControlPlaneReport.id == report_id,
        ControlPlaneReport.organization_id == organization_id,
    ))
    if row is None:
        raise HTTPException(404, "Report not found")
    return row


def _verify_control_plane_report(row: ControlPlaneReport, now: datetime) -> dict[str, Any]:
    payload = json.loads(row.payload_json)
    manifest = json.loads(row.signed_manifest_json)
    signature_valid = verify_manifest(payload, manifest)
    # The server-owned signing key is the local trust root.  The report's
    # embedded public key remains export metadata and cannot establish issuer
    # authenticity by itself.
    trusted_manifest = _report_signer.sign({}).as_dict()
    issuer_trusted = verify_manifest_with_trust(
        payload, manifest,
        {trusted_manifest["key_id"]: trusted_manifest["public_key"]},
    )
    scope_valid = bool(
        payload.get("schema") == _CONTROL_PLANE_REPORT_SCHEMA
        and payload.get("report_id") == row.id
        and payload.get("report_type") == row.report_type
        and payload.get("organization_id") == row.organization_id
    )
    expires = _utc(row.expires_at)
    expired = bool(expires is not None and expires <= now)
    return {
        "report_id": row.id,
        "report_type": row.report_type,
        "verified": signature_valid and issuer_trusted and scope_valid and not expired,
        "signature_valid": signature_valid,
        "issuer_trusted": issuer_trusted,
        "scope_valid": scope_valid,
        "expired": expired,
        "generated_at": row.generated_at.isoformat(),
        "expires_at": row.expires_at.isoformat(),
        "report_hash": row.report_hash,
        "key_id": row.signing_key_id,
        "evidence_levels": payload.get("evidence_levels", {}),
        "limitations": payload.get("limitations", []),
    }


@app.post("/api/v1/current/reports", status_code=201)
def create_control_plane_report(
    payload: ControlPlaneReportCreate,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = actor.membership.organization_id
    existing = int(db.scalar(select(func.count(ControlPlaneReport.id)).where(
        ControlPlaneReport.organization_id == org_id,
    )) or 0)
    if existing >= _CONTROL_PLANE_REPORT_STORAGE_LIMIT:
        raise HTTPException(
            429,
            {
                "code": "REPORT_STORAGE_LIMIT",
                "message": "The tenant report retention limit has been reached; export and remove old reports through the approved retention workflow.",
            },
        )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=_CONTROL_PLANE_REPORT_TTL_DAYS)
    report_id = str(uuid4())
    report_payload = _build_control_plane_report(
        db,
        organization_id=org_id,
        report_type=payload.report_type,
        report_id=report_id,
        generated_by_user_id=actor.user.id,
        now=now,
        expires_at=expires_at,
    )
    manifest = _report_signer.sign(report_payload).as_dict()
    row = ControlPlaneReport(
        id=report_id,
        organization_id=org_id,
        report_type=payload.report_type,
        generated_by_user_id=actor.user.id,
        generated_at=now,
        expires_at=expires_at,
        payload_json=json.dumps(report_payload, sort_keys=True),
        report_hash=manifest["payload_sha256"],
        signing_key_id=manifest["key_id"],
        signature=manifest["signature"],
        signing_public_key=manifest["public_key"],
        signed_manifest_json=json.dumps(manifest, sort_keys=True),
    )
    db.add(row)
    _audit(db, actor, org_id, "report.generated", "control_plane_report", report_id, {
        "report_type": payload.report_type,
    })
    db.commit()
    return {
        "report": report_payload,
        "signature": manifest,
        "verification": _verify_control_plane_report(row, now),
    }


@app.get("/api/v1/current/reports")
def list_control_plane_reports(
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = db.scalars(select(ControlPlaneReport).where(
        ControlPlaneReport.organization_id == actor.membership.organization_id,
    ).order_by(ControlPlaneReport.generated_at.desc()).limit(100)).all()
    return [_control_plane_report_summary(row) for row in rows]


@app.get("/api/v1/current/reports/{report_id}")
def read_control_plane_report(
    report_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = _control_plane_report_or_404(db, report_id, actor.membership.organization_id)
    return {
        "report": json.loads(row.payload_json),
        "signature": json.loads(row.signed_manifest_json),
        "verification": _verify_control_plane_report(row, datetime.now(timezone.utc)),
    }


@app.get("/api/v1/current/reports/{report_id}/verify")
def verify_control_plane_report(
    report_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = _control_plane_report_or_404(db, report_id, actor.membership.organization_id)
    return _verify_control_plane_report(row, datetime.now(timezone.utc))


@app.get("/api/v1/current/reports/{report_id}/download")
def download_control_plane_report(
    report_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> Response:
    row = _control_plane_report_or_404(db, report_id, actor.membership.organization_id)
    _audit(db, actor, row.organization_id, "report.downloaded", "control_plane_report", row.id, {
        "report_type": row.report_type,
    })
    db.commit()
    body = {
        "report": json.loads(row.payload_json),
        "signature": json.loads(row.signed_manifest_json),
    }
    return Response(
        json.dumps(body, indent=2, sort_keys=True),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="accessproof-{row.report_type.lower()}-{row.id}.json"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/reports/{run_id}.sarif.json")
def report_sarif(
    run_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run or not run.result_json:
        raise HTTPException(404, "Report not found")
    return render_sarif_payload(json.loads(run.result_json))


@app.get("/api/v1/reports/{run_id}.json")
def report_json(
    run_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run or not run.result_json:
        raise HTTPException(404, "Report not found")
    return dict(json.loads(run.result_json))


@app.get("/api/v1/reports/{run_id}.html", response_class=HTMLResponse)
def report_html(
    run_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> HTMLResponse:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run or not run.result_json:
        raise HTTPException(404, "Report not found")
    return HTMLResponse(render_html_payload(json.loads(run.result_json)))


@app.get("/api/v1/reports/{run_id}.pdf")
def report_pdf(
    run_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> Response:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run or not run.result_json:
        raise HTTPException(404, "Report not found")
    return Response(
        render_pdf_payload(json.loads(run.result_json)),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=accessproof-{run_id}.pdf"},
    )


@app.get("/api/v1/reports/{run_id}.junit.xml")
def report_junit(
    run_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> Response:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run or not run.result_json:
        raise HTTPException(404, "Report not found")
    return Response(render_junit_payload(json.loads(run.result_json)), media_type="application/xml")


@app.get("/api/v1/reports/{run_id}/integrity")
def report_integrity(
    run_id: str,
    actor: Actor = Depends(require(Permission.REPORT_READ)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == run_id, TestRun.organization_id == actor.membership.organization_id
        )
    )
    if not run or not run.result_json:
        raise HTTPException(404, "Report not found")
    report = db.scalar(
        select(Report).where(
            Report.run_id == run.id, Report.organization_id == actor.membership.organization_id
        )
    )
    if not report or not report.signed_manifest_json:
        return {"run_id": run.id, "verified": False, "reason": "report is not digitally signed"}
    payload = json.loads(run.result_json)
    manifest = json.loads(report.signed_manifest_json)
    verified = verify_manifest(payload, manifest)
    return {
        "run_id": run.id,
        # `verified` is retained for API compatibility and means only that the
        # persisted payload still matches the server signature. It does not
        # claim a control-plane observer executed private provider/target calls.
        "verified": verified,
        "integrity_verified": verified,
        "execution_independently_verified": False,
        "verification_scope": "server-signed runner attestation with consistency validation",
        "server_validation": payload.get("server_validation"),
        "report_hash": report.report_hash,
        "algorithm": manifest.get("algorithm"),
        "key_id": manifest.get("key_id"),
        "payload_sha256": manifest.get("payload_sha256"),
        "public_key": manifest.get("public_key"),
        "signature": manifest.get("signature"),
    }


@app.post("/api/v1/runners/registrations", status_code=201)
def create_runner_registration(
    payload: RunnerRegistrationCreate,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    project = _project_for_actor(db, actor, payload.project_id)
    count = (
        db.scalar(
            select(func.count(Runner.id)).where(
                Runner.organization_id == project.organization_id, Runner.revoked.is_(False)
            )
        )
        or 0
    )
    _enforce_count_entitlement(db, project.organization_id, "runners", int(count))
    # This is a bootstrap credential, not a runner credential. It is shown once,
    # stored only as a hash, constrained to the selected project, and consumed by
    # the runner's enrollment client over TLS in production.
    token = f"AP-ENROLL-{secrets.token_hex(18).upper()}"
    row = RunnerRegistration(
        organization_id=project.organization_id,
        project_id=project.id,
        token_hash=hash_token(token),
        display_name=payload.display_name,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.expires_in_minutes),
    )
    db.add(row)
    db.flush()
    _audit(
        db,
        actor,
        project.organization_id,
        "runner.registration_created",
        "runner_registration",
        row.id,
    )
    db.commit()
    return {
        "registration_token": token,
        "expires_in_seconds": payload.expires_in_minutes * 60,
        "project_id": project.id,
        "display_name": row.display_name,
    }


@app.get("/api/v1/runners/registrations")
def list_runner_registrations(
    project_id: str,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    project = _project_for_actor(db, actor, project_id)
    now = datetime.now(timezone.utc)
    rows = db.scalars(
        select(RunnerRegistration)
        .where(
            RunnerRegistration.organization_id == project.organization_id,
            RunnerRegistration.project_id == project.id,
        )
        .order_by(RunnerRegistration.created_at.desc())
        .limit(100)
    ).all()
    result = []
    for row in rows:
        expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
        result.append({
            "id": row.id,
            "project_id": row.project_id,
            "display_name": row.display_name,
            "created_at": row.created_at.isoformat(),
            "expires_at": row.expires_at.isoformat(),
            "used_at": row.used_at.isoformat() if row.used_at else None,
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
            "status": "revoked"
            if row.revoked_at
            else ("used" if row.used_at else ("expired" if expires_at <= now else "active")),
        })
    return result


@app.post("/api/v1/runners/registrations/{registration_id}/revoke")
def revoke_runner_registration(
    registration_id: str,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(RunnerRegistration).where(
            RunnerRegistration.id == registration_id,
            RunnerRegistration.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Enrollment code not found")
    if row.used_at is not None:
        raise HTTPException(409, "Used enrollment codes cannot be revoked")
    row.revoked_at = datetime.now(timezone.utc)
    _audit(db, actor, row.organization_id, "runner.registration_revoked", "runner_registration", row.id)
    db.commit()
    return {"id": row.id, "revoked": True}


@app.post("/api/v1/runners/exchange", status_code=201)
def exchange_runner(payload: RunnerExchange, db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    row = db.scalar(
        select(RunnerRegistration).where(
            RunnerRegistration.token_hash == hash_token(payload.registration_token)
        ).with_for_update()
    )
    if not row or row.used_at is not None or row.revoked_at is not None:
        raise HTTPException(401, "Invalid registration token")
    expires = (
        row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    )
    if expires <= now:
        raise HTTPException(401, "Expired registration token")
    if not _runner_version_compatible(payload.version):
        raise HTTPException(
            409,
            f"Runner {payload.version} is below minimum supported version {settings.minimum_runner_version}",
        )
    # Tenant derived from the matched one-time secret, never from the caller.
    set_tenant_context(db, row.organization_id)
    secret = secrets.token_urlsafe(48)
    runner = Runner(
        organization_id=row.organization_id,
        project_id=row.project_id,
        name=payload.name,
        credential_hash=hash_token(secret),
        version=payload.version,
        platform=payload.platform,
        architecture=payload.architecture,
        capabilities_json=json.dumps(payload.capabilities),
        installed_at=now,
        last_heartbeat_at=now,
    )
    db.add(runner)
    row.used_at = now
    db.flush()
    _audit(
        db,
        None,
        row.organization_id,
        "runner.registered",
        "runner",
        runner.id,
        {"version": payload.version, "platform": payload.platform, "architecture": payload.architecture},
    )
    db.commit()
    return {
        "runner_id": runner.id,
        "runner_secret": secret,
        "minimum_runner_version": settings.minimum_runner_version,
    }


@app.post("/api/v1/runners/heartbeat")
def runner_heartbeat(
    payload: RunnerHeartbeat,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    runner_secret = _runner_secret_from_auth(authorization, None)
    runner = db.get(Runner, payload.runner_id)
    if (
        not runner
        or runner.revoked
        or runner.disabled
        or runner.credential_hash != hash_token(runner_secret or "")
    ):
        raise HTTPException(401, "Invalid runner credential")
    if not _runner_version_compatible(payload.version):
        raise HTTPException(
            409,
            f"Runner {payload.version} is below minimum supported version {settings.minimum_runner_version}",
        )
    runner.last_heartbeat_at = datetime.now(timezone.utc)
    runner.version = payload.version
    if payload.platform:
        runner.platform = payload.platform
    if payload.architecture:
        runner.architecture = payload.architecture
    if payload.capabilities is not None:
        runner.capabilities_json = json.dumps(payload.capabilities)
    db.commit()
    runner_heartbeats.inc()
    return {"ok": True, "minimum_runner_version": settings.minimum_runner_version}


@app.get("/api/v1/runners")
def list_runners(
    project_id: str,
    actor: Actor = Depends(require(Permission.RESULT_READ)),
    db: OrmSession = Depends(get_db),
) -> list[dict[str, Any]]:
    project = _project_for_actor(db, actor, project_id)
    now = datetime.now(timezone.utc)
    rows = db.scalars(
        select(Runner)
        .where(Runner.project_id == project.id, Runner.organization_id == project.organization_id)
        .order_by(Runner.name.asc())
    ).all()
    result = []
    for row in rows:
        heartbeat = row.last_heartbeat_at
        if heartbeat and heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        age = (now - heartbeat).total_seconds() if heartbeat else None
        online = bool(
            age is not None
            and age <= settings.runner_offline_seconds
            and not row.revoked
            and not row.disabled
        )
        result.append(
            {
                "id": row.id,
                "name": row.name,
                "project_id": row.project_id,
                "version": row.version,
                "online": online,
                "health": "revoked"
                if row.revoked
                else ("disabled" if row.disabled else ("online" if online else "offline")),
                "last_heartbeat_at": heartbeat.isoformat() if heartbeat else None,
                "heartbeat_age_seconds": age,
                "last_job_at": row.last_job_at.isoformat() if row.last_job_at else None,
                "compatible": _runner_version_compatible(row.version),
                "platform": row.platform,
                "architecture": row.architecture,
                "capabilities": json.loads(row.capabilities_json or "{}"),
                "installed_at": row.installed_at.isoformat() if row.installed_at else None,
                "created_at": row.created_at.isoformat(),
            }
        )
    return result


@app.post("/api/v1/runners/{runner_id}/rotate-credential")
def rotate_runner_credential(
    runner_id: str,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(Runner).where(
            Runner.id == runner_id, Runner.organization_id == actor.membership.organization_id
        )
    )
    if not row:
        raise HTTPException(404, "Runner not found")
    secret = secrets.token_urlsafe(48)
    row.credential_hash = hash_token(secret)
    row.credential_rotated_at = datetime.now(timezone.utc)
    _audit(db, actor, row.organization_id, "runner.credential_rotated", "runner", row.id)
    db.commit()
    return {"runner_id": row.id, "runner_secret": secret}


@app.post("/api/v1/runners/{runner_id}/revoke")
def revoke_runner(
    runner_id: str,
    payload: RunnerAdminAction | None = None,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(Runner).where(
            Runner.id == runner_id, Runner.organization_id == actor.membership.organization_id
        )
    )
    if not row:
        raise HTTPException(404, "Runner not found")
    row.revoked = True
    row.disabled = True
    leased = db.scalars(
        select(TestRun).where(TestRun.lease_owner == row.id, TestRun.outcome.is_(None))
    ).all()
    for run in leased:
        run.state = "RUNNER_DISCONNECTED"
        run.lease_owner = None
        run.lease_expires_at = None
    _audit(
        db,
        actor,
        row.organization_id,
        "runner.revoked",
        "runner",
        row.id,
        {"reason": payload.reason if payload else None, "released_runs": len(leased)},
    )
    db.commit()
    return {"id": row.id, "revoked": True, "released_runs": len(leased)}


@app.post("/api/v1/runners/{runner_id}/disable")
def disable_runner(
    runner_id: str,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(Runner).where(
            Runner.id == runner_id, Runner.organization_id == actor.membership.organization_id
        )
    )
    if not row:
        raise HTTPException(404, "Runner not found")
    row.disabled = True
    _audit(db, actor, row.organization_id, "runner.disabled", "runner", row.id)
    db.commit()
    return {"id": row.id, "disabled": True}


@app.post("/api/v1/runners/{runner_id}/enable")
def enable_runner(
    runner_id: str,
    actor: Actor = Depends(require(Permission.RUNNER_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(Runner).where(
            Runner.id == runner_id, Runner.organization_id == actor.membership.organization_id
        )
    )
    if not row:
        raise HTTPException(404, "Runner not found")
    if row.revoked:
        raise HTTPException(409, "Revoked runner must be re-enrolled")
    row.disabled = False
    _audit(db, actor, row.organization_id, "runner.enabled", "runner", row.id)
    db.commit()
    return {"id": row.id, "disabled": False}


@app.post("/api/v1/webhooks", status_code=201)
def create_webhook(
    payload: WebhookCreate,
    actor: Actor = Depends(require(Permission.CI_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    if payload.project_id:
        _project_for_actor(db, actor, payload.project_id)
    try:
        validate_cloud_url(payload.url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    raw = secrets.token_urlsafe(32)
    row = WebhookEndpoint(
        organization_id=actor.membership.organization_id,
        project_id=payload.project_id,
        url=payload.url,
        secret_hash=hash_token(raw),
        encrypted_secret=_secret_box.encrypt(raw),
    )
    db.add(row)
    db.flush()
    _audit(db, actor, actor.membership.organization_id, "webhook.created", "webhook", row.id)
    db.commit()
    return {"id": row.id, "signing_secret": raw, "url": row.url}


@app.get("/api/v1/webhooks")
def list_webhooks(
    actor: Actor = Depends(require(Permission.CI_MANAGE)), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(WebhookEndpoint)
        .where(WebhookEndpoint.organization_id == actor.membership.organization_id)
        .order_by(WebhookEndpoint.created_at.desc())
    )
    return [
        {
            "id": row.id,
            "project_id": row.project_id,
            "url": row.url,
            "enabled": row.enabled,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


@app.delete("/api/v1/webhooks/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: str,
    actor: Actor = Depends(require(Permission.CI_MANAGE)),
    db: OrmSession = Depends(get_db),
) -> Response:
    row = db.scalar(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == webhook_id,
            WebhookEndpoint.organization_id == actor.membership.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Webhook not found")
    db.execute(delete(WebhookDelivery).where(WebhookDelivery.endpoint_id == row.id))
    _audit(db, actor, row.organization_id, "webhook.deleted", "webhook", row.id)
    db.delete(row)
    db.commit()
    return Response(status_code=204)


@app.get("/api/v1/entitlements")
def entitlements(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(Entitlement).where(Entitlement.organization_id == actor.membership.organization_id)
    )
    return [{"key": r.key, "value": r.value, "source": r.source} for r in rows]


@app.get("/api/v1/audit")
def audit_log(
    actor: Actor = Depends(require(Permission.AUDIT_READ)), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.organization_id == actor.membership.organization_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(200)
    )
    return [
        {
            "id": r.id,
            "actor": r.actor_user_id,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "created_at": r.created_at.isoformat(),
            "metadata": json.loads(r.metadata_json),
        }
        for r in rows
    ]


def _authenticate_runner(db: OrmSession, runner_id: str, runner_secret: str | None) -> Runner:
    runner = db.get(Runner, runner_id)
    if (
        not runner
        or runner.revoked
        or runner.disabled
        or runner.credential_hash != hash_token(runner_secret or "")
    ):
        raise HTTPException(401, "Invalid runner credential")
    set_tenant_context(db, runner.organization_id)
    return runner


def _runner_secret_from_auth(authorization: str | None, body_secret: str | None) -> str | None:
    """Read runner credentials exclusively from an HTTP Authorization header."""
    if body_secret is not None:
        raise HTTPException(400, "runner_secret must be sent as an Authorization bearer token")
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not value:
            raise HTTPException(401, "Invalid runner authorization")
        return value
    return None


def _parse_checkpoint_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _require_valid_pass_evidence(run: TestRun, suite: TestSuite, result: dict[str, Any], checkpoint: dict[str, Any] | None) -> None:
    """Reject a green verdict that lacks the minimum engine evidence contract.

    A private runner executes provider calls in the customer's network, so the
    control plane cannot pretend it independently observed those calls.  It can,
    however, bind the run oracle and reject internally inconsistent or empty
    claims before it stores an immutable runner attestation.
    """
    if result.get("run_id") != run.id:
        raise HTTPException(422, "PASS result run_id does not match the leased run")
    scenario = ScenarioDefinition.model_validate_json(suite.scenario_json)
    if result.get("source_ground_truth") != "DENIED":
        raise HTTPException(422, "PASS requires confirmed source denial")
    if float(result.get("expected_slo_seconds", -1)) != float(scenario.maximum_slo_seconds):
        raise HTTPException(422, "PASS SLO does not match the server-side suite")
    if not isinstance(checkpoint, dict) or not checkpoint.get("source_confirmed"):
        raise HTTPException(422, "PASS requires a persisted source-confirmed checkpoint")
    checkpoint_resource = checkpoint.get("resource") or {}
    if checkpoint_resource.get("canary") != run.oracle_canary:
        raise HTTPException(422, "PASS checkpoint does not match the server-issued run oracle")
    observations = result.get("observations")
    if not isinstance(observations, list) or len(observations) < scenario.stability.required_clean_observations:
        raise HTTPException(422, "PASS requires the configured number of clean observations")
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("exposed") is not False:
            raise HTTPException(422, "PASS cannot contain exposure or malformed observations")
        response_digest = observation.get("response_hash")
        if not isinstance(response_digest, str) or len(response_digest) != 64 or any(c not in "0123456789abcdef" for c in response_digest):
            raise HTTPException(422, "PASS observations require response hashes")
    derived = result.get("derived") or {}
    stable_latency = derived.get("stable_propagation_latency_seconds")
    if not isinstance(stable_latency, (int, float)) or stable_latency < 0 or stable_latency > scenario.maximum_slo_seconds:
        raise HTTPException(422, "PASS requires a stable propagation latency within the server-side SLO")
    timeline = result.get("timeline")
    states = {item.get("state") for item in timeline if isinstance(item, dict)} if isinstance(timeline, list) else set()
    if not {"VERIFYING_SOURCE_GROUND_TRUTH", "VERIFYING_STABLE_DENIAL", "PASSED"}.issubset(states):
        raise HTTPException(422, "PASS timeline is missing required verification states")


@app.post("/api/v1/runners/checkpoint")
def runner_checkpoint(
    payload: RunnerCheckpointUpdate,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    runner = _authenticate_runner(
        db, payload.runner_id, _runner_secret_from_auth(authorization, None)
    )
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == payload.run_id,
            TestRun.organization_id == runner.organization_id,
            TestRun.project_id == runner.project_id,
        )
    )
    if not run or run.lease_owner != runner.id:
        raise HTTPException(404, "Leased run not found")
    checkpoint = dict(payload.checkpoint or {})
    if checkpoint.get("run_id") not in {None, run.id}:
        raise HTTPException(422, "Checkpoint run_id mismatch")
    checkpoint["run_id"] = run.id
    resource = checkpoint.get("resource")
    if resource is not None:
        if not isinstance(resource, dict) or resource.get("canary") != run.oracle_canary:
            raise HTTPException(422, "Checkpoint resource does not match the server-issued run oracle")
    phase = str(checkpoint.get("phase") or "unknown")
    row = db.get(RunnerCheckpoint, run.id)
    if row is None:
        row = RunnerCheckpoint(
            run_id=run.id,
            organization_id=run.organization_id,
            project_id=run.project_id,
            runner_id=runner.id,
            phase=phase,
            checkpoint_json=json.dumps(checkpoint, sort_keys=True),
        )
        db.add(row)
    else:
        row.runner_id = runner.id
        row.phase = phase
        row.checkpoint_json = json.dumps(checkpoint, sort_keys=True)
        row.updated_at = datetime.now(timezone.utc)

    operation_id = checkpoint.get("mutation_operation_id")
    if operation_id:
        suite = db.get(TestSuite, run.suite_id)
        source = (
            db.get(SourceConnection, run.source_connection_id) if run.source_connection_id else None
        )
        resource = checkpoint.get("resource") or {}
        metrics = checkpoint.get("metrics") or {}
        allowed = json.loads(run.allowed_principal_json or "{}")
        mutation_type = "direct_user_revoke"
        if suite:
            try:
                mutation_type = str(json.loads(suite.scenario_json).get("mutation", mutation_type))
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        journal = db.scalar(
            select(MutationJournal)
            .where(
                MutationJournal.operation_id == str(operation_id),
                MutationJournal.organization_id == run.organization_id,
                MutationJournal.project_id == run.project_id,
                MutationJournal.run_id == run.id,
            )
            .with_for_update()
        )
        if journal is None:
            # Operation IDs are runner-provided idempotency keys. A key owned by
            # another tenant/run must never be reused to mutate its journal row.
            collision = db.scalar(
                select(MutationJournal.id).where(MutationJournal.operation_id == str(operation_id))
            )
            if collision is not None:
                raise HTTPException(409, "Mutation operation ID is already bound to another run")
            journal = MutationJournal(
                organization_id=run.organization_id,
                project_id=run.project_id,
                run_id=run.id,
                operation_id=str(operation_id),
                provider=(source.provider if source else "mock"),
                resource_id=resource.get("provider_id"),
                principal=allowed.get("email") or allowed.get("external_id"),
                mutation_type=mutation_type,
                status="requested",
                requested_at=_parse_checkpoint_dt(metrics.get("mutation_requested_at")),
                pre_state_json=json.dumps({"effective_access": "ALLOWED"}, sort_keys=True),
            )
            db.add(journal)
        journal.resource_id = resource.get("provider_id") or journal.resource_id
        journal.provider_request_id = (
            checkpoint.get("mutation_provider_request_id") or journal.provider_request_id
        )
        journal.requested_at = (
            _parse_checkpoint_dt(metrics.get("mutation_requested_at")) or journal.requested_at
        )
        if checkpoint.get("mutation_acknowledged"):
            journal.status = "acknowledged"
            journal.acknowledged_at = (
                _parse_checkpoint_dt(metrics.get("mutation_provider_acknowledged_at"))
                or journal.acknowledged_at
            )
        if checkpoint.get("source_confirmed"):
            journal.status = "confirmed"
            journal.confirmed_at = (
                _parse_checkpoint_dt(metrics.get("source_ground_truth_changed_at"))
                or journal.confirmed_at
            )
            journal.post_state_json = json.dumps({"effective_access": "DENIED"}, sort_keys=True)
        journal.updated_at = datetime.now(timezone.utc)

    run.state = "RUNNING"
    db.add(
        RunStateTransition(
            organization_id=run.organization_id,
            run_id=run.id,
            state="RUNNING",
            occurred_at=datetime.now(timezone.utc).isoformat(),
            detail=f"Runner checkpoint: {phase}",
        )
    )
    run.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=60)
    db.commit()
    return {"ok": True, "phase": phase}


@app.post("/api/v1/runners/lease")
def runner_lease(
    payload: RunnerLeaseRequest,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    runner = _authenticate_runner(
        db, payload.runner_id, _runner_secret_from_auth(authorization, None)
    )
    if not _runner_version_compatible(runner.version):
        raise HTTPException(
            409,
            f"Runner {runner.version or 'unknown'} is below minimum supported version {settings.minimum_runner_version}",
        )
    now = datetime.now(timezone.utc)
    run = db.scalar(
        select(TestRun)
        .where(
            TestRun.organization_id == runner.organization_id,
            TestRun.project_id == runner.project_id,
            TestRun.outcome.is_(None),
            or_(
                TestRun.state.in_(["CREATED", "RUNNER_DISCONNECTED"]),
                (TestRun.state.in_(["LEASED", "RUNNING"]))
                & (TestRun.lease_expires_at.is_not(None))
                & (TestRun.lease_expires_at < now),
            ),
        )
        .order_by(TestRun.created_at.asc())
        .limit(1)
    )
    if not run:
        runner_leases.labels("empty").inc()
        return {"job": None}
    run.state = "LEASED"
    run.lease_owner = runner.id
    run.lease_expires_at = now + timedelta(seconds=60)
    runner.last_job_at = now
    db.add(
        RunStateTransition(
            organization_id=run.organization_id,
            run_id=run.id,
            state="LEASED",
            occurred_at=now.isoformat(),
            detail=f"Leased to runner {runner.name}",
        )
    )
    suite = db.get(TestSuite, run.suite_id)
    source = (
        db.get(SourceConnection, run.source_connection_id) if run.source_connection_id else None
    )
    target = db.get(AITarget, run.ai_target_id) if run.ai_target_id else None
    if not suite:
        raise HTTPException(500, "Run suite missing")
    source_payload = None
    if source:
        source_payload = {
            "id": source.id,
            "provider": source.provider,
            "boundary": source.boundary,
            "credentials": json.loads(_secret_box.decrypt(source.encrypted_credentials))
            if source.encrypted_credentials
            else {},
        }
    target_payload = None
    if target:
        target_payload = {
            "id": target.id,
            "url": target.url,
            "runner_mode": target.runner_mode,
            "config": json.loads(target.config_json),
            "credentials": json.loads(_secret_box.decrypt(target.encrypted_credentials))
            if target.encrypted_credentials
            else {},
        }
    checkpoint_row = db.get(RunnerCheckpoint, run.id)
    checkpoint_payload = json.loads(checkpoint_row.checkpoint_json) if checkpoint_row else None
    def principal_for(identity_id: str | None, fallback_json: str) -> dict[str, Any]:
        principal: dict[str, Any] = json.loads(fallback_json or "{}")
        if not identity_id:
            return principal
        identity = db.get(TestIdentity, identity_id)
        if identity is None or identity.project_id != run.project_id:
            raise HTTPException(409, "Test identity is unavailable")
        principal = {"external_id": identity.subject_id, "email": identity.email}
        if identity.encrypted_credentials:
            credentials = json.loads(_secret_box.decrypt(identity.encrypted_credentials))
            token = credentials.get("access_token") or credentials.get("bearer_token")
            if isinstance(token, str) and token:
                principal["access_token"] = token
        return principal
    allowed_principal = principal_for(run.allowed_identity_id, run.allowed_principal_json)
    denied_principal = principal_for(run.denied_identity_id, run.denied_principal_json)
    db.commit()
    runner_leases.labels("leased").inc()
    return {
        "job": {
            "type": "permission_regression_v1",
            "run_id": run.id,
            "scenario": json.loads(suite.scenario_json),
            "source": source_payload,
            "target": target_payload,
            "allowed_principal": allowed_principal,
            "denied_principal": denied_principal,
            "checkpoint": checkpoint_payload,
            "oracle_canary": run.oracle_canary,
        }
    }


@app.post("/api/v1/runners/complete")
def runner_complete(
    payload: RunnerCompleteRequest,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    runner = _authenticate_runner(
        db, payload.runner_id, _runner_secret_from_auth(authorization, None)
    )
    run = db.scalar(
        select(TestRun).where(
            TestRun.id == payload.run_id,
            TestRun.organization_id == runner.organization_id,
            TestRun.project_id == runner.project_id,
        )
    )
    if not run or run.lease_owner != runner.id:
        raise HTTPException(404, "Leased run not found")
    outcome = str(payload.result.get("outcome", "ERROR"))
    if run.cancel_requested and outcome != "CANCELED":
        outcome = "CANCELED"
        payload.result["outcome"] = "CANCELED"
        payload.result["reason"] = (
            payload.result.get("reason") or "Cancellation requested by customer"
        )
    if outcome not in {"PASS", "FAIL", "INCONCLUSIVE", "ERROR", "PRECONDITION_FAILURE", "CANCELED"}:
        raise HTTPException(422, "Invalid outcome")
    suite = db.get(TestSuite, run.suite_id)
    checkpoint_row = db.get(RunnerCheckpoint, run.id)
    checkpoint = json.loads(checkpoint_row.checkpoint_json) if checkpoint_row else None
    if outcome == "PASS":
        if suite is None:
            raise HTTPException(409, "Run suite is unavailable")
        _require_valid_pass_evidence(run, suite, payload.result, checkpoint)
    # This assertion is intentionally precise: the server signs a runner
    # attestation after consistency validation, not a claim that it observed
    # the customer's private provider or target network itself.
    payload.result["server_validation"] = {
        "contract": "runner-attested-v1",
        # Only a PASS that survived the strict server evidence validation
        # above may be described as having passed. Signed FAIL, ERROR or
        # INCONCLUSIVE reports must never claim a green result.
        "passed": outcome == "PASS",
        "server_issued_oracle_bound": bool(
            checkpoint and (checkpoint.get("resource") or {}).get("canary") == run.oracle_canary
        ),
    }
    run.outcome = outcome
    run.state = {
        "PASS": "PASSED",
        "FAIL": "FAILED",
        "PRECONDITION_FAILURE": "PRECONDITION_FAILURE",
    }.get(outcome, outcome)
    run.result_json = json.dumps(payload.result, sort_keys=True)
    run.lease_expires_at = None
    db.query(EvidenceItem).filter(EvidenceItem.run_id == run.id).delete(synchronize_session=False)
    for event in payload.result.get("timeline", []):
        db.add(
            RunStateTransition(
                organization_id=run.organization_id,
                run_id=run.id,
                state=str(event.get("state")),
                occurred_at=str(event.get("at")),
                detail=str(event.get("detail", "")),
            )
        )
    for obs in payload.result.get("observations", []):
        db.add(
            EvidenceItem(
                organization_id=run.organization_id,
                run_id=run.id,
                observed_at=str(obs.get("observed_at")),
                exposed=bool(obs.get("exposed")),
                evidence_level=obs.get("evidence_level"),
                matched_signal=obs.get("matched_signal"),
                response_hash=obs.get("response_hash"),
            )
        )
    synthetic = payload.result.get("synthetic_resource")
    if synthetic:
        db.query(SyntheticResourceRecord).filter(SyntheticResourceRecord.run_id == run.id).delete(
            synchronize_session=False
        )
        canary_value = str(synthetic.get("canary", ""))
        db.add(
            SyntheticResourceRecord(
                organization_id=run.organization_id,
                run_id=run.id,
                provider_resource_id=synthetic.get("provider_id"),
                marker=synthetic.get("marker"),
                canary_hash=hash_token(canary_value) if canary_value else None,
            )
        )
        cleanup_pending = any(
            "Cleanup pending" in str(event.get("detail", ""))
            for event in payload.result.get("timeline", [])
        )
        if cleanup_pending and synthetic.get("provider_id"):
            source = (
                db.get(SourceConnection, run.source_connection_id)
                if run.source_connection_id
                else None
            )
            provider = source.provider if source else "mock"
            existing_cleanup = db.scalar(
                select(CleanupTask).where(
                    CleanupTask.run_id == run.id,
                    CleanupTask.provider_resource_id == str(synthetic.get("provider_id")),
                    CleanupTask.status.in_(["pending", "retry", "running"]),
                )
            )
            if existing_cleanup is None:
                db.add(
                    CleanupTask(
                        organization_id=run.organization_id,
                        project_id=run.project_id,
                        run_id=run.id,
                        provider=provider,
                        provider_resource_id=str(synthetic.get("provider_id")),
                        resource_json=json.dumps(synthetic, sort_keys=True),
                        status="pending",
                    )
                )
    signed_manifest = _report_signer.sign(payload.result).as_dict()
    report_hash = signed_manifest["payload_sha256"]
    existing_report = db.scalar(select(Report).where(Report.run_id == run.id))
    if existing_report:
        existing_report.report_hash = report_hash
        existing_report.signing_key_id = signed_manifest["key_id"]
        existing_report.signature = signed_manifest["signature"]
        existing_report.signing_public_key = signed_manifest["public_key"]
        existing_report.signed_manifest_json = json.dumps(signed_manifest, sort_keys=True)
        existing_report.generated_at = datetime.now(timezone.utc)
    else:
        db.add(
            Report(
                organization_id=run.organization_id,
                project_id=run.project_id,
                run_id=run.id,
                report_hash=report_hash,
                signing_key_id=signed_manifest["key_id"],
                signature=signed_manifest["signature"],
                signing_public_key=signed_manifest["public_key"],
                signed_manifest_json=json.dumps(signed_manifest, sort_keys=True),
            )
        )
    db.add(
        UsageRecord(
            organization_id=run.organization_id,
            metric="test_run",
            quantity="1",
            period=datetime.now(timezone.utc).strftime("%Y-%m"),
        )
    )
    event_type = {
        "PASS": "test_run.passed",
        "FAIL": "test_run.failed",
        "INCONCLUSIVE": "test_run.inconclusive",
        "CANCELED": "test_run.canceled",
    }.get(outcome, "test_run.completed")
    webhook_payload = {
        "id": str(uuid4()),
        "type": event_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data": {
            "run_id": run.id,
            "project_id": run.project_id,
            "outcome": outcome,
            "report_hash": report_hash,
        },
    }
    endpoints = db.scalars(
        select(WebhookEndpoint).where(
            WebhookEndpoint.organization_id == run.organization_id,
            WebhookEndpoint.enabled.is_(True),
        )
    )
    for endpoint in endpoints:
        if endpoint.project_id is None or endpoint.project_id == run.project_id:
            db.add(
                WebhookDelivery(
                    organization_id=run.organization_id,
                    endpoint_id=endpoint.id,
                    event_type=event_type,
                    payload_json=json.dumps(webhook_payload, sort_keys=True),
                )
            )
    checkpoint_row = db.get(RunnerCheckpoint, run.id)
    if checkpoint_row:
        checkpoint_row.phase = "completed"
        checkpoint_row.runner_id = runner.id
        checkpoint_row.updated_at = datetime.now(timezone.utc)
    if outcome == "FAIL":
        derived = payload.result.get("derived") or {}
        observed = derived.get("stable_propagation_latency_seconds")
        expected = payload.result.get("expected_slo_seconds")
        queue_alert(
            db,
            organization_id=run.organization_id,
            project_id=run.project_id,
            kind="slo_exceeded",
            severity="critical",
            dedupe_key=f"slo_exceeded:{run.id}",
            subject=f"{settings.product_name}: permission regression failed",
            detail=f"Run {run.id} failed. Stable denial={observed}s; required SLO={expected}s. {payload.result.get('reason', '')}",
        )
    elif outcome == "INCONCLUSIVE":
        previous = list(
            db.scalars(
                select(TestRun.outcome)
                .where(TestRun.suite_id == run.suite_id, TestRun.id != run.id)
                .order_by(TestRun.created_at.desc())
                .limit(2)
            )
        )
        if len(previous) == 2 and all(value == "INCONCLUSIVE" for value in previous):
            queue_alert(
                db,
                organization_id=run.organization_id,
                project_id=run.project_id,
                kind="repeated_inconclusive",
                severity="warning",
                dedupe_key=f"repeated_inconclusive:{run.suite_id}:{run.id}",
                subject=f"{settings.product_name}: repeated inconclusive permission tests",
                detail=f"Suite {run.suite_id} has produced at least three consecutive inconclusive runs; investigate provider, target, or runner availability.",
            )
    _audit(
        db, None, runner.organization_id, "run.completed", "test_run", run.id, {"outcome": outcome}
    )
    db.commit()
    source = (
        db.get(SourceConnection, run.source_connection_id) if run.source_connection_id else None
    )
    provider = source.provider if source else "mock"
    run_outcomes.labels(outcome, provider).inc()
    derived_metrics = payload.result.get("derived") or {}
    stable_seconds = derived_metrics.get("stable_propagation_latency_seconds")
    exposure_seconds = derived_metrics.get("exposure_window_seconds")
    if isinstance(stable_seconds, (int, float)) and stable_seconds >= 0:
        propagation_latency.labels(provider).observe(float(stable_seconds))
    if isinstance(exposure_seconds, (int, float)) and exposure_seconds >= 0:
        exposure_window.labels(provider).observe(float(exposure_seconds))
    return {"ok": True, "run_id": run.id, "outcome": outcome, "report_hash": report_hash}
