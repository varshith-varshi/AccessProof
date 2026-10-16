from __future__ import annotations
from collections.abc import AsyncIterator, Awaitable, Callable
from packages.connector_sdk.base import SourceAdapter

from typing import Any

import json
from dataclasses import asdict
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from threading import Lock
from uuid import uuid4
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
from apps.api.accessproof_api.config import settings, validate_production_settings
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
    ScimConfiguration,
    ScimIdentity,
    ScimGroup,
    ScimGroupMember,
    Organization,
    Project,
    Release,
    Report,
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
    WebhookDelivery,
    WebhookEndpoint,
    Session as DbSession,
    SourceConnection,
    TestIdentity,
    TestRun,
    TestSuite,
    User,
    set_tenant_context,
)
from apps.api.accessproof_api.schemas import (
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
    GuardAuditBatch as GuardAuditBatch,
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
from packages.crypto.totp import generate_totp_secret, provisioning_uri, verify_totp
from packages.crypto.secrets import build_secret_backend, hash_token
from packages.crypto.signing import Ed25519Signer, verify_manifest
from packages.auth.oidc import OidcDiscovery, OidcError, OidcProviderClient
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
    logger,
)
from apps.api.accessproof_api.retention import apply_retention, get_or_create_policy
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
_auth_attempts: dict[str, list[float]] = {}
_auth_attempts_lock = Lock()


def _limit_auth_request(request: Request, action: str, limit: int, window_seconds: int, discriminator: str = "") -> None:
    """Bound low-cost authentication abuse without persisting email addresses."""
    # Local test/dev accounts are intentionally ephemeral. Production retains
    # the full limiter; disabling it here prevents one reused fixture account
    # from contaminating unrelated deterministic tests.
    if settings.env != "production":
        return
    client = request.client.host if request.client else "unknown"
    # Keep the network-wide bound while separating independent accounts. The
    # discriminator is a one-way normalized value and is never logged/stored.
    digest = hashlib.sha256(discriminator.strip().lower().encode()).hexdigest()[:16] if discriminator else ""
    key = f"{action}:{client}:{digest}"
    now = time.monotonic()
    with _auth_attempts_lock:
        recent = [item for item in _auth_attempts.get(key, []) if item > now - window_seconds]
        if len(recent) >= limit:
            raise HTTPException(429, "Too many requests. Please try again shortly.")
        recent.append(now)
        _auth_attempts[key] = recent


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
            f"{settings.public_app_url.rstrip('/')}/verify-email?token={raw}\n\n"
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


@app.get("/metrics")
def metrics(db: OrmSession = Depends(get_db)) -> Response:
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
def guard_permission_event(payload: GuardEventCreate, actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)) -> dict[str, Any]:
    """Queue one normalized provider event; resolution happens in the worker."""
    organization_id = actor.membership.organization_id
    set_tenant_context(db, organization_id)
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
def guard_permission_events(actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)) -> list[dict[str, Any]]:
    organization_id = actor.membership.organization_id
    set_tenant_context(db, organization_id)
    rows = db.scalars(select(GuardPermissionEvent).where(GuardPermissionEvent.organization_id == organization_id).order_by(GuardPermissionEvent.received_at.desc()).limit(100)).all()
    return [{"id": r.id, "source_id": r.source_id, "provider": r.provider, "subject_id": r.subject_id, "resource_id": r.resource_id, "change_type": r.change_type, "provider_revision": r.provider_revision, "status": r.processing_status, "dedupe_key": r.dedupe_key, "error_code": r.error_code, "policy_id": r.policy_id} for r in rows]


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
    ))
    if enrollment is None or enrollment.used_at or enrollment.revoked_at:
        raise HTTPException(401, "Invalid enrollment token")
    expires_at = enrollment.expires_at if enrollment.expires_at.tzinfo else enrollment.expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(401, "Expired enrollment token")
    guard = db.get(GuardRegistration, enrollment.guard_id)
    if guard is None or guard.organization_id != enrollment.organization_id or guard.revoked_at:
        raise HTTPException(401, "Invalid enrollment token")
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
    guard.last_heartbeat_at = datetime.now(timezone.utc)
    guard.last_policy_sync_at = guard.last_heartbeat_at
    guard.version = payload.version
    guard.active_policy_version = payload.active_policy_version
    guard.health = "degraded" if payload.degraded_conditions else payload.cache_status
    db.commit()
    return {"ok": True}


@app.get("/api/v1/guards/{guard_id}/policies")
def guard_policies(
    guard_id: str,
    after_version: int = 0,
    full_snapshot: bool = False,
    authorization: str | None = Header(default=None),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Machine-only policy synchronization; no human credential is accepted."""
    guard = _authenticate_guard(db, guard_id, authorization)
    latest = int(db.scalar(select(func.max(GuardPolicy.version)).where(
        GuardPolicy.organization_id == guard.organization_id
    )) or 0)
    if full_snapshot:
        states = db.scalars(select(GuardEffectiveAccess).where(
            GuardEffectiveAccess.organization_id == guard.organization_id
        )).all()
        return {"kind": "full", "version": latest, "decisions": [
            {"subject_id": _guard_subject_identifier(db, guard.organization_id, row.subject_id), "source_id": row.source_id, "resource_id": _guard_resource_identifier(db, guard.organization_id, row.resource_id),
             "scope": row.scope, "decision": row.decision, "reason": row.reason}
            for row in states
        ]}
    rows = db.scalars(select(GuardPolicy).where(
        GuardPolicy.organization_id == guard.organization_id,
        GuardPolicy.version > after_version,
    ).order_by(GuardPolicy.version.asc())).all()
    return {"kind": "incremental", "version": latest, "policies": [
        {"version": row.version, "subject_id": _guard_subject_identifier(db, guard.organization_id, row.subject_id), "source_id": row.source_id,
         "resource_id": _guard_resource_identifier(db, guard.organization_id, row.resource_id), "scope": row.scope, "decision": row.decision,
         "reason": row.reason}
        for row in rows
    ]}


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
    accepted = 0
    for item in payload.events:
        # The unique constraint is the authority here.  The nested savepoint
        # makes concurrent replays harmless without discarding other items in
        # the same batch.
        try:
            with db.begin_nested():
                db.add(GuardAuditEvent(
                    organization_id=guard.organization_id,
                    guard_id=guard.id,
                    event_id=item.event_id,
                    application_id=item.application_id,
                    subject_id=item.subject_id,
                    request_id=item.request_id,
                    result=item.result,
                    reason=item.reason,
                    policy_version=item.policy_version,
                ))
                db.flush()
        except IntegrityError:
            continue
        accepted += 1
    db.commit()
    return {"accepted": accepted}


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
        raise HTTPException(403, "Please verify your email before signing in.")
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
        select(MfaMethod).where(MfaMethod.user_id == user.id, MfaMethod.enabled.is_(True))
    )
    if mfa:
        if not payload.totp_code:
            raise HTTPException(401, detail={"code": "mfa_required"})
        secret = _secret_box.decrypt(mfa.encrypted_secret)
        valid = verify_totp(secret, payload.totp_code)
        if not valid:
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
    state_row = db.scalar(
        select(OidcLoginState).where(OidcLoginState.state_hash == hash_token(payload.state))
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
    if claims.get("email_verified") is False:
        raise HTTPException(403, "OIDC provider reports an unverified email")
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
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(48)),
                email_verified=True,
            )
            db.add(user)
            db.flush()
        if identity is None:
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
    user.email_verified = True
    state_row.used_at = now
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
        select(OneTimeToken).where(
            OneTimeToken.token_hash == hash_token(payload.token),
            OneTimeToken.purpose == "password_reset",
        )
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
    actor.user.password_hash = hash_password(payload.new_password)
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
    row = db.scalar(select(MfaMethod).where(MfaMethod.user_id == actor.user.id))
    if not row:
        raise HTTPException(409, "Run MFA setup first")
    if not verify_totp(_secret_box.decrypt(row.encrypted_secret), payload.code):
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
        select(MfaMethod).where(MfaMethod.user_id == actor.user.id, MfaMethod.enabled.is_(True))
    )
    if not row:
        return {"enabled": False}
    secret = _secret_box.decrypt(row.encrypted_secret)
    valid = verify_totp(secret, payload.code)
    if not valid:
        hashes = json.loads(row.recovery_hashes_json)
        candidate = hash_token(payload.code)
        valid = candidate in hashes
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
    blocked_count = int(db.scalar(select(func.count(GuardProtectionDecision.id)).where(
        GuardProtectionDecision.organization_id == org_id,
        GuardProtectionDecision.result.in_(["block", "would_block"]),
    )) or 0)
    application_count = int(db.scalar(select(func.count(func.distinct(GuardProtectionDecision.application_id))).where(
        GuardProtectionDecision.organization_id == org_id
    )) or 0)

    activity: list[dict[str, Any]] = []
    for event in db.scalars(select(AuditEvent).where(
        AuditEvent.organization_id == org_id,
        AuditEvent.action.in_(_CURRENT_ACTIVITY_ACTIONS),
    ).order_by(AuditEvent.created_at.desc()).limit(50)):
        event_type, severity, summary = _CURRENT_ACTIVITY_ACTIONS[event.action]
        metadata = json.loads(event.metadata_json or "{}")
        activity.append({
            "id": event.id, "type": event_type, "severity": severity,
            "timestamp": event.created_at.isoformat(), "summary": summary,
            "guard_id": metadata.get("guard_id") if isinstance(metadata, dict) else None,
            "policy_version": metadata.get("version") if isinstance(metadata, dict) else None,
        })
    for event in db.scalars(select(GuardAuditEvent).where(
        GuardAuditEvent.organization_id == org_id,
        GuardAuditEvent.result.in_(["block", "would_block"]),
    ).order_by(GuardAuditEvent.created_at.desc()).limit(50)):
        activity.append({
            "id": event.id, "type": "LAYER2_BLOCK" if "PROVENANCE" in event.reason else "LAYER1_BLOCK",
            "severity": "warning", "timestamp": event.created_at.isoformat(),
            "summary": "Guard blocked an AI request", "guard_id": event.guard_id,
            "application_id": event.application_id, "policy_version": event.policy_version,
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
    return {
        "ai_applications": application_count,
        "guards_online": guards_online,
        "guards_total": len(guards),
        "permission_sources": source_count,
        "blocked_requests": blocked_count,
        "recent_activity": activity[:25],
    }


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


@app.post("/api/v1/sources", status_code=201)
def create_source(
    payload: SourceCreate,
    actor: Actor = Depends(require(Permission.SOURCE_WRITE)),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
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
    row = SourceConnection(
        organization_id=project.organization_id,
        project_id=project.id,
        provider=payload.provider,
        name=payload.name,
        boundary=payload.boundary,
        mutation_acknowledged=payload.mutation_acknowledged,
        encrypted_credentials=_secret_box.encrypt(json.dumps(payload.credentials))
        if payload.credentials
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


@app.get("/api/v1/current/sources")
def list_current_sources(
    actor: Actor = Depends(current_actor), db: OrmSession = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(select(SourceConnection).where(
        SourceConnection.organization_id == actor.membership.organization_id
    ).order_by(SourceConnection.name.asc(), SourceConnection.id.asc())).all()
    return [_source_payload(row) for row in rows]


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
    try:
        credentials = json.loads(_secret_box.decrypt(row.encrypted_credentials)) if row.encrypted_credentials else {}
        result = await synchronize_directory(db, row, credentials)
    except DirectorySyncError as exc:
        row.status = "degraded"
        row.last_error = exc.code
        _audit(db, actor, row.organization_id, "directory.sync_degraded", "source", row.id, {"code": exc.code})
        db.commit()
        raise HTTPException(424, f"Directory synchronization failed: {exc.code}") from exc
    except Exception as exc:
        row.status = "degraded"
        row.last_error = "DIRECTORY_SYNC_INCOMPLETE"
        _audit(db, actor, row.organization_id, "directory.sync_degraded", "source", row.id, {"code": row.last_error})
        db.commit()
        logger.warning("directory_sync_failed source_id=%s error=%s", row.id, type(exc).__name__)
        raise HTTPException(502, "Directory synchronization could not complete") from exc
    row.status = "connected"
    row.last_error = None
    row.last_validated_at = datetime.now(timezone.utc)
    _audit(db, actor, row.organization_id, "directory.sync_completed", "source", row.id, result)
    db.commit()
    return {"source": _source_payload(row), "synchronized": result}


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
        row.status = "connected"
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
    row.encrypted_credentials = (
        _secret_box.encrypt(json.dumps(payload.credentials, sort_keys=True))
        if payload.credentials
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
    # Validate the replacement before changing the encrypted record. A failed
    # reauthorization therefore preserves the known working credential.
    try:
        candidate = create_source_adapter(row.provider, payload.credentials)
        identity = await candidate.validate_connection()
        capabilities = await candidate.discover_capabilities()
    except Exception as exc:
        raise HTTPException(422, f"Replacement credential validation failed: {type(exc).__name__}") from exc
    finally:
        http_client = getattr(locals().get("candidate"), "_client", None) or getattr(locals().get("candidate"), "client", None)
        if http_client is not None:
            await http_client.aclose()
    row.encrypted_credentials = _secret_box.encrypt(json.dumps(payload.credentials, sort_keys=True))
    row.status = "connected"
    row.last_validated_at = datetime.now(timezone.utc)
    row.last_capability_refresh_at = row.last_validated_at
    row.capabilities_json = json.dumps({key.value: value.value for key, value in capabilities.capabilities.items()}, sort_keys=True)
    row.provider_identity_json = json.dumps({"provider": identity.provider, "tenant": identity.tenant, "account": identity.account, "boundary": identity.boundary, "metadata": identity.metadata}, sort_keys=True)
    row.granted_scopes_json = json.dumps(_configured_scopes(payload.credentials), sort_keys=True)
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
        if candidate is None:
            continue
        scenario = ScenarioDefinition.model_validate_json(suite.scenario_json)
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
        "verified": verified,
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
        )
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
            select(MutationJournal).where(MutationJournal.operation_id == str(operation_id))
        )
        if journal is None:
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
