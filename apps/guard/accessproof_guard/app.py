from __future__ import annotations

import os
import asyncio
import json
import stat
import httpx
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4
from collections import defaultdict
from contextlib import asynccontextmanager, suppress
from typing import Any, AsyncIterator, TypedDict

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .cache import AuditBufferFull, PolicyCache
from .multisource import MultiSourceGuard, principal_key
from .identity import IdentityError, OidcVerifier
from .onboarding import EnrollmentError, enroll_guard, public_status, setup_page
from .sync import GuardMachineCredentials, GuardSyncClient

cache = PolicyCache(os.getenv("ACCESSPROOF_GUARD_CACHE", "/var/lib/accessproof-guard/policy.db"))
issuer = os.getenv("ACCESSPROOF_GUARD_JWT_ISSUER")
audience = os.getenv("ACCESSPROOF_GUARD_JWT_AUDIENCE")
verification_key = os.getenv("ACCESSPROOF_GUARD_JWT_VERIFICATION_KEY")
identity_mode = os.getenv("ACCESSPROOF_GUARD_IDENTITY_MODE", "oidc" if not verification_key else "static").lower()
expected_tenant = os.getenv("ACCESSPROOF_GUARD_IDENTITY_TENANT_ID")
subject_claim = os.getenv("ACCESSPROOF_GUARD_IDENTITY_SUBJECT_CLAIM", "sub")
identity_cache_seconds = max(30.0, float(os.getenv("ACCESSPROOF_GUARD_IDENTITY_CACHE_SECONDS", "300")))
# Optional: require a user-delegated access token with this scope (e.g.
# "access_as_user"); rejects ID tokens and app-only tokens.
required_scope = os.getenv("ACCESSPROOF_GUARD_REQUIRED_SCOPE", "").strip() or None
mode = os.getenv("ACCESSPROOF_GUARD_MODE", "protect").lower()
fail_mode = os.getenv("ACCESSPROOF_GUARD_FAIL_MODE", "fail_closed").lower()
max_policy_age_seconds = max(10.0, float(os.getenv("ACCESSPROOF_GUARD_MAX_POLICY_AGE_SECONDS", "120")))
_credential_path = Path(os.getenv("ACCESSPROOF_GUARD_CREDENTIAL_FILE", "/var/lib/accessproof-guard/credentials.json"))
max_request_bytes = max(1_024, int(os.getenv("ACCESSPROOF_GUARD_MAX_REQUEST_BYTES", "1048576")))


def _load_machine_settings() -> dict[str, str]:
    """Load a mode-0600 local enrollment record without logging its contents."""
    # Read the actual opened file rather than following a link or checking
    # permissions before opening (which would introduce a TOCTOU gap).
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_credential_path, flags)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RuntimeError("Guard credential file must be a regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Guard credential file must be a regular file")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("Guard credential file has unsafe permissions; use chmod 600")
        with os.fdopen(descriptor, "r", encoding="utf-8") as file:
            descriptor = -1
            try:
                payload = json.load(file)
            except (OSError, json.JSONDecodeError):
                return {}
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        return {}
    allowed = {
        "control_plane_url", "guard_id", "credential", "identity_mode",
        "issuer", "audience", "subject_claim", "tenant_id",
    }
    return {key: str(value) for key, value in payload.items() if key in allowed}


def _effective_machine_settings() -> dict[str, str]:
    """Resolve a coherent enrollment record.

    A complete file-based enrollment wins as a unit. This prevents image or
    Compose defaults from mixing a local URL with a production machine
    credential. Environment-only configuration remains supported for managed
    deployments that inject all three values.
    """
    saved = _load_machine_settings()
    if all(saved.get(key) for key in ("control_plane_url", "guard_id", "credential")):
        return saved
    return {
        "control_plane_url": os.getenv("ACCESSPROOF_GUARD_CONTROL_PLANE_URL", ""),
        "guard_id": os.getenv("ACCESSPROOF_GUARD_ID", ""),
        "credential": os.getenv("ACCESSPROOF_GUARD_CREDENTIAL", ""),
    }


_machine_settings = _effective_machine_settings()
control_plane_url = _machine_settings.get("control_plane_url")
guard_id = _machine_settings.get("guard_id")
guard_credential = _machine_settings.get("credential")


def _resolve_identity_settings(env: Any, saved: dict[str, str]) -> dict[str, str | None]:
    """One precedence rule for every employee-identity setting (D-16).

    An explicitly set environment value wins, then the enrollment record, then
    the default. Previously issuer/audience/tenant followed that rule but
    subject_claim and identity_mode let the enrollment file override the
    environment, so an operator configuring the immutable Entra ``oid`` claim
    silently kept the pairwise ``sub`` claim.
    """
    def pick(env_key: str, saved_key: str, default: str | None = None) -> str | None:
        value = env.get(env_key)
        if value:
            return value
        value = saved.get(saved_key)
        return value if value else default

    has_static_key = bool(env.get("ACCESSPROOF_GUARD_JWT_VERIFICATION_KEY"))
    resolved_mode = pick("ACCESSPROOF_GUARD_IDENTITY_MODE", "identity_mode",
                         "static" if has_static_key else "oidc")
    return {
        "issuer": pick("ACCESSPROOF_GUARD_JWT_ISSUER", "issuer"),
        "audience": pick("ACCESSPROOF_GUARD_JWT_AUDIENCE", "audience"),
        "tenant_id": pick("ACCESSPROOF_GUARD_IDENTITY_TENANT_ID", "tenant_id"),
        "subject_claim": pick("ACCESSPROOF_GUARD_IDENTITY_SUBJECT_CLAIM", "subject_claim", "sub"),
        "identity_mode": (resolved_mode or "oidc").lower(),
    }


_identity_settings = _resolve_identity_settings(os.environ, _machine_settings)
issuer = _identity_settings["issuer"]
audience = _identity_settings["audience"]
identity_mode = str(_identity_settings["identity_mode"])
expected_tenant = _identity_settings["tenant_id"]
subject_claim = str(_identity_settings["subject_claim"])
guard_version = os.getenv("ACCESSPROOF_GUARD_VERSION", "0.1.0")
# Security presence is deliberately independent from the policy/audit loop.
# A one-second target is not a hard real-time guarantee over unreliable networks.
sync_interval_seconds = max(2.0, float(os.getenv("ACCESSPROOF_GUARD_SYNC_SECONDS", "10")))
presence_interval_seconds = max(1.0, float(os.getenv("ACCESSPROOF_GUARD_PRESENCE_SECONDS", "1")))
_sync_error: str | None = None
_oidc_verifier: OidcVerifier | None = None


def _oidc() -> OidcVerifier:
    global _oidc_verifier
    if not issuer or not audience:
        raise HTTPException(503, "IDENTITY_PROVIDER_UNAVAILABLE")
    if _oidc_verifier is None:
        _oidc_verifier = OidcVerifier(
            issuer=issuer,
            audience=audience,
            subject_claim=subject_claim,
            tenant_id=expected_tenant,
            cache_seconds=identity_cache_seconds,
            required_scope=required_scope,
        )
    return _oidc_verifier


async def _sync_loop() -> None:
    """Keep the local policy cache current without putting the data plane at risk."""
    global _sync_error, control_plane_url, guard_id, guard_credential
    client: GuardSyncClient | None = None
    active_identity: tuple[str, str, str] | None = None
    try:
        while True:
            settings = _effective_machine_settings()
            current = (
                settings.get("control_plane_url", ""),
                settings.get("guard_id", ""),
                settings.get("credential", ""),
            )
            if not all(current):
                _sync_error = "CONTROL_PLANE_NOT_CONFIGURED"
                await asyncio.sleep(sync_interval_seconds)
                continue
            if current != active_identity:
                if client is not None:
                    client.close()
                control_plane_url, guard_id, guard_credential = current
                client = GuardSyncClient(
                    cache,
                    GuardMachineCredentials(
                        control_plane_url=control_plane_url,
                        guard_id=guard_id,
                        credential=guard_credential,
                        version=guard_version,
                    ),
                )
                active_identity = current
            try:
                assert client is not None
                await asyncio.to_thread(client.sync_once)
                audit_error: str | None = None
                try:
                    await asyncio.to_thread(client.upload_audit)
                except Exception as exc:
                    # Audit delivery is retried from the durable local buffer;
                    # it must not suppress liveness and policy health reports.
                    audit_error = f"AUDIT_UPLOAD_{type(exc).__name__}"
                _sync_error = audit_error
            except Exception as exc:
                # Do not log credentials or request bodies.  The data plane
                # continues enforcing its last known durable policy.
                _sync_error = type(exc).__name__
            # Long polling is an outbound wake-up channel. It shortens normal
            # propagation without making policy content or authorization depend
            # on a notification; sync_once remains the authoritative fetch.
            # The long-poll is held open for the whole sync window (was 1 s plus a
            # 10 s sleep, which delayed revocations by up to ~10 s). Returning
            # without a change is the periodic sync tick; only an error backs off.
            try:
                if client:
                    await asyncio.to_thread(client.wait_for_policy_update,
                                            wait_seconds=int(min(25, max(1, sync_interval_seconds))))
            except Exception:
                await asyncio.sleep(sync_interval_seconds)
    finally:
        if client is not None:
            client.close()


async def _presence_loop() -> None:
    """Independent machine-authenticated Guard presence; never claims Protect.

    The 1s target remains best effort. Failed/late requests are reported by
    control-plane receipt timestamps, not by self-declared client uptime.
    """
    client: GuardSyncClient | None = None
    presence_transport: httpx.Client | None = None
    active_identity: tuple[str, str, str] | None = None
    try:
        while True:
            started = asyncio.get_running_loop().time()
            settings = _effective_machine_settings()
            current = (settings.get("control_plane_url", ""), settings.get("guard_id", ""), settings.get("credential", ""))
            if not all(current):
                if presence_transport is not None:
                    presence_transport.close()
                    presence_transport = None
                client = None
                active_identity = None
            else:
                if current != active_identity:
                    if presence_transport is not None:
                        presence_transport.close()
                    # Own the dedicated transport across heartbeats and close
                    # it when credentials rotate or this task is cancelled.
                    presence_transport = httpx.Client(
                        timeout=1.5, follow_redirects=False, trust_env=False
                    )
                    client = GuardSyncClient(
                        cache,
                        GuardMachineCredentials(
                            control_plane_url=current[0], guard_id=current[1],
                            credential=current[2], version=guard_version,
                        ),
                        presence_transport,
                    )
                    active_identity = current
                try:
                    conditions = []
                    if identity_mode != "oidc" or not issuer or not audience:
                        conditions.append("OIDC_IDENTITY_NOT_CONFIGURED")
                    if _sync_error:
                        conditions.append("POLICY_SYNC_OR_AUDIT_DEGRADED")
                    assert client is not None
                    await asyncio.to_thread(client.heartbeat, degraded_conditions=conditions)
                except Exception:
                    # Missing receipts cause control plane OFFLINE after TTL.
                    # Never convert a rejected heartbeat into an online claim.
                    pass
            elapsed = asyncio.get_running_loop().time() - started
            await asyncio.sleep(max(0.0, presence_interval_seconds - elapsed))
    finally:
        if presence_transport is not None:
            presence_transport.close()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    sync_task = asyncio.create_task(_sync_loop())
    presence_task = asyncio.create_task(_presence_loop())
    try:
        yield
    finally:
        sync_task.cancel()
        presence_task.cancel()
        for task in (sync_task, presence_task):
            with suppress(asyncio.CancelledError):
                await task
        if _oidc_verifier is not None:
            _oidc_verifier.close()


app = FastAPI(title="AccessProof Guard", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.middleware("http")
async def limit_request_bytes(request: Request, call_next: Any) -> Any:
    declared = request.headers.get("content-length")
    if declared and (not declared.isdigit() or int(declared) > max_request_bytes):
        return JSONResponse(status_code=413, content={"detail": "REQUEST_TOO_LARGE"})
    size = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_request_bytes:
            return JSONResponse(status_code=413, content={"detail": "REQUEST_TOO_LARGE"})
        chunks.append(chunk)
    request._body = b"".join(chunks)
    return await call_next(request)


@app.exception_handler(AuditBufferFull)
async def audit_buffer_full(_: Request, __: AuditBufferFull) -> JSONResponse:
    """Do not return an allowed decision when security evidence cannot be retained."""
    return JSONResponse(status_code=503, content={"detail": "AUDIT_BUFFER_FULL"})


class SetupEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str = Field(min_length=1, max_length=2048)
    token: str = Field(min_length=1, max_length=4096)
    issuer: str | None = Field(default=None, max_length=2048)
    audience: str | None = Field(default=None, max_length=512)
    subject_claim: str = Field(default="sub", min_length=1, max_length=128)
    tenant_id: str | None = Field(default=None, max_length=255)


def _require_local_setup(request: Request) -> None:
    """Require a real loopback transport peer, not a caller-controlled Host."""
    hostname = request.url.hostname
    peer = request.client.host if request.client is not None else ""
    try:
        is_loopback_peer = ip_address(peer).is_loopback
    except ValueError:
        is_loopback_peer = False
    if hostname not in {"localhost", "127.0.0.1", "::1"} or not is_loopback_peer:
        raise HTTPException(403, "SETUP_REQUIRES_LOCALHOST")


@app.get("/setup", response_class=HTMLResponse)
def setup(request: Request) -> str:
    _require_local_setup(request)
    return setup_page()


@app.get("/setup/status")
def setup_status(request: Request) -> dict[str, Any]:
    _require_local_setup(request)
    return public_status(_effective_machine_settings(), _sync_error)


@app.post("/setup/enroll")
def setup_enroll(payload: SetupEnrollmentRequest, request: Request) -> dict[str, Any]:
    """Enroll from the loopback UI without exposing the machine credential."""
    global control_plane_url, guard_id, guard_credential
    global issuer, audience, subject_claim, expected_tenant, identity_mode, _oidc_verifier
    _require_local_setup(request)
    existing = _effective_machine_settings()
    if existing.get("guard_id") and existing.get("credential"):
        raise HTTPException(409, "GUARD_ALREADY_ENROLLED")
    try:
        settings = enroll_guard(
            server=payload.server,
            token=payload.token,
            version=guard_version,
            state_dir=_credential_path.parent,
            issuer=payload.issuer,
            audience=payload.audience,
            subject_claim=payload.subject_claim,
            tenant_id=payload.tenant_id,
        )
    except EnrollmentError as exc:
        raise HTTPException(400, str(exc)) from exc
    control_plane_url = settings["control_plane_url"]
    guard_id = settings["guard_id"]
    guard_credential = settings["credential"]
    issuer = settings.get("issuer")
    audience = settings.get("audience")
    subject_claim = settings.get("subject_claim", "sub")
    expected_tenant = settings.get("tenant_id")
    identity_mode = settings.get("identity_mode", "oidc")
    if _oidc_verifier is not None:
        _oidc_verifier.close()
    _oidc_verifier = None
    return public_status(settings, "SYNC_STARTING")


class Resource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(max_length=255)
    resource_id: str = Field(max_length=1024)
    scope: str = Field(default="read", max_length=64)
    chunk_ids: list[str] = Field(default_factory=list, max_length=128)
    content_version: str | None = Field(default=None, max_length=1024)


class FilterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(max_length=255)
    request_id: str = Field(max_length=255)
    # A single employee request must not create unbounded SQLite contexts,
    # ACL evaluations, and audit-buffer allocations.
    resources: list[Resource] = Field(max_length=5000)


class AuthorizationScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(max_length=255)
    request_id: str = Field(max_length=255)




class ResourceDecision(TypedDict):
    source_id: str
    resource_id: str
    chunk_ids: list[str]
    reason: str


class OutputRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(max_length=255)
    application_id: str = Field(max_length=255)
    request_id: str = Field(max_length=255)
    used_resource_ids: list[str] = Field(default_factory=list, max_length=5000)
    provenance: list["ProvenanceItem"] = Field(default_factory=list, max_length=5000)
    # Extra sources must have passed their own Layer 1 check for this same request.
    additional_decision_ids: list[str] = Field(default_factory=list, max_length=16)


class ProvenanceItem(BaseModel):
    """A derived result with the stable source resources that produced it."""
    model_config = ConfigDict(extra="forbid")
    derived_id: str | None = Field(default=None, max_length=255)
    derived_type: str = Field(default="retrieval", max_length=64)
    source_resource_ids: list[str] = Field(default_factory=list, max_length=500)


def _production() -> bool:
    return os.getenv("ACCESSPROOF_ENV", "").lower() == "production"


def _identity_ready() -> bool:
    """Whether this Guard can authenticate employees in its environment."""
    if subject_claim not in {"sub", "oid"}:
        return False
    if identity_mode == "oidc":
        return bool(issuer and audience)
    return (identity_mode == "static" and not _production() and bool(issuer and audience)
            and len((verification_key or "").encode("utf-8")) >= 32)


def _identity(authorization: str | None) -> tuple[str, str, str | None]:
    # Applies to static development tokens as well as production OIDC.
    # Never key ACLs on reassigned emails or other mutable identity fields.
    if subject_claim not in {"sub", "oid"}:
        raise HTTPException(503, "IDENTITY_SUBJECT_CLAIM_UNSAFE")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "IDENTITY_TOKEN_INVALID")
    if identity_mode == "oidc":
        try:
            verified = _oidc().verify(token)
            return verified.subject, verified.issuer, verified.tenant_id
        except IdentityError as exc:
            status = 503 if exc.args[0] in {"IDENTITY_KEY_UNAVAILABLE", "IDENTITY_PROVIDER_UNAVAILABLE"} else 401
            raise HTTPException(status, exc.args[0]) from exc
    if identity_mode != "static" or not issuer or not audience or not verification_key:
        raise HTTPException(503, "IDENTITY_PROVIDER_UNAVAILABLE")
    if _production():
        # D-03: whoever holds a shared HS256 secret (typically the customer
        # RAG itself) can mint ANY employee identity. A production Guard
        # only accepts asymmetric, issuer-published OIDC signatures.
        raise HTTPException(503, "IDENTITY_STATIC_MODE_FORBIDDEN_IN_PRODUCTION")
    # Static HS256 credentials are a development / explicitly managed
    # integration option.  A short shared secret makes an otherwise strict
    # signature check susceptible to offline guessing, so fail closed instead
    # of treating a weak deployment configuration as authenticated identity.
    if len(verification_key.encode("utf-8")) < 32:
        raise HTTPException(503, "IDENTITY_STATIC_KEY_UNSAFE")
    try:
        claims = jwt.decode(token, verification_key, algorithms=["HS256"], issuer=issuer, audience=audience, options={"require": ["exp", "sub", "iss", "aud"]})
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "IDENTITY_TOKEN_INVALID") from exc
    if expected_tenant and claims.get("tid") != expected_tenant:
        raise HTTPException(401, "IDENTITY_TENANT_MISMATCH")
    stable_subject = claims.get(subject_claim)
    if not isinstance(stable_subject, str) or not stable_subject:
        raise HTTPException(401, "IDENTITY_SUBJECT_UNKNOWN")
    return stable_subject, issuer, str(claims.get("tid")) if claims.get("tid") else None


def _mapped_subject(authorization: str | None, source_id: str | None) -> str:
    """Resolve the authenticated enterprise identity to source ACL identity.

    Source authorization is never keyed directly by a user-supplied email or
    JWT claim. A missing mapping fails closed for every resource.
    """
    subject, token_issuer, tenant_id = _identity(authorization)
    if source_id is None:
        return subject  # standalone test compatibility; no synced app boundary
    # Pre-mapping installations retain their existing source-subject contract
    # until an authenticated control-plane response explicitly supplies the
    # mapping envelope. Once received (even empty), missing maps always deny.
    # This makes the rollout backward compatible without allowing an operator
    # to bypass a configured mapping boundary.
    if not cache.identity_mappings_received():
        # A signed OIDC token proves a principal at its issuer, not the
        # separate enterprise source identity. Old unauthenticated local test
        # fixtures may use static subjects, but a production or OIDC Guard
        # MUST NOT bypass a missing verified mapping snapshot.
        if identity_mode == "oidc" or guard_id or guard_credential:
            raise HTTPException(503, "IDENTITY_MAPPINGS_NOT_SYNCED")
        return subject
    mapped = cache.resolve_identity(source_id, token_issuer, subject, tenant_id)
    if mapped is None:
        raise HTTPException(403, "IDENTITY_MAPPING_UNRESOLVED")
    return mapped


@app.get("/health")
def health(application_id: str | None = None) -> dict[str, object]:
    # Gateway readiness is always scoped to one configured application.
    # A globally healthy Guard may still be missing this application's
    # binding, be in Shadow, or lack fresh Google source authorization.
    configured = bool(control_plane_url and guard_id and guard_credential)
    sync_age = cache.sync_age_seconds()
    fresh = sync_age is not None and sync_age <= max_policy_age_seconds
    source_healthy = cache.all_protect_sources_healthy()
    audit_buffer_ready = cache.audit_has_capacity()
    # A synchronized policy version alone is not customer readiness: a Guard
    # with zero bound applications cannot protect any customer RAG traffic.
    bindings_ready = (
        not configured
        or (cache.application_bindings_received() and bool(cache.application_modes()))
    )
    revisions_ready = (
        not cache.authorization_revisions_received()
        or cache.all_protect_revisions_present()
    )
    identity_ready = _identity_ready()
    ready = (
        cache.version() > 0 and source_healthy and audit_buffer_ready and bindings_ready
        and revisions_ready and (not configured or fresh) and identity_ready
    )
    if application_id is not None:
        binding = cache.application_binding(application_id) if cache.application_bindings_received() else None
        production = os.getenv("ACCESSPROOF_ENV", "").lower() == "production"
        app_ready = bool(
            binding is not None and binding[1] == "protect"
            and cache.source_acl_healthy(application_id)
            and (not production or (
                cache.identity_mappings_received() and
                cache.authorization_revisions_received()
            ))
            and (not cache.authorization_revisions_received()
                 or cache.authorization_revision(application_id) is not None)
        )
        ready = ready and app_ready
    return {
        "status": "ok" if ready and _sync_error is None else "degraded",
        "policy_version": cache.version(),
        "authorization_revisions_ready": revisions_ready,
        "ready": ready,
        "policy_fresh": fresh if configured else None,
        "audit_buffer_ready": audit_buffer_ready,
        "identity_ready": identity_ready,
        "certification_window": (cache.certification_window(application_id) if application_id is not None
                                 else any(cache.certification_window(a) for a in cache.application_modes())),
        "control_plane_configured": configured,
        "sync_error": _sync_error,
    }


def _application_mode(application_id: str) -> tuple[str, str | None]:
    """Resolve the current app-specific mode and source from trusted sync."""
    if cache.application_bindings_received():
        binding = cache.application_binding(application_id)
        if binding is None:
            raise HTTPException(403, "APPLICATION_NOT_BOUND")
        source_id, application_mode = binding
        if application_mode == "protect":
            # A production Guard without a received revision envelope cannot
            # correlate Layer 1 with the authorization state at Layer 2.
            # Never treat "not yet synced" as "no revisions required".
            if os.getenv("ACCESSPROOF_ENV", "").lower() == "production":
                if (not cache.authorization_revisions_received()
                        or cache.authorization_revision(application_id) is None):
                    raise HTTPException(503, "AUTHORIZATION_REVISION_NOT_SYNCED")
            age = cache.sync_age_seconds()
            if age is None or age > max_policy_age_seconds:
                raise HTTPException(503, "POLICY_SYNC_STALE")
            if not cache.source_acl_healthy(application_id) and not cache.certification_window(application_id):
                # D-19: inside a control-plane certification window the Guard
                # makes real, mapping-bound decisions; /health stays not ready.
                raise HTTPException(503, "SOURCE_ACL_STALE")
            if cache.authorization_revisions_received() and cache.authorization_revision(application_id) is None:
                raise HTTPException(503, "AUTHORIZATION_REVISION_MISSING")
        return application_mode, source_id
    if (
        guard_id or guard_credential
        or os.getenv("ACCESSPROOF_ENV", "").lower() not in {"development", "test"}
        or os.getenv("ACCESSPROOF_GUARD_STANDALONE_TEST_MODE") != "1"
    ):
        # Fail closed by default, including a missing ACCESSPROOF_ENV. Only
        # explicit isolated development tests may use an unbound legacy Guard.
        # Neither a static JWT nor a persisted local ACL grants an arbitrary
        # application permission without authoritative machine enrollment.
        raise HTTPException(503, "APPLICATION_BINDINGS_NOT_SYNCED")
    return mode, None


class ScopedResource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(min_length=1, max_length=255)
    resource_id: str = Field(min_length=1, max_length=1024)
    chunk_id: str | None = Field(default=None, max_length=1024)
    content_version: str | None = Field(default=None, max_length=1024)


class MultiSourceAuthorizationScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    application_id: str = Field(min_length=1, max_length=255)
    request_id: str = Field(min_length=1, max_length=255)
    source_ids: list[str] = Field(min_length=1, max_length=4)


@app.post("/guard/v2/authorization-scope")
def multisource_authorization_scope(
    payload: MultiSourceAuthorizationScopeRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    effective_mode, _ = _application_mode(payload.application_id)
    if effective_mode != "protect":
        raise HTTPException(403, "PROTECT_MODE_REQUIRED")
    if len(set(payload.source_ids)) != len(payload.source_ids):
        raise HTTPException(422, "DUPLICATE_SOURCES")
    bindings = cache.application_sources(payload.application_id)
    if not set(payload.source_ids).issubset(bindings):
        raise HTTPException(403, "APPLICATION_SOURCE_MISMATCH")
    if any(not bindings[s] for s in payload.source_ids):
        raise HTTPException(503, "SOURCE_ACL_STALE")
    revision = cache.authorization_revision(payload.application_id)
    if not cache.authorization_revisions_received() or revision is None:
        raise HTTPException(503, "AUTHORIZATION_REVISION_NOT_SYNCED")
    subject, token_issuer, tenant_id = _identity(authorization)
    scoped: list[dict[str, Any]] = []
    total = 0
    for source in payload.source_ids:
        mapped = _mapped_subject(authorization, source)
        resource_ids, truncated = cache.allowed_resources(mapped, source, limit=5000)
        total += len(resource_ids)
        if truncated or total > 5000:
            raise HTTPException(503, "AUTHORIZATION_SCOPE_TRUNCATED")
        scoped.append({"source_id": source, "allowed_resource_ids": resource_ids})
    result = "allow" if total else "block"
    cache.buffer_audit(
        str(uuid4()), application_id=payload.application_id,
        subject_id=principal_key(subject, token_issuer, tenant_id),
        request_id=payload.request_id, result=result,
        reason="MULTISOURCE_AUTHORIZATION_SCOPE",
        policy_version=cache.version(), layer="layer1",
        resource_ids=[f"{entry['source_id']}:{rid}" for entry in scoped for rid in entry["allowed_resource_ids"]],
        authorization_revision=revision[0], authorization_revision_hash=revision[1],
    )
    return {
        "decision": result, "mode": "protect",
        "reason": "MULTISOURCE_AUTHORIZATION_SCOPE",
        "sources": scoped, "scope_complete": True,
        "policy_version": cache.version(),
        "authorization_revision": revision[0],
        "authorization_revision_hash": revision[1],
    }


class ScopedOutputRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_id: str = Field(min_length=1, max_length=255)
    application_id: str = Field(min_length=1, max_length=255)
    request_id: str = Field(min_length=1, max_length=255)
    used_resources: list[ScopedResource] = Field(min_length=1, max_length=5000)
    provenance: list[ScopedResource] = Field(min_length=1, max_length=5000)


@app.post("/guard/v2/filter-resources")
def multisource_filter_resources(
    payload: FilterRequest, authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Source-qualified Layer 1, never accepting a source without a live binding."""
    _application_mode(payload.application_id)
    if not payload.resources:
        raise HTTPException(422, "NO_RETRIEVED_RESOURCES")
    sources = {item.source_id for item in payload.resources}
    bound = cache.application_sources(payload.application_id)
    if not sources.issubset(bound) or not bound:
        raise HTTPException(403, "APPLICATION_SOURCE_MISMATCH")
    binding = cache.application_binding(payload.application_id)
    if binding is None:
        raise HTTPException(403, "APPLICATION_NOT_BOUND")
    if binding[1] != "protect":
        raise HTTPException(403, "PROTECT_MODE_REQUIRED")
    subject, token_issuer, tenant_id = _identity(authorization)
    mapped = {src: _mapped_subject(authorization, src) for src in sources}
    if any(item.scope != "read" for item in payload.resources):
        raise HTTPException(422, "MULTISOURCE_SCOPE_UNSUPPORTED")
    if any(not item.content_version for item in payload.resources):
        raise HTTPException(422, "SOURCE_CONTENT_VERSION_REQUIRED")
    resources = [
        {
            "source_id": item.source_id, "resource_id": item.resource_id,
            "chunk_id": (item.chunk_ids[0] if len(item.chunk_ids) == 1 else ""),
            "content_version": item.content_version,
        } for item in payload.resources
    ]
    if any(len(item.chunk_ids) > 1 for item in payload.resources):
        raise HTTPException(422, "AMBIGUOUS_CHUNK_SCOPE")
    result = MultiSourceGuard(cache).filter(
        application_id=payload.application_id, request_id=payload.request_id,
        principal=principal_key(subject, token_issuer, tenant_id),
        mapped_subjects=mapped, resources=resources,
    )
    cache.buffer_audit(
        str(result.get("decision_id", uuid4())),
        application_id=payload.application_id,
        subject_id=principal_key(subject, token_issuer, tenant_id),
        request_id=payload.request_id, result=str(result["decision"]),
        reason=str(result["reason"]), policy_version=cache.version(),
        layer="layer1",
        resource_ids=sorted(f"{item.source_id}:{item.resource_id}" for item in payload.resources),
    )
    return result


@app.post("/guard/v2/check-output")
def multisource_check_output(
    payload: ScopedOutputRequest, authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """One-time, atomic release with all source-specific ACLs re-evaluated."""
    _application_mode(payload.application_id)
    subject, token_issuer, tenant_id = _identity(authorization)
    sources = {item.source_id for item in payload.used_resources + payload.provenance}
    if not sources.issubset(cache.application_sources(payload.application_id)):
        raise HTTPException(403, "APPLICATION_SOURCE_MISMATCH")
    mapped = {src: _mapped_subject(authorization, src) for src in sources}
    result = MultiSourceGuard(cache).release(
        application_id=payload.application_id, request_id=payload.request_id,
        principal=principal_key(subject, token_issuer, tenant_id),
        decision_id=payload.decision_id, mapped_subjects=mapped,
        used_resources=[entry.model_dump() for entry in payload.used_resources],
        provenance=[entry.model_dump() for entry in payload.provenance],
    )
    cache.buffer_audit(
        f"{payload.decision_id}:v2layer2", application_id=payload.application_id,
        subject_id=principal_key(subject, token_issuer, tenant_id),
        request_id=payload.request_id, result=str(result["decision"]),
        reason=str(result["reason"]), policy_version=cache.version(),
        decision_id=payload.decision_id, layer="layer2",
        resource_ids=sorted(f"{item.source_id}:{item.resource_id}" for item in payload.used_resources),
    )
    return result


@app.post("/guard/v1/authorization-scope")
def authorization_scope(
    payload: AuthorizationScopeRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Return the exact resource scope in which retrieval may run ANN search.

    The response contains stable provider resource identifiers, never content.
    An incomplete (truncated) scope is a hard failure: silently searching a
    partial allow-set is an availability and product-correctness defect, not a
    safe degradation.
    """
    effective_mode, bound_source = _application_mode(payload.application_id)
    if len(cache.application_sources(payload.application_id)) != 1:
        raise HTTPException(403, "MULTISOURCE_REQUIRES_V2")
    if bound_source is None:
        raise HTTPException(503, "APPLICATION_BINDINGS_NOT_SYNCED")
    subject = _mapped_subject(authorization, bound_source)
    resource_ids, truncated = cache.allowed_resources(subject, bound_source)
    revision = cache.authorization_revision(payload.application_id)
    revision_hash = revision[1] if revision else None
    decision_id = str(uuid4())
    if truncated:
        result, reason = "block", "AUTHORIZATION_SCOPE_TRUNCATED"
    elif not resource_ids:
        result, reason = "block", "NO_AUTHORIZED_RESOURCES"
    else:
        result, reason = "allow", "AUTHORIZATION_SCOPE"
    cache.buffer_audit(
        decision_id,
        application_id=payload.application_id,
        subject_id=subject,
        request_id=payload.request_id,
        result=result,
        reason=reason,
        policy_version=cache.version(),
        decision_id=decision_id,
        layer="layer1",
        resource_ids=resource_ids,
        authorization_revision=revision[0] if revision else None,
        authorization_revision_hash=revision_hash,
    )
    response: dict[str, Any] = {
        "decision_id": decision_id,
        "decision": result,
        "reason": reason,
        "mode": effective_mode,
        "policy_version": cache.version(),
        "source_id": bound_source,
        "allowed_resource_ids": resource_ids if result == "allow" else [],
        "truncated": truncated,
        "scope_complete": not truncated,
    }
    if revision is not None:
        response["authorization_revision"] = revision[0]
        response["authorization_revision_hash"] = revision_hash
    return response


@app.post("/guard/v1/filter-resources")
def filter_resources(payload: FilterRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    effective_mode, bound_source = _application_mode(payload.application_id)
    if len(cache.application_sources(payload.application_id)) > 1:
        raise HTTPException(403, "MULTISOURCE_REQUIRES_V2")
    if bound_source and any(resource.source_id != bound_source for resource in payload.resources):
        raise HTTPException(403, "APPLICATION_SOURCE_MISMATCH")
    subject = _mapped_subject(authorization, bound_source)
    grouped: dict[tuple[str, str, str], list[Resource]] = defaultdict(list)
    for resource in payload.resources:
        grouped[(resource.source_id, resource.resource_id, resource.scope)].append(resource)
    allowed: list[ResourceDecision] = []
    denied: list[ResourceDecision] = []
    unknown: list[ResourceDecision] = []
    for (source_id, resource_id, scope), items in grouped.items():
        decision, reason = cache.decide(subject, source_id, resource_id, scope)
        if decision == "allow":
            # Cached-chunk freshness: a still-valid attestation of an OLD
            # document version is not current content (fails closed).
            stale = cache.content_version_refusal(source_id, resource_id, [r.content_version for r in items])
            if stale:
                decision, reason = "deny", stale
        item: ResourceDecision = {"source_id": source_id, "resource_id": resource_id, "chunk_ids": [chunk for r in items for chunk in r.chunk_ids], "reason": reason}
        if decision == "allow":
            allowed.append(item)
        elif decision == "deny":
            denied.append(item)
        else:
            unknown.append(item)
    if effective_mode == "shadow":
        # Shadow preserves the unfiltered context while recording the would-block
        # outcome. It must never enforce an authorization denial.
        allowed += denied + unknown
        result = "would_block" if denied or unknown else "would_allow"
    else:
        # When retrieval mixes allowed and denied documents, pass only the
        # allowlisted resources. Do not block unrelated authorized documents.
        result = "allow" if allowed else "block"
    decision_id = str(uuid4())
    revision = cache.authorization_revision(payload.application_id)
    revision_hash = revision[1] if revision else ""
    cache.save_context(
        decision_id, payload.application_id, subject, [item["resource_id"] for item in allowed],
        request_id=payload.request_id, source_id=bound_source or "",
        revision_hash=revision_hash,
    )
    cache.buffer_audit(
        decision_id,
        application_id=payload.application_id,
        subject_id=subject,
        request_id=payload.request_id,
        result=result,
        reason="LAYER1_EFFECTIVE_ACCESS",
        policy_version=cache.version(),
        decision_id=decision_id,
        layer="layer1",
        resource_ids=[item["resource_id"] for item in allowed + denied + unknown],
        authorization_revision=revision[0] if revision else None,
        authorization_revision_hash=revision_hash or None,
    )
    response: dict[str, Any] = {"decision_id": decision_id, "decision": result, "policy_version": cache.version(), "mode": effective_mode, "allowed": allowed, "denied": denied, "unknown": unknown}
    if revision is not None:
        response["authorization_revision"] = revision[0]
        response["authorization_revision_hash"] = revision[1]
    return response


@app.post("/guard/v1/check-output")
def check_output(payload: OutputRequest, authorization: str | None = Header(default=None)) -> dict[str, str | int]:
    """Block output whose trusted provenance escapes the Layer 1 context."""
    effective_mode, bound_source = _application_mode(payload.application_id)
    if len(cache.application_sources(payload.application_id)) > 1:
        raise HTTPException(403, "MULTISOURCE_REQUIRES_V2")
    subject = _mapped_subject(authorization, bound_source)
    context_ids = [payload.decision_id, *payload.additional_decision_ids]
    context_valid = len(context_ids) == len(set(context_ids))
    primary = (
        cache.load_context_binding(payload.decision_id, payload.application_id, subject, payload.request_id,
                                   source_id=bound_source)
        if context_valid else None
    )
    permitted = primary[0] if primary is not None else None
    context_revisions = {primary[1]} if primary is not None else set()
    # A late source is acceptable only if it passed an additional real Layer 1
    # check for the SAME verified subject/application/request. Merely reporting
    # an extra provenance ID must never authorize it.
    for extra_decision_id in payload.additional_decision_ids:
        if permitted is None:
            break
        extra = cache.load_context_binding(
            extra_decision_id, payload.application_id, subject, payload.request_id,
            source_id=bound_source,
        )
        if extra is None:
            permitted = None
            break
        permitted.update(extra[0])
        context_revisions.add(extra[1])
    # The policy may change between this check and context consumption.
    # The consume operation rejects a policy rollover under the same cache lock.
    checked_policy_version = cache.version()
    # Permissions may be revoked during generation, or an in-flight Shadow
    # request may finish after Protect becomes active. Re-check every source
    # resource against the newest installed policy at the release boundary.
    revoked_after_layer1 = (
        effective_mode == "protect"
        and bound_source is not None
        and permitted is not None
        and any(cache.decide(subject, bound_source, resource_id, "read")[0] != "allow"
                for resource_id in permitted)
    )
    provenance_ids = {
        resource_id
        for item in payload.provenance
        for resource_id in item.source_resource_ids
    }
    revision = cache.authorization_revision(payload.application_id)
    revision_changed = bool(
        effective_mode == "protect"
        and permitted is not None
        and cache.authorization_revisions_received()
        and (revision is None or any(
            context_hash != revision[1] for context_hash in context_revisions
        ))
    )
    revision_fields: dict[str, str | int] = (
        {"authorization_revision": revision[0], "authorization_revision_hash": revision[1]}
        if revision is not None else {}
    )
    result: dict[str, str | int]
    if permitted is None:
        result = {"decision": "would_block" if effective_mode == "shadow" else "block", "reason": "DECISION_CONTEXT_INVALID", "policy_version": cache.version()}
    elif revision_changed:
        result = {"decision": "block", "reason": "AUTHORIZATION_REVISION_CHANGED", "policy_version": cache.version()}
    elif revoked_after_layer1:
        result = {"decision": "block", "reason": "LAYER2_ACCESS_REVOKED", "policy_version": cache.version()}
    elif not provenance_ids or not set(payload.used_resource_ids).issubset(provenance_ids):
        result = {"decision": "would_block" if effective_mode == "shadow" else "block", "reason": "PROVENANCE_MISSING", "policy_version": cache.version()}
    elif provenance_ids.difference(permitted) or set(payload.used_resource_ids).difference(permitted):
        result = {"decision": "block" if effective_mode == "protect" else "would_block", "reason": "PROVENANCE_ESCAPE", "policy_version": cache.version()}
    else:
        result = {"decision": "allow" if effective_mode == "protect" else "would_allow", "reason": "TRUSTED_PROVENANCE_VALID", "policy_version": cache.version()}
    # One-time contexts must be consumed atomically: concurrent or replayed
    # Layer 2 checks cannot release a response by reusing a decision.
    if permitted is not None:
        if bound_source is not None:
            # Lock reauthorization and context consumption to one SQLite write
            # transaction. A revoke or app-mode change cannot slip between them.
            finalized = cache.consume_contexts_with_recheck(
                context_ids, payload.application_id, subject, payload.request_id,
                source_id=bound_source, expected_mode=effective_mode,
            )
            if finalized == "revoked":
                result = {"decision": "block", "reason": "LAYER2_ACCESS_REVOKED", "policy_version": cache.version()}
            elif finalized == "revision_changed":
                result = {"decision": "block", "reason": "AUTHORIZATION_REVISION_CHANGED", "policy_version": cache.version()}
            elif finalized != "ok":
                result = {"decision": "block", "reason": "DECISION_CONTEXT_INVALID", "policy_version": cache.version()}
        elif not cache.consume_contexts(
            context_ids, payload.application_id, subject, payload.request_id,
            expected_policy_version=checked_policy_version,
        ):
            result = {"decision": "would_block" if effective_mode == "shadow" else "block",
                      "reason": "DECISION_CONTEXT_INVALID", "policy_version": cache.version()}
    cache.buffer_audit(
        f"{payload.decision_id}:layer2",
        application_id=payload.application_id,
        subject_id=subject,
        request_id=payload.request_id,
        result=str(result["decision"]),
        reason=str(result["reason"]),
        policy_version=cache.version(),
        decision_id=payload.decision_id,
        layer="layer2",
        resource_ids=sorted(provenance_ids),
        authorization_revision=revision[0] if revision else None,
        authorization_revision_hash=revision[1] if revision else None,
    )
    result.update(revision_fields)
    return result
