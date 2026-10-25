from __future__ import annotations

import os
import asyncio
import json
import stat
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4
from collections import defaultdict
from contextlib import asynccontextmanager, suppress
from typing import Any, AsyncIterator, TypedDict

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .cache import PolicyCache
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
mode = os.getenv("ACCESSPROOF_GUARD_MODE", "protect").lower()
fail_mode = os.getenv("ACCESSPROOF_GUARD_FAIL_MODE", "fail_closed").lower()
max_policy_age_seconds = max(10.0, float(os.getenv("ACCESSPROOF_GUARD_MAX_POLICY_AGE_SECONDS", "120")))
_credential_path = Path(os.getenv("ACCESSPROOF_GUARD_CREDENTIAL_FILE", "/var/lib/accessproof-guard/credentials.json"))


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
issuer = issuer or _machine_settings.get("issuer")
audience = audience or _machine_settings.get("audience")
identity_mode = _machine_settings.get("identity_mode", identity_mode)
expected_tenant = expected_tenant or _machine_settings.get("tenant_id")
subject_claim = _machine_settings.get("subject_claim", subject_claim)
guard_version = os.getenv("ACCESSPROOF_GUARD_VERSION", "0.1.0")
sync_interval_seconds = max(2.0, float(os.getenv("ACCESSPROOF_GUARD_SYNC_SECONDS", "10")))
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
                await asyncio.to_thread(client.upload_audit)
                identity_degraded = [] if identity_mode == "oidc" and issuer and audience else ["OIDC_IDENTITY_NOT_CONFIGURED"]
                await asyncio.to_thread(client.heartbeat, degraded_conditions=identity_degraded)
                _sync_error = None
            except Exception as exc:
                # Do not log credentials or request bodies.  The data plane
                # continues enforcing its last known durable policy.
                _sync_error = type(exc).__name__
            await asyncio.sleep(sync_interval_seconds)
    finally:
        if client is not None:
            client.close()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    task = asyncio.create_task(_sync_loop())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if _oidc_verifier is not None:
            _oidc_verifier.close()


app = FastAPI(title="AccessProof Guard", docs_url=None, redoc_url=None, lifespan=lifespan)


class SetupEnrollmentRequest(BaseModel):
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
    source_id: str
    resource_id: str
    scope: str = "read"
    chunk_ids: list[str] = Field(default_factory=list)


class FilterRequest(BaseModel):
    application_id: str
    request_id: str
    resources: list[Resource]




class ResourceDecision(TypedDict):
    source_id: str
    resource_id: str
    chunk_ids: list[str]
    reason: str


class OutputRequest(BaseModel):
    decision_id: str
    application_id: str
    request_id: str
    used_resource_ids: list[str] = Field(default_factory=list)
    provenance: list["ProvenanceItem"] = Field(default_factory=list)
    # Extra sources must have passed their own Layer 1 check for this same request.
    additional_decision_ids: list[str] = Field(default_factory=list, max_length=16)


class ProvenanceItem(BaseModel):
    """A derived result with the stable source resources that produced it."""
    derived_id: str | None = Field(default=None, max_length=255)
    derived_type: str = Field(default="retrieval", max_length=64)
    source_resource_ids: list[str] = Field(default_factory=list, max_length=500)


def _subject(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "IDENTITY_TOKEN_INVALID")
    if identity_mode == "oidc":
        try:
            return _oidc().verify(token).subject
        except IdentityError as exc:
            status = 503 if exc.args[0] in {"IDENTITY_KEY_UNAVAILABLE", "IDENTITY_PROVIDER_UNAVAILABLE"} else 401
            raise HTTPException(status, exc.args[0]) from exc
    if identity_mode != "static" or not issuer or not audience or not verification_key:
        raise HTTPException(503, "IDENTITY_PROVIDER_UNAVAILABLE")
    try:
        claims = jwt.decode(token, verification_key, algorithms=["HS256"], issuer=issuer, audience=audience, options={"require": ["exp", "sub", "iss", "aud"]})
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "IDENTITY_TOKEN_INVALID") from exc
    if expected_tenant and claims.get("tid") != expected_tenant:
        raise HTTPException(401, "IDENTITY_TENANT_MISMATCH")
    stable_subject = claims.get(subject_claim)
    if not isinstance(stable_subject, str) or not stable_subject:
        raise HTTPException(401, "IDENTITY_SUBJECT_UNKNOWN")
    return stable_subject


@app.get("/health")
def health() -> dict[str, object]:
    configured = bool(control_plane_url and guard_id and guard_credential)
    sync_age = cache.sync_age_seconds()
    fresh = sync_age is not None and sync_age <= max_policy_age_seconds
    source_healthy = cache.all_protect_sources_healthy()
    # A synchronized policy version alone is not customer readiness: a Guard
    # with zero bound applications cannot protect any customer RAG traffic.
    bindings_ready = (
        not configured
        or (cache.application_bindings_received() and bool(cache.application_modes()))
    )
    ready = cache.version() > 0 and source_healthy and bindings_ready and (not configured or fresh)
    return {
        "status": "ok" if ready and _sync_error is None else "degraded",
        "policy_version": cache.version(),
        "ready": ready,
        "policy_fresh": fresh if configured else None,
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
            age = cache.sync_age_seconds()
            if age is None or age > max_policy_age_seconds:
                raise HTTPException(503, "POLICY_SYNC_STALE")
            if not cache.source_acl_healthy(application_id):
                raise HTTPException(503, "SOURCE_ACL_STALE")
        return application_mode, source_id
    if guard_id or guard_credential:
        # Production Guard must not fall back to a global mode or accept an
        # arbitrary caller-provided application identifier before sync.
        raise HTTPException(503, "APPLICATION_BINDINGS_NOT_SYNCED")
    # Isolated standalone unit tests retain the original local-only fallback.
    return mode, None


@app.post("/guard/v1/filter-resources")
def filter_resources(payload: FilterRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    subject = _subject(authorization)
    effective_mode, bound_source = _application_mode(payload.application_id)
    if bound_source and any(resource.source_id != bound_source for resource in payload.resources):
        raise HTTPException(403, "APPLICATION_SOURCE_MISMATCH")
    grouped: dict[tuple[str, str, str], list[Resource]] = defaultdict(list)
    for resource in payload.resources:
        grouped[(resource.source_id, resource.resource_id, resource.scope)].append(resource)
    allowed: list[ResourceDecision] = []
    denied: list[ResourceDecision] = []
    unknown: list[ResourceDecision] = []
    for (source_id, resource_id, scope), items in grouped.items():
        decision, reason = cache.decide(subject, source_id, resource_id, scope)
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
    cache.save_context(
        decision_id, payload.application_id, subject, [item["resource_id"] for item in allowed],
        request_id=payload.request_id,
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
    )
    return {"decision_id": decision_id, "decision": result, "policy_version": cache.version(), "mode": effective_mode, "allowed": allowed, "denied": denied, "unknown": unknown}


@app.post("/guard/v1/check-output")
def check_output(payload: OutputRequest, authorization: str | None = Header(default=None)) -> dict[str, str | int]:
    """Block output whose trusted provenance escapes the Layer 1 context."""
    subject = _subject(authorization)
    effective_mode, bound_source = _application_mode(payload.application_id)
    context_ids = [payload.decision_id, *payload.additional_decision_ids]
    context_valid = len(context_ids) == len(set(context_ids))
    permitted = (
        cache.load_context(payload.decision_id, payload.application_id, subject, payload.request_id)
        if context_valid else None
    )
    # A late source is acceptable only if it passed an additional real Layer 1
    # check for the SAME verified subject/application/request. Merely reporting
    # an extra provenance ID must never authorize it.
    for extra_decision_id in payload.additional_decision_ids:
        if permitted is None:
            break
        extra = cache.load_context(
            extra_decision_id, payload.application_id, subject, payload.request_id
        )
        if not extra:
            permitted = None
            break
        permitted.update(extra)
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
    result: dict[str, str | int]
    if permitted is None:
        result = {"decision": "would_block" if effective_mode == "shadow" else "block", "reason": "DECISION_CONTEXT_INVALID", "policy_version": cache.version()}
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
    )
    return result
