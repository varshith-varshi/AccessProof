from __future__ import annotations

import os
import asyncio
import json
from pathlib import Path
from uuid import uuid4
from collections import defaultdict
from contextlib import asynccontextmanager, suppress
from typing import Any

import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .cache import PolicyCache
from .identity import IdentityError, OidcVerifier
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
_credential_path = Path(os.getenv("ACCESSPROOF_GUARD_CREDENTIAL_FILE", "/var/lib/accessproof-guard/credentials.json"))


def _load_machine_settings() -> dict[str, str]:
    """Load a mode-0600 local enrollment record without logging its contents."""
    if not _credential_path.is_file():
        return {}
    try:
        payload = json.loads(_credential_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {key: str(value) for key, value in payload.items() if key in {"control_plane_url", "guard_id", "credential"}}


_machine_settings = _load_machine_settings()
control_plane_url = os.getenv("ACCESSPROOF_GUARD_CONTROL_PLANE_URL") or _machine_settings.get("control_plane_url")
guard_id = os.getenv("ACCESSPROOF_GUARD_ID") or _machine_settings.get("guard_id")
guard_credential = os.getenv("ACCESSPROOF_GUARD_CREDENTIAL") or _machine_settings.get("credential")
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
    global _sync_error
    if not control_plane_url or not guard_id or not guard_credential:
        _sync_error = "CONTROL_PLANE_NOT_CONFIGURED"
        return
    client = GuardSyncClient(
        cache,
        GuardMachineCredentials(
            control_plane_url=control_plane_url,
            guard_id=guard_id,
            credential=guard_credential,
            version=guard_version,
        ),
    )
    try:
        while True:
            try:
                await asyncio.to_thread(client.sync_once)
                await asyncio.to_thread(client.upload_audit)
                await asyncio.to_thread(client.heartbeat)
                _sync_error = None
            except Exception as exc:
                # Do not log credentials or request bodies.  The data plane
                # continues enforcing its last known durable policy.
                _sync_error = type(exc).__name__
            await asyncio.sleep(sync_interval_seconds)
    finally:
        client.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
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


class Resource(BaseModel):
    source_id: str
    resource_id: str
    scope: str = "read"
    chunk_ids: list[str] = Field(default_factory=list)


class FilterRequest(BaseModel):
    application_id: str
    request_id: str
    resources: list[Resource]


class OutputRequest(BaseModel):
    decision_id: str
    application_id: str
    request_id: str
    used_resource_ids: list[str] = Field(default_factory=list)
    provenance: list["ProvenanceItem"] = Field(default_factory=list)


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
    return {
        "status": "ok" if _sync_error is None else "degraded",
        "policy_version": cache.version(),
        "ready": cache.version() > 0,
        "control_plane_configured": configured,
        "sync_error": _sync_error,
    }


@app.post("/guard/v1/filter-resources")
def filter_resources(payload: FilterRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    subject = _subject(authorization)
    grouped: dict[tuple[str, str, str], list[Resource]] = defaultdict(list)
    for resource in payload.resources:
        grouped[(resource.source_id, resource.resource_id, resource.scope)].append(resource)
    allowed: list[dict[str, object]] = []
    denied: list[dict[str, object]] = []
    unknown: list[dict[str, object]] = []
    for (source_id, resource_id, scope), items in grouped.items():
        decision, reason = cache.decide(subject, source_id, resource_id, scope)
        item = {"source_id": source_id, "resource_id": resource_id, "chunk_ids": [chunk for r in items for chunk in r.chunk_ids], "reason": reason}
        if decision == "allow":
            allowed.append(item)
        elif decision == "deny":
            denied.append(item)
        else:
            unknown.append(item)
    if mode == "shadow":
        allowed += denied + unknown
        result = "would_block" if denied or (unknown and fail_mode == "fail_closed") else "would_allow"
    else:
        result = "block" if denied or (unknown and fail_mode == "fail_closed") else "allow"
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
    return {"decision_id": decision_id, "decision": result, "policy_version": cache.version(), "mode": mode, "allowed": allowed, "denied": denied, "unknown": unknown}


@app.post("/guard/v1/check-output")
def check_output(payload: OutputRequest, authorization: str | None = Header(default=None)) -> dict[str, str | int]:
    """Block output whose trusted provenance escapes the Layer 1 context."""
    subject = _subject(authorization)
    permitted = cache.load_context(payload.decision_id, payload.application_id, subject, payload.request_id)
    provenance_ids = {
        resource_id
        for item in payload.provenance
        for resource_id in item.source_resource_ids
    }
    if permitted is None:
        result = {"decision": "unknown", "reason": "DECISION_CONTEXT_INVALID", "policy_version": cache.version()}
    elif not provenance_ids or not set(payload.used_resource_ids).issubset(provenance_ids):
        result = {"decision": "block" if fail_mode == "fail_closed" and mode == "protect" else "unknown", "reason": "PROVENANCE_MISSING", "policy_version": cache.version()}
    elif provenance_ids.difference(permitted) or set(payload.used_resource_ids).difference(permitted):
        result = {"decision": "block" if mode == "protect" else "would_block", "reason": "PROVENANCE_ESCAPE", "policy_version": cache.version()}
    else:
        result = {"decision": "allow" if mode == "protect" else "would_allow", "reason": "TRUSTED_PROVENANCE_VALID", "policy_version": cache.version()}
    if permitted is not None:
        cache.consume_context(payload.decision_id, payload.application_id, subject, payload.request_id)
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
