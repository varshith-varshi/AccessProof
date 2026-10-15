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
from .sync import GuardMachineCredentials, GuardSyncClient

cache = PolicyCache(os.getenv("ACCESSPROOF_GUARD_CACHE", "/var/lib/accessproof-guard/policy.db"))
issuer = os.getenv("ACCESSPROOF_GUARD_JWT_ISSUER")
audience = os.getenv("ACCESSPROOF_GUARD_JWT_AUDIENCE")
verification_key = os.getenv("ACCESSPROOF_GUARD_JWT_VERIFICATION_KEY")
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
    used_resource_ids: list[str] = Field(default_factory=list)
    trusted_provenance: bool = False


def _subject(authorization: str | None) -> str:
    if not issuer or not audience or not verification_key:
        raise HTTPException(503, "Trusted identity validation is not configured")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "Trusted identity token required")
    try:
        claims = jwt.decode(token, verification_key, algorithms=["HS256"], issuer=issuer, audience=audience, options={"require": ["exp", "sub", "iss", "aud"]})
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid trusted identity token") from exc
    return str(claims["sub"])


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
    cache.save_context(decision_id, payload.application_id, subject, [item["resource_id"] for item in allowed])
    cache.buffer_audit(
        decision_id,
        application_id=payload.application_id,
        subject_id=subject,
        request_id=payload.request_id,
        result=result,
        reason="LAYER1_EFFECTIVE_ACCESS",
        policy_version=cache.version(),
    )
    return {"decision_id": decision_id, "decision": result, "policy_version": cache.version(), "mode": mode, "allowed": allowed, "denied": denied, "unknown": unknown}


@app.post("/guard/v1/check-output")
def check_output(payload: OutputRequest, authorization: str | None = Header(default=None)) -> dict[str, str | int]:
    """Block output whose trusted provenance escapes the Layer 1 context."""
    subject = _subject(authorization)
    permitted = cache.load_context(payload.decision_id, payload.application_id, subject)
    if permitted is None:
        result = {"decision": "unknown", "reason": "DECISION_CONTEXT_INVALID", "policy_version": cache.version()}
    elif not payload.trusted_provenance:
        result = {"decision": "block" if fail_mode == "fail_closed" and mode == "protect" else "unknown", "reason": "PROVENANCE_MISSING", "policy_version": cache.version()}
    elif set(payload.used_resource_ids).difference(permitted):
        result = {"decision": "block" if mode == "protect" else "would_block", "reason": "PROVENANCE_ESCAPE", "policy_version": cache.version()}
    else:
        result = {"decision": "allow" if mode == "protect" else "would_allow", "reason": "TRUSTED_PROVENANCE_VALID", "policy_version": cache.version()}
    cache.buffer_audit(
        f"{payload.decision_id}:layer2",
        application_id=payload.application_id,
        subject_id=subject,
        request_id=payload.decision_id,
        result=str(result["decision"]),
        reason=str(result["reason"]),
        policy_version=cache.version(),
    )
    return result
