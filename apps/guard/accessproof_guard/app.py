from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .cache import PolicyCache

cache = PolicyCache(os.getenv("ACCESSPROOF_GUARD_CACHE", "/var/lib/accessproof-guard/policy.db"))
issuer = os.getenv("ACCESSPROOF_GUARD_JWT_ISSUER")
audience = os.getenv("ACCESSPROOF_GUARD_JWT_AUDIENCE")
verification_key = os.getenv("ACCESSPROOF_GUARD_JWT_VERIFICATION_KEY")
mode = os.getenv("ACCESSPROOF_GUARD_MODE", "protect").lower()
fail_mode = os.getenv("ACCESSPROOF_GUARD_FAIL_MODE", "fail_closed").lower()
app = FastAPI(title="AccessProof Guard", docs_url=None, redoc_url=None)


class Resource(BaseModel):
    source_id: str
    resource_id: str
    scope: str = "read"
    chunk_ids: list[str] = Field(default_factory=list)


class FilterRequest(BaseModel):
    application_id: str
    request_id: str
    resources: list[Resource]


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
    return {"status": "ok", "policy_version": cache.version(), "ready": cache.version() > 0}


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
    return {"decision": result, "policy_version": cache.version(), "mode": mode, "allowed": allowed, "denied": denied, "unknown": unknown}
