from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import httpx
import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


MODEL_BASE_URL = os.getenv("DEMO_AI_MODEL_BASE_URL", "").rstrip("/")
MODEL_API_KEY = os.getenv("DEMO_AI_MODEL_API_KEY", "")
MODEL_NAME = os.getenv("DEMO_AI_MODEL_NAME", "")
SERVICE_TOKEN = os.getenv("DEMO_AI_SERVICE_TOKEN", "")
STALE_SECONDS = max(0.0, float(os.getenv("DEMO_AI_STALE_ACCESS_SECONDS", "0")))
OIDC_ISSUER = os.getenv("DEMO_AI_OIDC_ISSUER", "").rstrip("/")
OIDC_AUDIENCE = os.getenv("DEMO_AI_OIDC_AUDIENCE", "")
REQUIRE_OIDC = os.getenv("DEMO_AI_REQUIRE_OIDC", "0").lower() in {"1", "true", "yes"}
OIDC_REQUIRED_SCOPES = {item for item in os.getenv("DEMO_AI_OIDC_REQUIRED_SCOPES", "").split() if item}
OIDC_TENANT_ID = os.getenv("DEMO_AI_OIDC_TENANT_ID", "")
OIDC_CACHE_SECONDS = max(30.0, float(os.getenv("DEMO_AI_OIDC_CACHE_SECONDS", "300")))

app = FastAPI(title="AccessProof external-AI demo")


@dataclass
class Document:
    name: str
    content: str
    marker: str
    grants: set[str] = field(default_factory=set)
    revoked_at: dict[str, float] = field(default_factory=dict)


documents: dict[str, Document] = {}
_oidc_metadata: tuple[float, dict[str, object]] | None = None
_oidc_jwks: tuple[float, dict[str, object]] | None = None


class DocumentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=100_000)
    marker: str = Field(min_length=8, max_length=200)


class GrantRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=320)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)
    user_id: str | None = Field(default=None, max_length=320)


def _authorize(authorization: str | None) -> None:
    if SERVICE_TOKEN and authorization != f"Bearer {SERVICE_TOKEN}":
        raise HTTPException(401, "Invalid demo-AI service token")


async def _oidc_json(url: str) -> dict[str, object]:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, "OIDC provider metadata is unavailable") from exc
    if not isinstance(payload, dict):
        raise HTTPException(503, "OIDC provider returned invalid metadata")
    return payload


async def _oidc_discovery(*, refresh: bool = False) -> dict[str, object]:
    global _oidc_metadata
    if not refresh and _oidc_metadata and time.monotonic() - _oidc_metadata[0] < OIDC_CACHE_SECONDS:
        return _oidc_metadata[1]
    payload = await _oidc_json(f"{OIDC_ISSUER}/.well-known/openid-configuration")
    if str(payload.get("issuer") or "").rstrip("/") != OIDC_ISSUER or not isinstance(payload.get("jwks_uri"), str):
        raise HTTPException(503, "OIDC discovery configuration is invalid")
    _oidc_metadata = (time.monotonic(), payload)
    return payload


async def _oidc_signing_key(token: str) -> tuple[Any, str]:
    global _oidc_jwks
    try:
        header = jwt.get_unverified_header(token)
        kid, algorithm = header.get("kid"), header.get("alg")
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "MALFORMED_TOKEN") from exc
    if not isinstance(kid, str) or algorithm not in {"RS256", "RS384", "RS512", "ES256", "ES384"}:
        raise HTTPException(401, "INVALID_ALGORITHM")
    for refresh in (False, True):
        if refresh or not _oidc_jwks or time.monotonic() - _oidc_jwks[0] >= OIDC_CACHE_SECONDS:
            discovery = await _oidc_discovery(refresh=refresh)
            jwks = await _oidc_json(str(discovery["jwks_uri"]))
            _oidc_jwks = (time.monotonic(), jwks)
        keys = _oidc_jwks[1].get("keys")
        if isinstance(keys, list):
            for item in keys:
                if isinstance(item, dict) and item.get("kid") == kid:
                    try:
                        return jwt.PyJWK.from_dict(item, algorithm=algorithm).key, algorithm
                    except jwt.PyJWTError as exc:
                        raise HTTPException(401, "INVALID_SIGNING_KEY") from exc
    raise HTTPException(401, "UNKNOWN_SIGNING_KEY")


async def _authenticated_identity(authorization: str | None, requested_user: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer access token required")
    token = authorization[7:]
    if REQUIRE_OIDC:
        if not OIDC_ISSUER or not OIDC_AUDIENCE:
            raise HTTPException(503, "OIDC validation is not configured")
        try:
            signing_key, algorithm = await _oidc_signing_key(token)
            claims = jwt.decode(token, signing_key, algorithms=[algorithm], audience=OIDC_AUDIENCE, issuer=OIDC_ISSUER, options={"require": ["exp", "iat", "iss", "aud"]})
        except HTTPException:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(401, "TOKEN_EXPIRED") from exc
        except jwt.InvalidAudienceError as exc:
            raise HTTPException(401, "INVALID_AUDIENCE") from exc
        except jwt.InvalidIssuerError as exc:
            raise HTTPException(401, "INVALID_ISSUER") from exc
        except jwt.PyJWTError as exc:
            raise HTTPException(401, "INVALID_OIDC_TOKEN") from exc
        if OIDC_TENANT_ID and claims.get("tid") != OIDC_TENANT_ID:
            raise HTTPException(401, "INVALID_TENANT")
        scopes = set(str(claims.get("scp") or "").split())
        if OIDC_REQUIRED_SCOPES:
            if not scopes:
                raise HTTPException(401, "WRONG_TOKEN_TYPE")
            if not OIDC_REQUIRED_SCOPES.issubset(scopes):
                raise HTTPException(403, "MISSING_SCOPE")
        identity = claims.get("oid") or claims.get("sub")
        if not isinstance(identity, str) or not identity:
            raise HTTPException(401, "OIDC token has no stable subject")
        return identity
    if SERVICE_TOKEN and token == SERVICE_TOKEN and requested_user:
        return requested_user
    raise HTTPException(401, "OIDC validation is required for caller identity")


def _readable(document: Document, user_id: str, *, for_source_check: bool = False) -> bool:
    if user_id in document.grants:
        return True
    revoked_at = document.revoked_at.get(user_id)
    if not for_source_check and revoked_at is not None:
        return time.monotonic() - revoked_at < STALE_SECONDS
    return False


async def _answer(question: str, document: Document) -> str:
    """Use an external OpenAI-compatible model only after authorized retrieval."""
    if not (MODEL_BASE_URL and MODEL_API_KEY and MODEL_NAME):
        return f"Authorized synthetic document: {document.content}"
    headers = {"Authorization": f"Bearer {MODEL_API_KEY}"}
    payload = {
        "model": MODEL_NAME,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": "Answer only from the supplied retrieved document. Quote its unique canary exactly if relevant.",
            },
            {"role": "user", "content": f"Question: {question}\n\nRetrieved document:\n{document.content}"},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(f"{MODEL_BASE_URL}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            answer = response.json()["choices"][0]["message"]["content"]
            if isinstance(answer, str) and answer:
                return answer
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        pass
    return "The external model did not return an answer."


@app.get("/health")
async def health() -> dict[str, object]:
    return {"status": "ok", "external_model_configured": bool(MODEL_BASE_URL and MODEL_API_KEY and MODEL_NAME)}


@app.post("/v1/documents")
async def create_document(payload: DocumentCreate, authorization: str | None = Header(default=None)) -> dict[str, str]:
    _authorize(authorization)
    document_id = str(uuid4())
    documents[document_id] = Document(name=payload.name, content=payload.content, marker=payload.marker)
    return {"id": document_id}


@app.delete("/v1/documents/{document_id}", status_code=204)
async def delete_document(document_id: str, authorization: str | None = Header(default=None)) -> None:
    _authorize(authorization)
    documents.pop(document_id, None)


@app.post("/v1/documents/{document_id}/grants")
async def grant(document_id: str, payload: GrantRequest, authorization: str | None = Header(default=None)) -> dict[str, str]:
    _authorize(authorization)
    document = documents.get(document_id)
    if document is None:
        raise HTTPException(404, "Document not found")
    document.grants.add(payload.user_id)
    document.revoked_at.pop(payload.user_id, None)
    return {"grant_id": f"grant-{document_id}-{payload.user_id}"}


@app.delete("/v1/documents/{document_id}/grants/{user_id}", status_code=204)
async def revoke(document_id: str, user_id: str, authorization: str | None = Header(default=None)) -> None:
    _authorize(authorization)
    document = documents.get(document_id)
    if document is None:
        raise HTTPException(404, "Document not found")
    document.grants.discard(user_id)
    document.revoked_at[user_id] = time.monotonic()


@app.get("/v1/documents/{document_id}/access")
async def access(document_id: str, user_id: str, authorization: str | None = Header(default=None)) -> dict[str, bool]:
    _authorize(authorization)
    document = documents.get(document_id)
    return {"allowed": bool(document and _readable(document, user_id, for_source_check=True))}


@app.post("/v1/chat")
async def chat(payload: ChatRequest, authorization: str | None = Header(default=None)) -> dict[str, object]:
    user_id = await _authenticated_identity(authorization, payload.user_id)
    for document_id, document in documents.items():
        if _readable(document, user_id):
            answer = await _answer(payload.message, document)
            return {"answer": answer, "citations": [document_id], "retrieved_documents": [document.content]}
    return {"answer": "I do not have access to that information.", "citations": [], "retrieved_documents": []}
