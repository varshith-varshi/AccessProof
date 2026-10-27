import asyncio
import base64
import json
import os
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from packages.demo_cache.protected_cache import SignedRedisAnswerCache, CacheIntegrityError
from packages.demo_cache.universal import SignedBackendAnswerCache
from packages.demo_cache.factory import configured_cache_backend, CacheConfigurationError
from packages.demo_cache.trusted_snapshot import load_snapshot, SnapshotInvalid
from packages.rag_core import (
    GuardClient, ProtectedRAG, RetrievedResource, SourceAttestationVerifier,
    CachedAnswerManifestSigner, CachedAnswerManifestVerifier,
)
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from packages.auth.google_demo_login import (
    router as google_login_router, session_token_from_request as google_session_token,
)
from packages.auth.entra_demo_login import (
    router as entra_login_router, session_token_from_request as entra_session_token,
)
from pydantic import BaseModel

DRIVE_TOKEN = os.getenv("DRIVE_OWNER_TOKEN", "")
ROOT_FOLDER_ID = os.getenv("DRIVE_ROOT_FOLDER_ID", "")

ALICE_EMAIL = os.getenv("ALICE_EMAIL", "").lower()
ALICE_TOKEN = os.getenv("ALICE_RAG_TOKEN", "")

BOB_EMAIL = os.getenv("BOB_EMAIL", "").lower()
BOB_TOKEN = os.getenv("BOB_RAG_TOKEN", "")

CACHE_SECONDS = float(os.getenv("ACL_CACHE_SECONDS", "20"))
# Legacy endpoint is an intentionally vulnerable ACL-cache simulator, only
# available when explicitly enabled in isolated non-production environments.
ALLOW_LEGACY = os.getenv("ACCESSPROOF_DEMO_ALLOW_LEGACY", "0") == "1" and os.getenv("ACCESSPROOF_ENV", "development") == "development"

# Protected endpoint uses the real AccessProof Guard with a verified employee
# OIDC JWT and the source/application IDs registered in the control plane.
GUARD_URL = os.getenv("ACCESSPROOF_DEMO_GUARD_URL", "")
SOURCE_ID = os.getenv("ACCESSPROOF_DEMO_SOURCE_ID", "")
APPLICATION_ID = os.getenv("ACCESSPROOF_DEMO_APPLICATION_ID", "")


def _source_attestation_verifier() -> SourceAttestationVerifier | None:
    """Strict mode only: pins a trusted ingestion public key, never a signer.

    The ordinary text-only demo source refresh has no trusted ingestion
    attestations and therefore cannot pass this mode until customer ingestion
    is integrated. Missing configuration MUST fail closed.
    """
    if os.getenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT") != "1":
        return None
    try:
        tenant = os.environ["ACCESSPROOF_DEMO_ATTESTATION_TENANT"]
        key_id = os.environ["ACCESSPROOF_DEMO_ATTESTATION_KEY_ID"]
        material = base64.b64decode(
            os.environ["ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64"], validate=True,
        )
        key = Ed25519PublicKey.from_public_bytes(material)
        return SourceAttestationVerifier(
            tenant_id=tenant, trusted_keys={key_id: key},
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(503, "TRUSTED_SOURCE_ATTESTATION_NOT_CONFIGURED") from exc


def _signed_redis_cache(verifier: SourceAttestationVerifier | None) -> SignedRedisAnswerCache | None:
    """Opt-in cache only on this independently attested reference route."""
    try:
        backend = configured_cache_backend()
    except CacheConfigurationError as exc:
        raise HTTPException(503, "SIGNED_CACHE_CONFIGURATION_INVALID") from exc
    if backend is None:
        return None
    if verifier is None:
        raise HTTPException(503, "SIGNED_CACHE_REQUIRES_TRUSTED_SOURCE")
    try:
        key_id = os.environ["ACCESSPROOF_DEMO_CACHE_KEY_ID"]
        private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(
            os.environ["ACCESSPROOF_DEMO_CACHE_PRIVATE_KEY_B64"], validate=True,
        ))
        signer = CachedAnswerManifestSigner(key_id=key_id, private_key=private)
        manifest_verifier = CachedAnswerManifestVerifier(
            tenant_id=verifier.tenant_id, trusted_keys={key_id: private.public_key()},
        )
        return SignedBackendAnswerCache(
            backend=backend,
            tenant_id=verifier.tenant_id, application_id=APPLICATION_ID,
            signer=signer, verifier=manifest_verifier,
            source_verifier=verifier, ttl_seconds=300,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(503, "SIGNED_CACHE_CONFIGURATION_INVALID") from exc


def _verified_snapshot_resources(verifier: SourceAttestationVerifier | None) -> list[RetrievedResource] | None:
    path = os.getenv("ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH", "").strip()
    if not path:
        return None
    if verifier is None or not SOURCE_ID or not APPLICATION_ID:
        raise HTTPException(503, "TRUSTED_SNAPSHOT_CONFIG_REQUIRED")
    from pathlib import Path
    try:
        return load_snapshot(
            Path(path), verifier=verifier, application_id=APPLICATION_ID,
            source_id=SOURCE_ID, max_age_seconds=240,
        )
    except SnapshotInvalid as exc:
        raise HTTPException(503, "TRUSTED_SNAPSHOT_INVALID_OR_EXPIRED") from exc


app = FastAPI(title="AccessProof Protected Enterprise RAG Demo")
app.include_router(google_login_router)
app.include_router(entra_login_router)

cached_files = []
last_refresh = 0.0


class ChatRequest(BaseModel):
    message: str


def identity_from_token(auth: str | None) -> str:
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")

    token = auth[7:]

    if token == ALICE_TOKEN:
        return ALICE_EMAIL

    if token == BOB_TOKEN:
        return BOB_EMAIL

    raise HTTPException(401, "Invalid test identity")


async def drive_get(client, url, **kwargs):
    headers = {
        "Authorization": f"Bearer {DRIVE_TOKEN}"
    }

    try:
        r = await client.get(url, headers=headers, **kwargs)
        r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            raise HTTPException(
                503,
                "GOOGLE_DRIVE_TOKEN_EXPIRED_OR_INVALID",
            ) from exc
        raise HTTPException(502, "GOOGLE_DRIVE_API_ERROR") from exc
    except httpx.RequestError as exc:
        raise HTTPException(503, "GOOGLE_DRIVE_UNAVAILABLE") from exc
    return r


async def refresh_cache():
    """Scan only the configured sandbox root; recurse with pagination.

    This is a deliberately small text-only demo index, NOT an enterprise
    document ingestion engine. Guard is the authority for protected requests.
    """
    global cached_files, last_refresh

    result = []
    folders = [ROOT_FOLDER_ID]
    visited = set()
    max_files = 200
    max_content_bytes = 128_000

    async with httpx.AsyncClient(timeout=20) as client:
        while folders and len(result) < max_files:
            folder_id = folders.pop(0)
            if folder_id in visited:
                continue
            visited.add(folder_id)
            page_token = None
            while len(result) < max_files:
                params = {
                    "q": f"'{folder_id}' in parents and trashed=false",
                    "fields": "nextPageToken,files(id,name,mimeType)",
                    "pageSize": 100,
                    "supportsAllDrives": "true",
                    "includeItemsFromAllDrives": "true",
                }
                if page_token:
                    params["pageToken"] = page_token
                listing = (await drive_get(
                    client, "https://www.googleapis.com/drive/v3/files", params=params
                )).json()
                for file in listing.get("files", []):
                    file_id = str(file["id"])
                    mime = str(file.get("mimeType") or "")
                    if mime == "application/vnd.google-apps.folder":
                        folders.append(file_id)
                        continue
                    if len(result) >= max_files:
                        break
                    # Native Docs require export; binary and other native
                    # formats aren't indexed by this small text-only demo.
                    if mime == "application/vnd.google-apps.document":
                        content_response = await drive_get(
                            client,
                            f"https://www.googleapis.com/drive/v3/files/{file_id}/export",
                            params={"mimeType": "text/plain"},
                        )
                    elif mime.startswith("text/"):
                        content_response = await drive_get(
                            client,
                            f"https://www.googleapis.com/drive/v3/files/{file_id}",
                            params={"alt": "media", "supportsAllDrives": "true"},
                        )
                    else:
                        continue
                    if len(content_response.content) > max_content_bytes:
                        continue

                    allowed = set()
                    permissions_token = None
                    while True:
                        permission_params = {
                            "fields": "nextPageToken,permissions(emailAddress,type,role)",
                            "supportsAllDrives": "true",
                            "pageSize": 100,
                        }
                        if permissions_token:
                            permission_params["pageToken"] = permissions_token
                        perm_data = (await drive_get(
                            client,
                            f"https://www.googleapis.com/drive/v3/files/{file_id}/permissions",
                            params=permission_params,
                        )).json()
                        for permission in perm_data.get("permissions", []):
                            email = permission.get("emailAddress")
                            if email:
                                allowed.add(str(email).lower())
                        permissions_token = perm_data.get("nextPageToken")
                        if not permissions_token:
                            break
                    result.append({
                        "id": file_id,
                        "name": str(file.get("name") or file_id),
                        "content": content_response.text,
                        "allowed": allowed,
                    })
                page_token = listing.get("nextPageToken")
                if not page_token:
                    break

    cached_files = result
    last_refresh = time.monotonic()


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "cached_files": len(cached_files),
        "acl_cache_seconds": CACHE_SECONDS,
    }


@app.get("/health/ready")
async def ready():
    """Strict Protect readiness, independent of the development /health."""
    if not GUARD_URL or not SOURCE_ID or not APPLICATION_ID:
        raise HTTPException(503, "GUARD_INTEGRATION_NOT_CONFIGURED")
    if os.getenv("ACCESSPROOF_ENV") == "production" and not os.getenv(
        "ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH"
    ):
        raise HTTPException(503, "CERTIFIED_SOURCE_INGESTION_REQUIRED")
    verifier = _source_attestation_verifier()
    source_resources = await asyncio.to_thread(_verified_snapshot_resources, verifier)
    if os.getenv("ACCESSPROOF_ENV") == "production" and not source_resources:
        raise HTTPException(503, "CERTIFIED_SOURCE_INGESTION_REQUIRED")
    client = GuardClient(GUARD_URL)
    try:
        status = await asyncio.to_thread(client.health)
    except Exception as exc:
        raise HTTPException(503, "GUARD_NOT_READY") from exc
    finally:
        client.close()
    if status.get("status") != "ok" or status.get("ready") is not True:
        raise HTTPException(503, "GUARD_NOT_READY")
    if (os.getenv("ACCESSPROOF_DEMO_CACHE_BACKEND") or
            os.getenv("ACCESSPROOF_DEMO_CACHE_URL") or
            os.getenv("ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL") or
            os.getenv("ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST")):
        cache = _signed_redis_cache(verifier)
        if cache is None:
            raise HTTPException(503, "SIGNED_CACHE_CONFIGURATION_INVALID")
        try:
            if not await asyncio.to_thread(cache.redis.ping):
                raise ValueError("Configured cache unavailable")
        except Exception as exc:
            raise HTTPException(503, "SIGNED_CACHE_UNAVAILABLE") from exc
    return {"status": "ok", "ready": True,
            "trusted_source_resources": len(source_resources or [])}


@app.post("/v1/chat")
async def chat(
    payload: ChatRequest,
    authorization: str | None = Header(default=None),
):
    global last_refresh
    if not ALLOW_LEGACY:
        raise HTTPException(404, "LEGACY_DEMO_DISABLED")

    user = identity_from_token(authorization)

    now = time.monotonic()

    # This intentionally simulates a RAG ACL/index cache.
    if not cached_files or now - last_refresh >= CACHE_SECONDS:
        await refresh_cache()

    accessible = [
        doc for doc in cached_files
        if user in doc["allowed"]
    ]

    if not accessible:
        return {
            "answer": "I do not have access to that information.",
            "citations": [],
            "retrieved_documents": [],
            "tool_outputs": [],
        }

    doc = accessible[0]

    return {
        "answer": f"Based on the retrieved document: {doc['content']}",
        "citations": [doc["id"]],
        "retrieved_documents": [
            {
                "id": doc["id"],
                "content": doc["content"],
            }
        ],
        "tool_outputs": [],
    }


@app.post("/v1/protected-chat")
async def protected_chat(
    payload: ChatRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Real Guard data-plane demonstration using a deterministic generator.

    The legacy /v1/chat endpoint deliberately simulates a stale ACL cache,
    and does NOT exercise Guard enforcement. This endpoint does: every source
    document passes Layer 1 before its content can reach the generator, and
    the result is buffered until Layer 2 accepts trusted provenance.

    The customer must provide an actual OIDC/JWKS-verifiable employee JWT.
    The legacy Alice/Bob simulation tokens are not accepted by Guard.
    """
    if not GUARD_URL or not SOURCE_ID or not APPLICATION_ID:
        raise HTTPException(503, "GUARD_INTEGRATION_NOT_CONFIGURED")
    source_provider = os.getenv("ACCESSPROOF_DEMO_SOURCE_PROVIDER", "google").lower()
    # Browser sessions never send an identity selector in place of an actual
    # Entra/Google signed token. Only one configured OIDC provider is active.
    if authorization is None:
        session_jwt = (entra_session_token(request) if source_provider == "microsoft365"
                       else google_session_token(request) if source_provider == "google"
                       else None)
        if session_jwt is not None:
            authorization = f"Bearer {session_jwt}"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "VERIFIED_EMPLOYEE_TOKEN_REQUIRED")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "VERIFIED_EMPLOYEE_TOKEN_REQUIRED")
    # SharePoint mode may never silently use the Google Drive legacy fetcher,
    # simulated ACL data, or unsigned/expired local files. Entra login alone
    # grants no document permissions: trusted source bytes plus Guard required.
    if source_provider == "microsoft365" and (
        os.getenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT") != "1"
        or not os.getenv("ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH", "").strip()
    ):
        raise HTTPException(503, "SHAREPOINT_SIGNED_SOURCE_REQUIRED")
    verifier = _source_attestation_verifier()
    answer_cache = _signed_redis_cache(verifier)
    if answer_cache is not None:
        try:
            hit = await asyncio.to_thread(answer_cache.load, payload.message)
            if hit is not None:
                manifest, signature = hit
                guard = GuardClient(GUARD_URL)
                try:
                    checked = await asyncio.to_thread(
                        ProtectedRAG(guard, provenance_verifier=verifier).verify_cached_answer,
                        employee_token=token, application_id=APPLICATION_ID,
                        manifest=manifest, manifest_token=signature,
                        manifest_verifier=answer_cache.verifier,
                    )
                finally:
                    guard.close()
                if checked.decision != "allow" or checked.response is None:
                    # Never regenerate after an invalid/stale/revoked cache hit;
                    # do not return any of its previously generated text.
                    raise HTTPException(403, "CACHED_ANSWER_NOT_AUTHORIZED")
                return {
                    "answer": checked.response,
                    "citations": [dep.resource_id for dep in manifest.dependencies],
                    "retrieved_documents": [], "tool_outputs": [],
                    "decision": "allow", "cache_hit": True,
                    "provenance_level": checked.provenance_level,
                    "certification_eligible": checked.certification_eligible,
                }
        except CacheIntegrityError as exc:
            raise HTTPException(503, "SIGNED_CACHE_ENTRY_INVALID") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, "SIGNED_CACHE_UNAVAILABLE") from exc
    # File I/O and Ed25519 validation are bounded but CPU-intensive; never
    # serialize concurrent RAG requests on the ASGI event loop.
    snapshot_resources = await asyncio.to_thread(_verified_snapshot_resources, verifier)
    if snapshot_resources is not None:
        # This mode never accesses the demo's untrusted legacy Drive fetcher.
        # All retrieved bytes originate from the independent signed ingestion
        # volume and are verified against the pinned customer public key.
        resources = snapshot_resources
    else:
        # Metadata-only legacy retrieval is development-only and never allowed
        # in Microsoft/SharePoint mode, including during local demonstrations.
        if source_provider == "microsoft365":
            raise HTTPException(503, "SHAREPOINT_SIGNED_SOURCE_REQUIRED")
        # A production release must not silently downgrade signed-ingestion.
        if os.getenv("ACCESSPROOF_ENV") == "production":
            raise HTTPException(503, "CERTIFIED_SOURCE_INGESTION_REQUIRED")
        if not cached_files or time.monotonic() - last_refresh >= CACHE_SECONDS:
            await refresh_cache()
        resources = [
        RetrievedResource(
            source_id=SOURCE_ID,
            resource_id=str(doc["id"]),
            chunk_id=str(doc["chunk_id"]) if doc.get("chunk_id") is not None else None,
            content=str(doc["content"]),
            content_version=str(doc["content_version"])
            if doc.get("content_version") is not None else None,
            content_attestation=str(doc["content_attestation"])
            if doc.get("content_attestation") is not None else None,
        )
        for doc in cached_files
        ]
    if not resources:
        return {"answer": "No indexed test documents.", "citations": [],
                "retrieved_documents": [], "tool_outputs": []}

    authorized: list[RetrievedResource] = []

    def generate(allowed: list[RetrievedResource]) -> str:
        # Deterministic stand-in for an LLM; no content is passed to generation
        # until Layer 1 grants its resource. Never pass cached_files directly.
        authorized.extend(allowed)
        return "Based on the authorized documents: " + "\n".join(
            item.content for item in allowed
        )

    client = GuardClient(GUARD_URL)
    try:
        result = await asyncio.to_thread(
            ProtectedRAG(
                client, provenance_verifier=verifier,
                # Production already refuses the metadata-only branch below;
                # local demo mode remains explicitly non-certified.
                allow_unattested_metadata=verifier is None,
            ).run,
            employee_token=token,
            application_id=APPLICATION_ID,
            retrieved=resources,
            generate=generate,
            # This reference route feeds only `authorized` to its generator;
            # the actual application-owned lineage is recorded during generation.
            source_trace=lambda: list(authorized),
        )
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        # Never fall back to the legacy RAG path on a Guard failure.
        raise HTTPException(503, "ACCESSPROOF_GUARD_UNAVAILABLE_OR_INVALID") from exc
    finally:
        client.close()

    # The SDK intentionally converts transport/adapter exceptions into a
    # safe-deny result. Preserve a distinct 503 for operational Guard outages
    # instead of misreporting infrastructure failure as user permission denial.
    if result.reason in {"GUARD_REQUEST_FAILED", "PROTECTION_PIPELINE_FAILED"}:
        raise HTTPException(503, "ACCESSPROOF_GUARD_UNAVAILABLE_OR_INVALID")
    if result.response is None:
        return {"answer": "I do not have access to that information.",
                "citations": [], "retrieved_documents": [], "tool_outputs": [],
                "decision": result.decision}
    if answer_cache is not None and result.decision == "allow":
        try:
            await asyncio.to_thread(
                answer_cache.store, payload.message, result.response, authorized,
                authorization_revision=result.authorization_revision,
                authorization_revision_hash=result.authorization_revision_hash,
            )
        except Exception as exc:
            raise HTTPException(503, "SIGNED_CACHE_WRITE_FAILED") from exc
    return {
        "answer": result.response,
        "cache_hit": False,
        "citations": [item.resource_id for item in authorized],
        "retrieved_documents": [
            {"id": item.resource_id, "content": item.content} for item in authorized
        ],
        "tool_outputs": [],
        "decision": result.decision,
        "shadow_only": result.decision.startswith("would_"),
        "provenance_level": result.provenance_level,
        "certification_eligible": result.certification_eligible,
    }


@app.post("/v1/protected-chat/stream")
async def protected_chat_stream(
    payload: ChatRequest,
    request: Request,
    authorization: str | None = Header(default=None),
) -> StreamingResponse:
    """SSE response bytes are produced only AFTER both Guard layers finish.

    Important: this makes THIS exact demo route buffered and gated. It does
    not automatically protect arbitrary customer WebSocket/tool/chat paths.
    """
    completed = await protected_chat(payload, request=request, authorization=authorization)
    answer = completed.get("answer", "")
    # Never stream arbitrary raw model text as SSE control fields: JSON
    # escapes newlines and prevents 'event:'/'data:' injection from content.
    def emit():
        for offset in range(0, len(answer), 2048):
            fragment = answer[offset:offset + 2048]
            yield f"event: token\ndata: {json.dumps(fragment)}\n\n"
        yield "event: complete\ndata: {}\n\n"

    return StreamingResponse(
        emit(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        },
    )


@app.get('/demo', response_class=HTMLResponse, include_in_schema=False)
def google_employee_demo() -> HTMLResponse:
    """Single-user browser test panel; all Google tokens stay in server memory."""
    page = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AccessProof | Google employee RAG demo</title>
<style>
body{font:16px system-ui,Arial,sans-serif;max-width:740px;margin:45px auto;padding:20px;color:#182230}
h1{font-size:29px}p{line-height:1.55;color:#415064}button,a.login{border:0;background:#183c67;color:#fff;padding:12px 16px;border-radius:7px;cursor:pointer;display:inline-block;text-decoration:none}input{width:96%;padding:12px;border:1px solid #aab9c6;border-radius:5px;margin:12px 0}pre{background:#edf3f9;padding:18px;white-space:pre-wrap;overflow-wrap:anywhere;min-height:100px;border-radius:8px}.small{font-size:13px}</style>
</head><body><h1>AccessProof: Google employee RAG</h1>
<p>Sign in with a managed Google Cloud Identity / Workspace employee to test access to documents in the protected RAG route. Use synthetic confidential documents only.</p>
<a class="login" href="/v1/auth/google/start">Sign in with Google</a>
<button id="logout" type="button">Log out</button><p id="identity">Checking login…</p>
<label for="question">Question to the protected RAG</label>
<input id="question" placeholder="What do the confidential documents say?" value="What do the documents say?">
<button id="send" type="button">Ask protected RAG</button>
<h2>Guard result</h2><pre id="output">No request yet.</pre>
<p class="small">This controlled demo does not establish enterprise certification. Guard blocks unauthorized and stale retrieval only when its source synchronization, identity mapping and protection bindings are healthy.</p>
<script>
const $=id=>document.getElementById(id);
async function me(){try{const r=await fetch('/v1/auth/google/me',{credentials:'same-origin',cache:'no-store'});const j=await r.json();$('identity').textContent=r.ok?'Signed in as '+j.email:'Not signed in';}catch(e){$('identity').textContent='Session unavailable';}}
$('send').addEventListener('click',async()=>{ $('output').textContent='Checking Guard…'; try{const r=await fetch('/v1/protected-chat',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:$('question').value})});const j=await r.json();$('output').textContent=JSON.stringify({http_status:r.status,...j},null,2);}catch(e){$('output').textContent='Protected RAG is unavailable';}});
$('logout').addEventListener('click',async()=>{await fetch('/v1/auth/google/logout',{method:'POST',credentials:'same-origin'});await me();$('output').textContent='Logged out.';});me();
</script></body></html>'''
    return HTMLResponse(
        page,
        headers={
            'Cache-Control': 'no-store',
            'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; "
                                       "style-src 'unsafe-inline'; connect-src 'self'; "
                                       "base-uri 'none'; form-action 'self'",
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
        },
    )


@app.get('/demo/entra', response_class=HTMLResponse, include_in_schema=False)
def entra_employee_demo() -> HTMLResponse:
    """Real Microsoft login switcher; roles are hints, never trusted policy."""
    if os.getenv("ACCESSPROOF_DEMO_SOURCE_PROVIDER", "google").lower() != "microsoft365":
        raise HTTPException(503, "MICROSOFT_DEMO_SOURCE_PROVIDER_NOT_SELECTED")
    page = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AccessProof | Microsoft Entra RAG validation</title>
<style>
body{background:#f4f7fb;font:16px system-ui,Arial,sans-serif;color:#102640;max-width:850px;margin:40px auto;padding:22px}
main{background:white;padding:28px;border-radius:14px;box-shadow:0 3px 20px #b3c1d444}
h1{font-size:29px}.desc{line-height:1.5;color:#405671}button,a.switch{border:0;border-radius:8px;cursor:pointer;padding:13px 16px;background:#1352a1;color:white;text-decoration:none;display:inline-block;margin:5px 10px 8px 0;font-weight:600}button.secondary{background:#44556c}
input{width:94%;padding:14px;border:1px solid #a7b9cf;border-radius:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;min-height:110px;background:#e9f2fc;padding:17px;border-radius:8px}.small{font-size:13px;color:#576881}
</style></head><body><main><h1>AccessProof · SharePoint employee RAG</h1>
<p class="desc">Choose a test identity. Each switch sends you through Microsoft Entra sign-in, which independently verifies who you are. A dropdown alone cannot impersonate another employee.</p>
<a class="switch" href="/v1/auth/entra/start?as_user=alice">Sign in / switch to Alice</a>
<a class="switch" href="/v1/auth/entra/start?as_user=bob">Sign in / switch to Bob</a>
<button class="secondary" id="logout">Log out</button>
<p id="identity">Checking your verified identity…</p>
<label for="question"><strong>Ask protected RAG</strong></label>
<p><input id="question" placeholder="What does the finance document say?" value="What information can I access?"></p>
<button id="ask">Ask as signed-in employee</button>
<h2>AccessProof Guard decision</h2><pre id="result">No request yet.</pre>
<p class="small">Only verified identities and live source authorization can establish a permission result. This interface is a security test demonstration, not an automatic SharePoint Protect certification.</p>
<script>
const $=id=>document.getElementById(id);
async function me(){try{let r=await fetch('/v1/auth/entra/me',{credentials:'same-origin',cache:'no-store'});let d=await r.json();$('identity').textContent=r.ok?'Microsoft Entra employee: '+d.email:'Not authenticated. Choose Alice or Bob above.';}catch(e){$('identity').textContent='Identity service unavailable';}}
$('ask').addEventListener('click',async()=>{ $('result').textContent='Checking signed identity and Guard…';try{let r=await fetch('/v1/protected-chat',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:$('question').value})});let d=await r.json();$('result').textContent=JSON.stringify({http_status:r.status,...d},null,2);}catch(e){$('result').textContent='Protected RAG unavailable';}});
$('logout').addEventListener('click',async()=>{await fetch('/v1/auth/entra/logout',{method:'POST',credentials:'same-origin'});$('result').textContent='Logged out';await me();});me();
</script></main></body></html>'''
    return HTMLResponse(page, headers={
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; "
                                   "style-src 'unsafe-inline'; connect-src 'self'; "
                                   "base-uri 'none'; form-action 'self'",
    })
