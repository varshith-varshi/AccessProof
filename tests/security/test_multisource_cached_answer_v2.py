"""Signed mixed-provider cache hits must never bypass live source authorization."""
from __future__ import annotations

import hashlib

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.rag_core import (
    CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner,
    CachedAnswerManifestVerifier, ContentBinding, GuardClient, ProtectedRAG,
    SourceAttestationSigner, SourceAttestationVerifier,
)
from tests.security.test_multisource_guard_v2 import (
    APP, DOC, GOOGLE, SHAREPOINT, _ready, _token,
)


def _cached_fixture(tenant: str = "tenant-a"):
    issuer_keys = {source: Ed25519PrivateKey.generate() for source in (GOOGLE, SHAREPOINT)}
    dependencies = []
    for source in (GOOGLE, SHAREPOINT):
        content = "SYNTHETIC_CONFIDENTIAL_" + source
        binding = ContentBinding(
            tenant_id=tenant, application_id=APP, source_id=source,
            resource_id=DOC, chunk_id=source + "-chunk", content_version="etag1",
            content=content,
        )
        dependencies.append(CacheDependency(
            source_id=source, resource_id=DOC, chunk_id=source + "-chunk",
            content_version="etag1", content_digest=hashlib.sha256(content.encode()).hexdigest(),
            content_attestation=SourceAttestationSigner(
                key_id=source, private_key=issuer_keys[source],
            ).issue(binding),
        ))
    manifest = CachedAnswerManifest(
        tenant_id=tenant, application_id=APP, answer="SYNTHETIC_MIXED_SOURCE_ANSWER",
        dependencies=tuple(dependencies), producer_id="signed-test-cache",
        authorization_revision=1, authorization_revision_hash="a" * 64,
    )
    private = Ed25519PrivateKey.generate()
    signed_manifest = CachedAnswerManifestSigner(
        key_id="trusted-cache-writer", private_key=private,
    ).issue(manifest)
    cache_verifier = CachedAnswerManifestVerifier(
        tenant_id=tenant, trusted_keys={"trusted-cache-writer": private.public_key()},
    )
    source_verifier = SourceAttestationVerifier(
        tenant_id=tenant, trusted_keys={
            source: key.public_key() for source, key in issuer_keys.items()
        },
    )
    return manifest, signed_manifest, cache_verifier, source_verifier


def test_signed_multisource_cache_hit_rechecked_for_current_employee(tmp_path, monkeypatch):
    guard_client, cache = _ready(tmp_path, monkeypatch)
    manifest, signed, cache_verifier, source_verifier = _cached_fixture()
    observed = []
    with guard_client:
        def handler(request: httpx.Request) -> httpx.Response:
            observed.append(request.url.path)
            response = guard_client.request(
                request.method, request.url.path,
                content=request.content,
                headers={"Authorization": request.headers.get("Authorization", ""), "Content-Type": request.headers.get("Content-Type", "")},
            )
            return httpx.Response(response.status_code, content=response.content)

        guarded_http = httpx.Client(transport=httpx.MockTransport(handler))
        guard = GuardClient("https://guard.synthetic", client=guarded_http, multisource=True)
        protection = ProtectedRAG(guard, provenance_verifier=source_verifier)

        def query(user):
            return protection.verify_cached_answer(
                employee_token=_token(user), application_id=APP, manifest=manifest,
                manifest_token=signed, manifest_verifier=cache_verifier,
            )

        first = query("alice")
        assert first.decision == "allow", first.reason
        assert first.response == manifest.answer
        assert "/guard/v2/filter-resources" in observed
        assert "/guard/v2/check-output" in observed

        # Bob's Google grant never authorizes the same-ID SharePoint resource.
        second = query("bob")
        assert second.decision == "block"
        assert second.response is None

        # Revoke Alice's SharePoint source after cache creation.
        cache.install(2, [{
            "subject_id": "alice-m", "source_id": SHAREPOINT,
            "resource_id": DOC, "scope": "read", "decision": "deny",
        }])
        revoked = query("alice")
        assert revoked.decision == "block"
        assert revoked.response is None
        guarded_http.close()


def test_mixed_cache_manifest_requires_current_application_revision(tmp_path, monkeypatch):
    guard_client, cache = _ready(tmp_path, monkeypatch)
    manifest, signed, cache_verifier, source_verifier = _cached_fixture()
    with guard_client:
        def handler(request: httpx.Request) -> httpx.Response:
            response = guard_client.request(
                request.method, request.url.path, content=request.content,
                headers={"Authorization": request.headers.get("Authorization", ""), "Content-Type": request.headers.get("Content-Type", "")},
            )
            return httpx.Response(response.status_code, content=response.content)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        protection = ProtectedRAG(
            GuardClient("https://guard.synthetic", client=client, multisource=True),
            provenance_verifier=source_verifier,
        )
        cache.set_authorization_revisions([{
            "application_id": APP, "revision": 2, "revision_hash": "b" * 64,
            "generated_at": "2026-10-27T00:00:00Z",
        }])
        result = protection.verify_cached_answer(
            employee_token=_token("alice"), application_id=APP,
            manifest=manifest, manifest_token=signed, manifest_verifier=cache_verifier,
        )
        assert result.decision == "block"
        assert result.reason == "CACHE_AUTHORIZATION_REVISION_STALE"
        client.close()
