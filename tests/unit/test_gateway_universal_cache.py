"""Generic HTTP cached-answer release for Redis/Memcached/SQL/custom caches."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from packages.rag_core import (
    CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner,
    CachedAnswerManifestVerifier, ContentBinding, SourceAttestationSigner,
    SourceAttestationVerifier,
)


def _reference(*, access_allowed: bool = True, include_cache_key: bool = True):
    signing = Ed25519PrivateKey.generate()
    source_signing = Ed25519PrivateKey.generate()
    state = {"allowed": access_allowed, "seen": []}

    def mock(request: httpx.Request) -> httpx.Response:
        state["seen"].append(request.url.path)
        if request.url.path.endswith("/filter-resources"):
            payload = json.loads(request.content)
            return httpx.Response(200, json={
                "mode": "protect", "decision": "allow" if state["allowed"] else "block",
                "decision_id": "decision-1", "allowed": ([{
                    "source_id": dep["source_id"],
                    "resource_id": dep["resource_id"],
                    "chunk_ids": dep.get("chunk_ids", []),
                } for dep in payload["resources"]] if state["allowed"] else []),
            })
        if request.url.path.endswith("/check-output"):
            return httpx.Response(200, json={
                "decision": "allow" if state["allowed"] else "block",
                "reason": "TEST",
            })
        raise AssertionError("Model must not be invoked by cached-answer verification")

    client = httpx.Client(transport=httpx.MockTransport(mock))
    keys = {"cache-signing": signing.public_key()}
    settings = GatewaySettings(
        guard_url="https://guard.synthetic", model_url="https://model.synthetic/v1/chat/completions",
        tenant_id="tenant-a", application_id="app-a",
        verifier=SourceAttestationVerifier(
            tenant_id="tenant-a", trusted_keys={"source-signing": source_signing.public_key()},
        ),
        cache_verifier=(CachedAnswerManifestVerifier(
            tenant_id="tenant-a", trusted_keys=keys,
        ) if include_cache_key else None),
    )
    source_binding = ContentBinding(
        "tenant-a", "app-a", "source-a", "document-a", "chunk-a",
        "1", "approved confidential text",
    )
    source_token = SourceAttestationSigner(
        key_id="source-signing", private_key=source_signing,
    ).issue(source_binding)
    dependency = CacheDependency(
        source_id="source-a", resource_id="document-a", chunk_id="chunk-a",
        content_version="1",
        content_digest=hashlib.sha256(source_binding.content.encode()).hexdigest(),
        content_attestation=source_token,
    )
    manifest = CachedAnswerManifest(
        tenant_id="tenant-a", application_id="app-a", answer="signed cached answer",
        dependencies=(dependency,), producer_id="customer-owned-rag",
    )
    token = CachedAnswerManifestSigner(
        key_id="cache-signing", private_key=signing,
    ).issue(manifest)
    payload = {
        "tenant_id": "tenant-a", "application_id": "app-a",
        "answer": manifest.answer, "producer_id": manifest.producer_id,
        "dependencies": [asdict(dependency)], "manifest_token": token,
    }
    return TestClient(create_app(settings, client=client)), payload, state


def test_generic_http_cache_authorization_allows_then_denies_after_revoke():
    client, payload, state = _reference()
    with client:
        headers = {"Authorization": "Bearer synthetic-employee-token"}
        allow = client.post("/v1/cache/authorize", headers=headers, json=payload)
        assert allow.status_code == 200, allow.text
        assert allow.json()["answer"] == "signed cached answer"
        assert allow.json()["citations"] == ["document-a"]
        assert len(state["seen"]) == 2
        state["allowed"] = False
        denied = client.post("/v1/cache/authorize", headers=headers, json=payload)
        assert denied.status_code == 403
        assert "signed cached answer" not in denied.text
        assert len(state["seen"]) == 3


def test_generic_http_cache_rejects_invalid_signatures_and_tenant_confusion():
    client, payload, state = _reference()
    with client:
        headers = {"Authorization": "Bearer synthetic-employee-token"}
        for overrides in (
            {"answer": "forged answer"},
            {"application_id": "app-other"},
            {"tenant_id": "tenant-other"},
            {"manifest_token": "badtoken"},
            {"dependencies": [{**payload["dependencies"][0], "resource_id": "other-doc"}]},
        ):
            reply = client.post("/v1/cache/authorize", headers=headers,
                                json={**payload, **overrides})
            assert reply.status_code in {403, 422}
            assert "signed cached answer" not in reply.text
        assert state["seen"] == []


def test_generic_http_cache_no_trusted_key_is_fail_closed():
    client, payload, state = _reference(include_cache_key=False)
    with client:
        assert client.post("/v1/cache/authorize", headers={
            "Authorization": "Bearer fake-employee",
        }, json=payload).status_code == 503
        assert not state["seen"]


def test_generic_http_cache_missing_employee_token_is_denied_without_processing():
    client, payload, state = _reference()
    with client:
        denied = client.post("/v1/cache/authorize", json=payload)
        assert denied.status_code == 401
        assert not state["seen"]


def test_generic_http_cache_refuses_unsourced_or_untrusted_body_fields():
    client, payload, state = _reference()
    with client:
        for malformed in (
            {**payload, "dependencies": []},
            {**payload, "unverified_context": "secret"},
            {**payload, "dependencies": [{**payload["dependencies"][0], "cached_admin_override": True}]},
        ):
            reply = client.post("/v1/cache/authorize", headers={
                "Authorization": "Bearer synthetic-employee",
            }, json=malformed)
            assert reply.status_code == 422
        assert not state["seen"]


def test_gateway_loads_pinned_cache_verification_keys_from_environment(monkeypatch):
    import base64
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    signer = Ed25519PrivateKey.generate()
    source = Ed25519PrivateKey.generate()
    source_public = source.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    cache_public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    required = {
        "ACCESSPROOF_GATEWAY_GUARD_URL": "https://guard.customer.internal",
        "ACCESSPROOF_GATEWAY_MODEL_URL": "https://model.customer.internal/v1/chat/completions",
        "ACCESSPROOF_GATEWAY_APPLICATION_ID": "registered-app",
        "ACCESSPROOF_GATEWAY_TENANT_ID": "customer-tenant",
        "ACCESSPROOF_GATEWAY_ATTESTATION_PUBLIC_KEYS_JSON": json.dumps({
            "ingestion": base64.urlsafe_b64encode(source_public).decode(),
        }),
        "ACCESSPROOF_GATEWAY_CACHE_PUBLIC_KEYS_JSON": json.dumps({
            "cache-key": base64.urlsafe_b64encode(cache_public).decode(),
        }),
    }
    for key, value in required.items():
        monkeypatch.setenv(key, value)
    settings = GatewaySettings.from_env()
    assert settings.cache_verifier is not None
    assert "cache-key" in settings.cache_verifier.trusted_keys
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_CACHE_PUBLIC_KEYS_JSON", '{"cache-key":"bad"}')
    with pytest.raises(RuntimeError, match="cache public key configuration invalid"):
        GatewaySettings.from_env()
