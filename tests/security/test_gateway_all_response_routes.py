"""Real Guard HTTP + Gateway route matrix with synthetic identities and signed canaries.

A passing result applies to the enumerated endpoints only; it does not
certify arbitrary customer middleware, caches or egress architectures.
"""
from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from packages.demo_cache.trusted_snapshot import write_snapshot
from packages.rag_core import (
    SourceAttestationSigner, SourceAttestationVerifier, TrustedSourceIngestor,
    VerifiedSourceDocument,
)
from tests.security.test_multisource_guard_v2 import (
    APP, DOC, SHAREPOINT, _ready, _token,
)
from tests.security.test_multisource_cached_answer_v2 import _cached_fixture

LEAK_MARKER = "TEST_ONLY_UNRELEASED_INFORMATION"


def _gateway(tmp_path, monkeypatch, *, outage=False, revoke_on_generation=False):
    guard_client, policy = _ready(tmp_path, monkeypatch)
    private = Ed25519PrivateKey.generate()
    src_signer = SourceAttestationSigner(key_id="source-trusted", private_key=private)
    chunk = TrustedSourceIngestor(src_signer).attest_document(
        VerifiedSourceDocument(
            tenant_id="tenant-a", application_id=APP, source_id=SHAREPOINT,
            resource_id=DOC, content_version="etag1",
            content=LEAK_MARKER, provider_identity_verified=True,
        )
    )
    signed_path = tmp_path / "sharepoint-signed.json"
    write_snapshot(
        signed_path, tenant_id="tenant-a", application_id=APP,
        source_id=SHAREPOINT, resources=chunk,
    )
    cached, cached_signature, cached_verifier, cache_source_verifier = _cached_fixture()
    keys = {
        "source-trusted": private.public_key(),
        **cache_source_verifier.trusted_keys,
    }
    observed = {"llm_count": 0, "guard_paths": [], "outage": outage,
                "revoke_on_generation": revoke_on_generation}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/guard/"):
            observed["guard_paths"].append(request.url.path)
            if observed["outage"]:
                return httpx.Response(503, json={"detail": "simulated outage"})
            with TestClient(guard_client.app) as probe:
                result = probe.request(
                    request.method, request.url.path, content=request.content,
                    headers={"Authorization": request.headers.get("Authorization", "")},
                )
                return httpx.Response(result.status_code, content=result.content)
        assert request.url.path == "/v1/chat/completions"
        observed["llm_count"] += 1
        if observed["revoke_on_generation"]:
            policy.install(2, [{
                "subject_id": "alice-m", "source_id": SHAREPOINT,
                "resource_id": DOC, "scope": "read", "decision": "deny",
            }])
        return httpx.Response(200, json={
            "choices": [{"message": {"content": LEAK_MARKER},
                         "finish_reason": "stop"}],
        })

    http = httpx.Client(transport=httpx.MockTransport(handler))
    settings = GatewaySettings(
        guard_url="https://guard.synthetic",
        model_url="https://model.synthetic/v1/chat/completions",
        application_id=APP, tenant_id="tenant-a",
        verifier=SourceAttestationVerifier(tenant_id="tenant-a", trusted_keys=keys),
        cache_verifier=cached_verifier,
        source_snapshots={SHAREPOINT: signed_path},
        multisource_guard_v2=True,
    )
    return (TestClient(create_app(settings, client=http)), policy, observed,
            chunk[0], cached, cached_signature, guard_client, http)


def _answer_body(resource, *, stream):
    return {
        "application_id": APP, "employee_question": "What is available?",
        "retrieved_resources": [{
            "source_id": resource.source_id,
            "resource_id": resource.resource_id,
            "chunk_id": resource.chunk_id,
            "content": resource.content,
            "content_version": resource.content_version,
            "content_attestation": resource.content_attestation,
        }],
        "stream": stream,
    }


def _snapshot_body(*, stream):
    return {
        "application_id": APP, "employee_question": "What is available?",
        "source_ids": [SHAREPOINT], "stream": stream,
    }


def _cached_body(cached, signature):
    return {
        "tenant_id": cached.tenant_id,
        "application_id": APP,
        "answer": cached.answer,
        "producer_id": cached.producer_id,
        "dependencies": [vars(dependency) for dependency in cached.dependencies],
        "manifest_token": signature,
        "authorization_revision": cached.authorization_revision,
        "authorization_revision_hash": cached.authorization_revision_hash,
    }


def _assert_denial(response):
    assert response.status_code in {403, 503}, response.text
    assert LEAK_MARKER not in response.text
    assert "SYNTHETIC_MIXED_SOURCE_ANSWER" not in response.text
    assert "data: " not in response.text
    assert response.headers.get("cache-control") == "no-store"


@pytest.mark.parametrize("endpoint", [
    "/v1/chat/completions",
    "/v1/snapshots/chat/completions",
])
@pytest.mark.parametrize("stream", [False, True])
def test_source_routes_guard_denial_before_model(tmp_path, monkeypatch, endpoint, stream):
    gateway, _policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    payload = (_snapshot_body(stream=stream)
               if endpoint.startswith("/v1/snapshots") else _answer_body(chunk, stream=stream))
    with gateway:
        response = gateway.post(endpoint, headers={
            "Authorization": "Bearer " + _token("bob"),
        }, json=payload)
        _assert_denial(response)
        assert observed["llm_count"] == 0
        assert "/guard/v2/filter-resources" in observed["guard_paths"]


@pytest.mark.parametrize("endpoint", [
    "/v1/chat/completions",
    "/v1/snapshots/chat/completions",
])
@pytest.mark.parametrize("stream", [False, True])
def test_source_routes_do_not_stream_after_mid_generation_revocation(
    tmp_path, monkeypatch, endpoint, stream,
):
    gateway, _policy, observed, chunk, *_ = _gateway(
        tmp_path, monkeypatch, revoke_on_generation=True,
    )
    body = (_snapshot_body(stream=stream)
            if endpoint.startswith("/v1/snapshots") else _answer_body(chunk, stream=stream))
    with gateway:
        response = gateway.post(endpoint, headers={
            "Authorization": "Bearer " + _token("alice"),
        }, json=body)
        _assert_denial(response)
        assert observed["llm_count"] == 1
        assert "/guard/v2/check-output" in observed["guard_paths"]


@pytest.mark.parametrize("endpoint", [
    "/v1/cache/authorize", "/v1/responses/authorize",
])
def test_both_cache_release_aliases_fail_closed_for_bob_and_revocation(
    tmp_path, monkeypatch, endpoint,
):
    gateway, policy, observed, _chunk, cached, signature, *_ = _gateway(
        tmp_path, monkeypatch,
    )
    payload = _cached_body(cached, signature)
    with gateway:
        denied = gateway.post(endpoint, headers={
            "Authorization": "Bearer " + _token("bob"),
        }, json=payload)
        _assert_denial(denied)
        policy.install(2, [{
            "subject_id": "alice-m", "source_id": SHAREPOINT,
            "resource_id": DOC, "scope": "read", "decision": "deny",
        }])
        stale = gateway.post(endpoint, headers={
            "Authorization": "Bearer " + _token("alice"),
        }, json=payload)
        _assert_denial(stale)
        assert observed["llm_count"] == 0


@pytest.mark.parametrize("endpoint", [
    "/v1/chat/completions",
    "/v1/snapshots/chat/completions",
    "/v1/cache/authorize",
    "/v1/responses/authorize",
])
def test_all_supported_response_routes_block_when_guard_down(
    tmp_path, monkeypatch, endpoint,
):
    gateway, _, observed, chunk, cached, signature, *_ = _gateway(
        tmp_path, monkeypatch, outage=True,
    )
    payload = (_cached_body(cached, signature) if endpoint.endswith("authorize")
               else _snapshot_body(stream=True) if endpoint.startswith("/v1/snapshots")
               else _answer_body(chunk, stream=True))
    with gateway:
        response = gateway.post(endpoint, headers={
            "Authorization": "Bearer " + _token("alice"),
        }, json=payload)
        _assert_denial(response)
        assert observed["llm_count"] == 0


def test_protected_routes_are_explicit_and_unknown_alternates_not_available(
    tmp_path, monkeypatch,
):
    gateway, _, _, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        paths = {route.path for route in gateway.app.routes if hasattr(route, "path")}
        expected = {
            "/v1/chat/completions", "/v1/snapshots/chat/completions",
            "/v1/cache/authorize", "/v1/responses/authorize",
        }
        assert expected.issubset(paths)
        for route in (
            "/v1/direct-model", "/v1/uncached-chat",
            "/v1/chat/completions/stream", "/v1/tools/execute",
        ):
            assert route not in paths
            assert gateway.post(route, json={"content": LEAK_MARKER}).status_code == 404
        for protected in expected:
            response = gateway.post(protected, json={})
            assert response.status_code == 401
            assert LEAK_MARKER not in response.text
