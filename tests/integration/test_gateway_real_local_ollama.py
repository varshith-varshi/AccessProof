"""Optional real LOCAL Ollama inference with actual Guard V2 authorization.

All identities, source grants and documents remain synthetic. This is not
Microsoft/Google employee validation or production certification.
"""
from __future__ import annotations

import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from packages.demo_cache.trusted_snapshot import write_snapshot
from packages.rag_core import (
    SourceAttestationSigner, SourceAttestationVerifier,
    TrustedSourceIngestor, VerifiedSourceDocument,
)
from tests.security.test_multisource_guard_v2 import (
    APP, DOC, GOOGLE, SHAREPOINT, _ready, _token,
)


@pytest.mark.parametrize("mode", ["authorized", "partial", "revoked_midstream"])
def test_real_ollama_provider_never_sees_denied_documents(
    tmp_path, monkeypatch, mode,
):
    with httpx.Client(timeout=3, trust_env=False) as probe:
        try:
            tags = probe.get("http://127.0.0.1:11434/api/tags")
            tags.raise_for_status()
            models = {m["name"] for m in tags.json()["models"]}
            if "llama3.2:3b" not in models:
                pytest.skip("No local llama3.2:3b model")
        except (httpx.HTTPError, ValueError):
            pytest.skip("Local Ollama not running")

    guard_client, policy = _ready(tmp_path, monkeypatch)
    keys = {GOOGLE: Ed25519PrivateKey.generate(),
            SHAREPOINT: Ed25519PrivateKey.generate()}
    signed = {}
    for source in (GOOGLE, SHAREPOINT):
        chunks = TrustedSourceIngestor(SourceAttestationSigner(
            key_id=source, private_key=keys[source],
        )).attest_document(VerifiedSourceDocument(
            tenant_id="tenant-a", application_id=APP,
            source_id=source, resource_id=DOC,
            content_version="etag1",
            content="SYNTHETIC_PROTECTED_CANARY_FROM_" + source,
            provider_identity_verified=True,
        ))
        path = tmp_path / (source + ".json")
        write_snapshot(path, tenant_id="tenant-a", application_id=APP,
                       source_id=source, resources=chunks)
        signed[source] = path

    observed = {"model_requests": [], "guard_calls": [], "revoked": False}
    with (
        guard_client,
        httpx.Client(timeout=90, trust_env=False) as ollama,
    ):
        def dispatch(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/guard/"):
                observed["guard_calls"].append(request.url.path)
                outcome = guard_client.request(
                    request.method, request.url.path, content=request.content,
                    headers={"Authorization": request.headers.get("Authorization", ""), "Content-Type": request.headers.get("Content-Type", "")},
                )
                return httpx.Response(outcome.status_code, content=outcome.content)
            assert request.url.path == "/v1/chat/completions"
            payload = json.loads(request.content)
            observed["model_requests"].append(payload)
            # Bound local inference time/tokens without changing Gateway code.
            payload.update(max_tokens=256, temperature=0, stream=False)
            actual = ollama.post(
                "http://127.0.0.1:11434/v1/chat/completions",
                json=payload, timeout=90,
            )
            if mode == "revoked_midstream":
                policy.install(2, [{
                    "subject_id": "alice-m", "source_id": SHAREPOINT,
                    "resource_id": DOC, "decision": "deny",
                }])
                observed["revoked"] = True
            return httpx.Response(actual.status_code, content=actual.content,
                                  headers={"content-type": "application/json"})

        gateway_settings = GatewaySettings(
            guard_url="https://guard.synthetic",
            model_url="http://127.0.0.1:11434/v1/chat/completions",
            application_id=APP, tenant_id="tenant-a",
            verifier=SourceAttestationVerifier(
                tenant_id="tenant-a",
                trusted_keys={k: v.public_key() for k, v in keys.items()},
            ),
            source_snapshots=signed,
            multisource_guard_v2=True,
            model_name="llama3.2:3b",
        )
        wire = httpx.Client(transport=httpx.MockTransport(dispatch))
        with TestClient(create_app(gateway_settings, client=wire)) as gateway:
            response = gateway.post(
                "/v1/snapshots/chat/completions",
                headers={"Authorization": "Bearer " + _token(
                    "bob" if mode == "partial" else "alice",
                )},
                json={
                    "application_id": APP,
                    "employee_question":
                        "Reply with the word OK using authorized information.",
                    "source_ids": [GOOGLE, SHAREPOINT],
                    "stream": True,
                },
            )

        assert len(observed["model_requests"]) == 1
        prompt = json.dumps(observed["model_requests"][0])
        assert "SYNTHETIC_PROTECTED_CANARY_FROM_" + GOOGLE in prompt
        if mode == "partial":
            assert "SYNTHETIC_PROTECTED_CANARY_FROM_" + SHAREPOINT not in prompt
        else:
            assert "SYNTHETIC_PROTECTED_CANARY_FROM_" + SHAREPOINT in prompt

        if mode == "revoked_midstream":
            assert observed["revoked"]
            assert response.status_code in (403, 503)
            assert "data: " not in response.text
            assert "SYNTHETIC_PROTECTED_CANARY_FROM_" not in response.text
        else:
            assert response.status_code == 200, response.text[:500]
            assert "data: [DONE]" in response.text
        assert "/guard/v2/filter-resources" in observed["guard_calls"]
        assert "/guard/v2/check-output" in observed["guard_calls"]
