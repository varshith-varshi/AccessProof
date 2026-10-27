"""Provider-neutral Gateway: two independently signed sources, one Guard."""
from __future__ import annotations

import json
import time
from pathlib import Path

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


TENANT = "tenant-example"
APP = "protected-enterprise-rag"
GOOGLE = "google-drive-test-source"
SHAREPOINT = "microsoft365-sharepoint-test-source"
DOC1 = "SYNTHETIC_SHARED_DRIVE_CANARY"
DOC2 = "SYNTHETIC_PRIVATE_SHAREPOINT_CANARY"


def _test_gateway(tmp_path: Path):
    google_key, sharepoint_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    paths = {}
    for source, key, doc_id, content in (
        (GOOGLE, google_key, "drive-document", DOC1),
        (SHAREPOINT, sharepoint_key, "sharepoint-document", DOC2),
    ):
        signer = TrustedSourceIngestor(SourceAttestationSigner(
            key_id=source + "-signer", private_key=key,
        ))
        resources = signer.attest_document(VerifiedSourceDocument(
            tenant_id=TENANT, application_id=APP, source_id=source,
            resource_id=doc_id, content_version="etag-1", content=content,
            provider_identity_verified=True,
        ))
        path = tmp_path / (source + ".json")
        write_snapshot(path, tenant_id=TENANT, application_id=APP,
                       source_id=source, resources=resources)
        paths[source] = path
    observed = {"requests": [], "model_calls": [], "revoke": False, "all_denied": False}

    def respond(request: httpx.Request) -> httpx.Response:
        observed["requests"].append(request)
        path = request.url.path
        if path.endswith("/filter-resources"):
            payload = json.loads(request.content)
            employee = request.headers.get("Authorization", "")
            allowed = []
            for item in payload["resources"]:
                if observed["all_denied"]:
                    continue
                if item["source_id"] == GOOGLE or employee == "Bearer alice":
                    allowed.append({
                        "source_id": item["source_id"],
                        "resource_id": item["resource_id"],
                        "chunk_ids": item.get("chunk_ids", []),
                    })
            return httpx.Response(200, json={
                "decision_id": "test-decision", "decision": "allow" if allowed else "block",
                "mode": "protect", "allowed": allowed,
            })
        if path.endswith("/check-output"):
            return httpx.Response(200, json={
                "decision": "block" if observed["revoke"] else "allow",
                "reason": "SOURCE_REVOKED" if observed["revoke"] else "VALID",
            })
        if path == "/v1/chat/completions":
            body = json.loads(request.content)
            observed["model_calls"].append(body)
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "MODEL_AUTHORIZED_TEST_ANSWER"},
                             "finish_reason": "stop"}],
            })
        raise AssertionError("Unexpected external call: " + path)

    settings = GatewaySettings(
        guard_url="https://guard.example", model_url="https://model.example/v1/chat/completions",
        application_id=APP, tenant_id=TENANT,
        verifier=SourceAttestationVerifier(tenant_id=TENANT, trusted_keys={
            GOOGLE + "-signer": google_key.public_key(),
            SHAREPOINT + "-signer": sharepoint_key.public_key(),
        }),
        source_snapshots=paths,
    )
    gateway = TestClient(create_app(settings, client=httpx.Client(transport=httpx.MockTransport(respond))))
    return gateway, observed, paths


def _call(gateway: TestClient, employee: str, *, source_ids=None, stream=False):
    return gateway.post("/v1/snapshots/chat/completions", headers={
        "Authorization": "Bearer " + employee,
    }, json={
        "application_id": APP, "employee_question": "What can I access?",
        "source_ids": source_ids if source_ids is not None else [GOOGLE],
        "stream": stream,
    })


def test_one_gateway_code_accepts_each_signed_provider_but_enforces_per_user(tmp_path):
    gateway, seen, _paths = _test_gateway(tmp_path)
    with gateway:
        alice = _call(gateway, "alice", source_ids=[SHAREPOINT])
        assert alice.status_code == 200, alice.text
        assert alice.headers["cache-control"] == "no-store"
        assert alice.headers["vary"] == "Authorization, Cookie"
        assert DOC2 in json.dumps(seen["model_calls"][-1])
        assert DOC1 not in json.dumps(seen["model_calls"][-1])
        bob = _call(gateway, "bob", source_ids=[GOOGLE])
        assert bob.status_code == 200, bob.text
        assert DOC1 in json.dumps(seen["model_calls"][-1])
        assert DOC2 not in json.dumps(seen["model_calls"][-1])
        assert DOC2 not in bob.text


def test_provider_neutral_gateway_never_generates_on_total_denial(tmp_path):
    gateway, seen, _ = _test_gateway(tmp_path)
    seen["all_denied"] = True
    with gateway:
        resp = _call(gateway, "bob")
        assert resp.status_code == 403
        assert DOC1 not in resp.text and DOC2 not in resp.text
        assert not seen["model_calls"]


def test_multisource_gateway_blocks_inflight_revoke_even_for_stream(tmp_path):
    gateway, seen, _ = _test_gateway(tmp_path)
    seen["revoke"] = True
    with gateway:
        resp = _call(gateway, "alice", stream=True)
        assert resp.status_code in {403, 503}
        assert "MODEL_AUTHORIZED_TEST_ANSWER" not in resp.text
        assert "data: " not in resp.text
        assert len(seen["model_calls"]) == 1
        seen["revoke"] = False
        allowed = _call(gateway, "alice", stream=True)
        assert allowed.status_code == 200
        assert allowed.headers["cache-control"] == "no-store"
        assert "data: [DONE]" in allowed.text


def test_multisource_gateway_rejects_unknown_duplicate_or_unsigned_source(tmp_path):
    gateway, seen, paths = _test_gateway(tmp_path)
    with gateway:
        no_token = gateway.post("/v1/snapshots/chat/completions", json={
            "application_id": APP, "employee_question": "x", "source_ids": [GOOGLE],
        })
        assert no_token.status_code == 401
        unknown = _call(gateway, "alice", source_ids=["unapproved-folder"])
        assert unknown.status_code == 403
        dup = _call(gateway, "alice", source_ids=[GOOGLE, GOOGLE])
        assert dup.status_code == 422
        # Mixed requests require V2 Guard authorization (no V1 fallback).
        mixed = _call(gateway, "alice", source_ids=[GOOGLE, SHAREPOINT])
        assert mixed.status_code == 200
        assert DOC1 in json.dumps(seen["model_calls"][-1])
        assert DOC2 in json.dumps(seen["model_calls"][-1])
        assert any(request.url.path == "/guard/v2/filter-resources" for request in seen["requests"])
        assert any(request.url.path == "/guard/v2/check-output" for request in seen["requests"])
        # Signed source data was altered after ingestion.
        count_before_tamper = len(seen["model_calls"])
        original = paths[SHAREPOINT].read_text()
        paths[SHAREPOINT].write_text(original.replace(DOC2, "FORGED_SHAREPOINT_CANARY"))
        tampered = _call(gateway, "alice", source_ids=[SHAREPOINT])
        assert tampered.status_code == 503
        assert DOC2 not in tampered.text
        assert len(seen["model_calls"]) == count_before_tamper


def test_multisource_gateway_fails_closed_on_stale_snapshot(tmp_path):
    gateway, seen, paths = _test_gateway(tmp_path)
    path = paths[GOOGLE]
    data = json.loads(path.read_text())
    data["generated_at"] = int(time.time()) - 500
    path.write_text(json.dumps(data))
    with gateway:
        resp = _call(gateway, "alice")
        assert resp.status_code == 503
        assert not seen["model_calls"]


def test_gateway_snapshot_source_config_rejects_untrusted_paths(tmp_path):
    signing = Ed25519PrivateKey.generate()
    base = dict(
        guard_url="https://guard.example", model_url="https://model.example/v1/chat/completions",
        application_id=APP, tenant_id=TENANT,
        verifier=SourceAttestationVerifier(tenant_id=TENANT, trusted_keys={
            "key": signing.public_key(),
        }),
    )
    for paths in (
        {"source": Path("relative-file.json")},
        {"source": Path("/tmp/a/../unsafe")},
        {"unsafe/source": tmp_path / "signed.json"},
        {"source-a": tmp_path / "one.json", "source-b": tmp_path / "one.json"},
        {str(i): tmp_path / f"{i}.json" for i in range(5)},
    ):
        with pytest.raises(ValueError, match="Gateway source|Too many configured"):
            GatewaySettings(**base, source_snapshots=paths)

def test_multisource_gateway_blocks_untracked_conversation(tmp_path):
    gateway, seen, _paths = _test_gateway(tmp_path)
    with gateway:
        response = gateway.post("/v1/snapshots/chat/completions", headers={
            "Authorization": "Bearer alice",
        }, json={
            "application_id": APP,
            "employee_question": "Can you repeat earlier details?",
            "source_ids": [GOOGLE, SHAREPOINT],
            "employee_conversation": [{"role": "user", "content": "Prior restricted source text"}],
        })
        assert response.status_code == 422
        assert not seen["model_calls"]
