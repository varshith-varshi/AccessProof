"""Real connected SharePoint *synthetic* content through Guard V2 and real Ollama.

Authorizations and revoke are synthetic: not delegated Entra/Graph certification.
Fixture is private local evidence and intentionally excluded from Git.
"""
import json
from pathlib import Path
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from packages.rag_core import SourceAttestationSigner, SourceAttestationVerifier, TrustedSourceIngestor, VerifiedSourceDocument
from packages.demo_cache.trusted_snapshot import write_snapshot
from tests.security.test_multisource_guard_v2 import APP, SHAREPOINT, _ready, _token

FIXTURE = Path(__file__).resolve().parents[2] / ".accessproof-runner/synthetic-sharepoint-finance-live-20261027.json"


def test_actual_sharepoint_synthetic_bytes_authorized_into_real_ollama(tmp_path, monkeypatch):
    if not FIXTURE.exists():
        pytest.skip("No opt-in connected SharePoint synthetic fixture")
    assert not FIXTURE.is_symlink() and FIXTURE.stat().st_size < 10000
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["grant_listing"] == {"alice": True, "bob": False}
    assert fixture["effective_employee_access_verified"] is False
    assert fixture["real_provider_revocation_verified"] is False
    assert "AP_ALICE_20261027_J3R8" in fixture["content"]
    with httpx.Client(timeout=3, trust_env=False) as probe:
        try:
            models = probe.get("http://127.0.0.1:11434/api/tags").json()["models"]
            if "llama3.2:3b" not in {m["name"] for m in models}:
                pytest.skip("Local Ollama model missing")
        except (httpx.HTTPError, ValueError, KeyError):
            pytest.skip("Local Ollama unavailable")
    guard_client, policy = _ready(tmp_path, monkeypatch)
    resource_id = fixture["resource_id"]
    policy.install(2, [
        {"subject_id": "alice-m", "source_id": SHAREPOINT, "resource_id": resource_id, "decision": "allow"},
        {"subject_id": "bob-m", "source_id": SHAREPOINT, "resource_id": resource_id, "decision": "deny"},
    ])
    key = Ed25519PrivateKey.generate()
    key_id = "connected-sharepoint-synthetic-test"
    chunks = TrustedSourceIngestor(SourceAttestationSigner(key_id=key_id, private_key=key)).attest_document(
        VerifiedSourceDocument(
            tenant_id="tenant-a", application_id=APP, source_id=SHAREPOINT,
            resource_id=resource_id, content_version=fixture["content_version"],
            content=fixture["content"], provider_identity_verified=True,
        ),
    )
    source_file = tmp_path / "signed.json"
    write_snapshot(source_file, tenant_id="tenant-a", application_id=APP, source_id=SHAREPOINT, resources=chunks)
    seen = {"model_prompts": [], "guard_calls": []}
    with guard_client, httpx.Client(timeout=90, trust_env=False) as model:
        def dispatch(req):
            if req.url.path.startswith("/guard/"):
                seen["guard_calls"].append(req.url.path)
                r = guard_client.request(req.method, req.url.path, content=req.content,
                                         headers={"Authorization": req.headers.get("Authorization", "")})
                return httpx.Response(r.status_code, content=r.content)
            assert req.url.path == "/v1/chat/completions"
            body = json.loads(req.content)
            seen["model_prompts"].append(body)
            body.update(max_tokens=256, temperature=0, stream=False)
            r = model.post("http://127.0.0.1:11434/v1/chat/completions", json=body, timeout=90)
            return httpx.Response(r.status_code, content=r.content, headers={"content-type": "application/json"})
        settings = GatewaySettings(
            guard_url="https://guard.synthetic",
            model_url="http://127.0.0.1:11434/v1/chat/completions",
            application_id=APP, tenant_id="tenant-a",
            verifier=SourceAttestationVerifier(tenant_id="tenant-a", trusted_keys={key_id: key.public_key()}),
            source_snapshots={SHAREPOINT: source_file}, multisource_guard_v2=True,
            model_name="llama3.2:3b",
        )
        with TestClient(create_app(settings, client=httpx.Client(transport=httpx.MockTransport(dispatch)))) as gateway:
            def ask(name):
                return gateway.post(
                    "/v1/snapshots/chat/completions",
                    headers={"Authorization": "Bearer " + _token(name)},
                    json={"application_id": APP, "source_ids": [SHAREPOINT],
                          "employee_question": "Summarize the synthetic test reference."},
                )
            alice = ask("alice")
            assert alice.status_code == 200, alice.text[:200]
            assert len(seen["model_prompts"]) == 1
            assert fixture["content"] in "\n".join(x["content"] for x in seen["model_prompts"][0]["messages"])
            bob = ask("bob")
            assert bob.status_code in (403, 503)
            assert fixture["content"] not in bob.text
            assert len(seen["model_prompts"]) == 1
            # Local policy revocation only, no external SharePoint mutation.
            policy.install(3, [{"subject_id": "alice-m", "source_id": SHAREPOINT,
                                "resource_id": resource_id, "decision": "deny"}])
            revoked = ask("alice")
            assert revoked.status_code in (403, 503)
            assert fixture["content"] not in revoked.text
            assert len(seen["model_prompts"]) == 1
        assert "/guard/v2/filter-resources" in seen["guard_calls"]
        assert "/guard/v2/check-output" in seen["guard_calls"]
