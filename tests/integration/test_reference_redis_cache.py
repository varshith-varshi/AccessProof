"""Reference RAG Redis cache: signed writes, fresh Guard on hits, revokes deny."""
from __future__ import annotations

import base64
import importlib.util
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from packages.demo_cache.protected_cache import SignedRedisAnswerCache
from packages.rag_core import (
    CachedAnswerManifestSigner, CachedAnswerManifestVerifier, ContentBinding,
    SourceAttestationSigner, SourceAttestationVerifier,
)


class MemoryRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def setex(self, key, seconds, content):
        assert 0 < seconds <= 3600
        self.data[key] = content.encode("utf-8")


class Guard:
    allowed = True
    calls = []

    def __init__(self, url):
        assert url == "http://guard.test"

    def filter_resources(self, **kwargs):
        self.calls.append("layer1")
        resources = kwargs["resources"]
        return {
            "mode": "protect", "decision": "allow" if self.allowed else "block",
            "decision_id": "decision-1", "allowed": ([{
                "source_id": item.source_id, "resource_id": item.resource_id,
                "chunk_ids": [item.chunk_id] if item.chunk_id else [],
            } for item in resources] if self.allowed else []),
        }

    def check_output(self, **kwargs):
        self.calls.append("layer2")
        return {"decision": "allow", "reason": "PROVENANCE_ACCEPTED"}

    def close(self):
        pass


def test_reference_cache_revocation_blocks_original_cached_answer(monkeypatch):
    for name, value in {
        "DRIVE_OWNER_TOKEN": "synthetic", "DRIVE_ROOT_FOLDER_ID": "root",
        "ALICE_EMAIL": "alice@example.com", "ALICE_RAG_TOKEN": "alice-test",
        "BOB_EMAIL": "bob@example.com", "BOB_RAG_TOKEN": "bob-test",
        "ACCESSPROOF_DEMO_GUARD_URL": "http://guard.test",
        "ACCESSPROOF_DEMO_SOURCE_ID": "source-1",
        "ACCESSPROOF_DEMO_APPLICATION_ID": "rag-1",
        "ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT": "1",
        "ACCESSPROOF_DEMO_ATTESTATION_TENANT": "tenant-1",
        "ACCESSPROOF_DEMO_ATTESTATION_KEY_ID": "trusted-source",
    }.items():
        monkeypatch.setenv(name, value)
    source_key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    source_public = source_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv("ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64", base64.b64encode(source_public).decode())
    app_path = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = importlib.util.spec_from_file_location("reference_drive_rag_app", app_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "GuardClient", Guard)
    key = Ed25519PrivateKey.generate()
    cache = SignedRedisAnswerCache(
        redis_client=MemoryRedis(), tenant_id="tenant-1", application_id="rag-1",
        signer=CachedAnswerManifestSigner(key_id="answer", private_key=key),
        verifier=CachedAnswerManifestVerifier(
            tenant_id="tenant-1", trusted_keys={"answer": key.public_key()},
        ),
        source_verifier=SourceAttestationVerifier(
            tenant_id="tenant-1", trusted_keys={"trusted-source": source_key.public_key()},
        ),
    )
    monkeypatch.setattr(module, "_signed_redis_cache", lambda verifier: cache)
    binding = ContentBinding(
        tenant_id="tenant-1", application_id="rag-1", source_id="source-1",
        resource_id="secret-report", chunk_id=None, content_version="1",
        content="trusted Q4 report text",
    )
    signed_source = SourceAttestationSigner(key_id="trusted-source", private_key=source_key).issue(binding)
    module.cached_files = [{
        "id": "secret-report", "content": binding.content,
        "content_version": "1", "content_attestation": signed_source,
    }]
    module.last_refresh = time.monotonic()
    Guard.allowed = True
    Guard.calls = []
    with TestClient(module.app) as client:
        request = {"message": "What is inside Q4?"}
        headers = {"Authorization": "Bearer synthetic-verified-employee"}
        fresh = client.post("/v1/protected-chat", json=request, headers=headers)
        assert fresh.status_code == 200, fresh.text
        assert fresh.json()["cache_hit"] is False
        answer = fresh.json()["answer"]
        assert "trusted Q4" in answer
        assert Guard.calls == ["layer1", "layer2"]
        Guard.calls = []
        hit = client.post("/v1/protected-chat", json=request, headers=headers)
        assert hit.status_code == 200, hit.text
        assert hit.json()["cache_hit"] is True
        assert hit.json()["answer"] == answer
        assert Guard.calls == ["layer1", "layer2"]
        Guard.calls = []
        Guard.allowed = False
        revoked = client.post("/v1/protected-chat", json=request, headers=headers)
        assert revoked.status_code == 403
        assert "trusted Q4" not in revoked.text
        assert Guard.calls == ["layer1"]
        # A Redis outage cannot trigger an unchecked fallback response.
        class BrokenRedis:
            def get(self, key):
                raise TimeoutError("synthetic redis outage")
        cache.redis = BrokenRedis()
        outage = client.post("/v1/protected-chat", json=request, headers=headers)
        assert outage.status_code == 503
        assert "trusted Q4" not in outage.text


def test_reference_docker_requirements_include_signed_cache_dependencies():
    requirements = (Path(__file__).resolve().parents[2]
                    / "drive-rag-demo" / "requirements.txt").read_text()
    assert "redis>=6,<7" in requirements
    assert "cryptography>=46,<47" in requirements
