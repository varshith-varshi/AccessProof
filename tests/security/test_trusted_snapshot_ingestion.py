"""Source-authenticated snapshot boundary in the customer-owned reference RAG."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.demo_cache.trusted_snapshot import (
    SnapshotInvalid, load_snapshot, write_snapshot,
)
from packages.rag_sdk import (
    ContentBinding, RetrievedResource, SourceAttestationSigner,
    SourceAttestationVerifier,
)
from connectors.google_drive import snapshot_agent


def _source(*, now: int):
    private = Ed25519PrivateKey.generate()
    signer = SourceAttestationSigner(key_id="ingestion", private_key=private)
    verifier = SourceAttestationVerifier(tenant_id="tenant", trusted_keys={"ingestion": private.public_key()})
    content = "Confidential synthetic Drive content"
    item = RetrievedResource(
        source_id="source", resource_id="file", chunk_id="file:1",
        content=content, content_version="1",
        content_attestation=signer.issue(
            ContentBinding("tenant", "app", "source", "file", "file:1", "1", content),
            ttl_seconds=300, now=now,
        ),
    )
    return item, verifier


def test_snapshot_signed_allow_tamper_expire_replay_and_symlink(tmp_path):
    item, verifier = _source(now=1000)
    path = tmp_path / "trusted.snapshot.json"
    write_snapshot(path, tenant_id="tenant", application_id="app", source_id="source",
                   resources=[item], now=1000)
    assert load_snapshot(path, verifier=verifier, application_id="app",
                         source_id="source", now=1010) == [item]
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(SnapshotInvalid):
        load_snapshot(path, verifier=verifier, application_id="wrong",
                      source_id="source", now=1010)
    with pytest.raises(SnapshotInvalid):
        load_snapshot(path, verifier=verifier, application_id="app",
                      source_id="source", now=1301)
    altered = json.loads(path.read_text())
    altered["resources"][0]["content"] = "malicious replaced data"
    path.write_text(json.dumps(altered))
    with pytest.raises(SnapshotInvalid):
        load_snapshot(path, verifier=verifier, application_id="app",
                      source_id="source", now=1010)
    target = tmp_path / "target"
    target.write_text("placeholder")
    symlink = tmp_path / "symlink"
    symlink.symlink_to(target)
    with pytest.raises(SnapshotInvalid):
        load_snapshot(symlink, verifier=verifier, application_id="app",
                      source_id="source", now=1010)


def test_atomic_snapshot_does_not_rewrite_existing_data_on_bad_input(tmp_path):
    item, verifier = _source(now=1000)
    path = tmp_path / "snapshot.json"
    write_snapshot(path, tenant_id="tenant", application_id="app", source_id="source",
                   resources=[item], now=1000)
    original = path.read_bytes()
    with pytest.raises(SnapshotInvalid):
        write_snapshot(path, tenant_id="tenant", application_id="app", source_id="source",
                       resources=[], now=1005)
    assert path.read_bytes() == original
    assert load_snapshot(path, verifier=verifier, application_id="app",
                         source_id="source", now=1010) == [item]


@pytest.mark.asyncio
async def test_google_ingester_scopes_fetches_and_publishes_complete_snapshot(monkeypatch, tmp_path):
    item, verifier = _source(now=1000)
    private_path = tmp_path / "source.key"
    private_path.write_bytes(b"r" * 32)
    private_path.chmod(0o600)
    class FakeDrive:
        def __init__(self, **kwargs):
            assert kwargs["test_root_folder_id"] == "root"
            self._client = self

        async def validate_connection(self):
            return {"valid": True}

        async def list_boundary_resources(self, *, max_items=50):
            assert max_items == 50
            return [{"id": "file", "mimeType": "text/plain"},
                    {"id": "folder", "mimeType": "application/vnd.google-apps.folder"}]

        async def aclose(self):
            pass

    class FakeIngestion:
        def __init__(self, adapter, signer, settings):
            assert settings.source_id == "source"

        async def ingest(self, file_id):
            assert file_id == "file"
            return [item]

    monkeypatch.setattr(snapshot_agent, "GoogleDriveAdapter", FakeDrive)
    monkeypatch.setattr(snapshot_agent, "GoogleDriveTrustedIngestion", FakeIngestion)
    snapshot = tmp_path / "published.snapshot"
    chunks = await snapshot_agent.ingest_snapshot(
        access_token="synthetic", root_folder_id="root",
        tenant_id="tenant", application_id="app", source_id="source",
        signing_key=private_path, key_id="ingestion", snapshot_path=snapshot,
    )
    assert chunks == 1
    assert snapshot.is_file()
    payload = json.loads(snapshot.read_bytes())
    assert len(payload["resources"]) == 1
    assert payload["resources"][0]["content_attestation"] == item.content_attestation


@pytest.mark.asyncio
async def test_ingester_never_replaces_snapshot_when_provider_fetch_fails(monkeypatch, tmp_path):
    path = tmp_path / "snapshot"
    path.write_text("safe existing")
    key = tmp_path / "sign.key"
    key.write_bytes(b"r" * 32)
    key.chmod(0o600)
    class FakeDrive:
        def __init__(self, **kwargs):
            self._client = self
        async def validate_connection(self):
            pass
        async def list_boundary_resources(self, **kwargs):
            raise RuntimeError("provider down")
        async def aclose(self):
            pass
    monkeypatch.setattr(snapshot_agent, "GoogleDriveAdapter", FakeDrive)
    with pytest.raises(RuntimeError, match="provider down"):
        await snapshot_agent.ingest_snapshot(
            access_token="synthetic", root_folder_id="root",
            tenant_id="tenant", application_id="app", source_id="source",
            signing_key=key, key_id="ingestion", snapshot_path=path,
        )
    assert path.read_text() == "safe existing"


def test_production_reference_rag_requires_independently_signed_snapshot(monkeypatch, tmp_path):
    import base64
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from fastapi.testclient import TestClient

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer = SourceAttestationSigner(key_id="ingest", private_key=private)
    token = signer.issue(
        ContentBinding("tenant", "app", "source", "drive-file", "chunk-1",
                       "v1", "actual trusted Drive content"),
    )
    resource = RetrievedResource(
        source_id="source", resource_id="drive-file", chunk_id="chunk-1",
        content="actual trusted Drive content", content_version="v1",
        content_attestation=token,
    )
    path = tmp_path / "source.snapshot"
    write_snapshot(path, tenant_id="tenant", application_id="app",
                   source_id="source", resources=[resource])
    environment = {
        "ACCESSPROOF_ENV": "production",
        "ACCESSPROOF_DEMO_GUARD_URL": "http://synthetic-guard",
        "ACCESSPROOF_DEMO_SOURCE_ID": "source",
        "ACCESSPROOF_DEMO_APPLICATION_ID": "app",
        "ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT": "1",
        "ACCESSPROOF_DEMO_ATTESTATION_TENANT": "tenant",
        "ACCESSPROOF_DEMO_ATTESTATION_KEY_ID": "ingest",
        "ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64": base64.b64encode(public).decode(),
        "ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH": str(path),
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ACCESSPROOF_DEMO_CACHE_URL", raising=False)

    app_path = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = __import__("importlib.util", fromlist=["spec_from_file_location"]).spec_from_file_location(
        "trusted_reference_drive", app_path,
    )
    module = __import__("importlib.util", fromlist=["module_from_spec"]).module_from_spec(spec)
    spec.loader.exec_module(module)

    class Guard:
        calls = []
        def __init__(self, url):
            assert url == "http://synthetic-guard"
        def filter_resources(self, **kwargs):
            self.calls.append("layer1")
            return {
                "decision": "allow", "mode": "protect", "decision_id": "l1",
                "allowed": [{"source_id": "source", "resource_id": "drive-file",
                             "chunk_ids": ["chunk-1"]}],
            }
        def check_output(self, **kwargs):
            self.calls.append("layer2")
            return {"decision": "allow", "reason": "PROVENANCE_VALID"}
        def close(self):
            pass

    monkeypatch.setattr(module, "GuardClient", Guard)
    monkeypatch.setattr(module, "refresh_cache",
                        lambda: (_ for _ in ()).throw(AssertionError("unsigned source used")))
    Guard.calls = []
    with TestClient(module.app) as client:
        response = client.post(
            "/v1/protected-chat", json={"message": "What does the report contain?"},
            headers={"Authorization": "Bearer verified-employee"},
        )
        assert response.status_code == 200, response.text
        assert "actual trusted Drive content" in response.json()["answer"]
        assert Guard.calls == ["layer1", "layer2"]
        # After tampering, even the same employee cannot use untrusted source text.
        payload = json.loads(path.read_text())
        payload["resources"][0]["content"] = "forged secret"
        path.write_text(json.dumps(payload))
        Guard.calls = []
        invalid = client.post(
            "/v1/protected-chat", json={"message": "What does the report contain?"},
            headers={"Authorization": "Bearer verified-employee"},
        )
        assert invalid.status_code == 503
        assert "forged secret" not in invalid.text
        assert Guard.calls == []

    monkeypatch.delenv("ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH")
    with TestClient(module.app) as client:
        without_source = client.post(
            "/v1/protected-chat", json={"message": "test"},
            headers={"Authorization": "Bearer verified-employee"},
        )
        assert without_source.status_code == 503
        assert "CERTIFIED_SOURCE_INGESTION_REQUIRED" in without_source.text


def test_reference_rag_production_readiness_requires_source_and_guard(monkeypatch, tmp_path):
    import importlib.util
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ACCESSPROOF_ENV", "production")
    monkeypatch.setenv("ACCESSPROOF_DEMO_GUARD_URL", "http://guard.synthetic")
    monkeypatch.setenv("ACCESSPROOF_DEMO_SOURCE_ID", "source")
    monkeypatch.setenv("ACCESSPROOF_DEMO_APPLICATION_ID", "app")
    monkeypatch.setenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT", "1")
    monkeypatch.delenv("ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH", raising=False)
    path = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = importlib.util.spec_from_file_location("readiness_reference_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app) as client:
        assert client.get("/health").status_code == 200  # process live
        not_ready = client.get("/health/ready")
        assert not_ready.status_code == 503
        assert not_ready.json()["detail"] == "CERTIFIED_SOURCE_INGESTION_REQUIRED"
