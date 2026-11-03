"""Entra Alice/Bob demo switching: signed tokens, no identity impersonation."""
from __future__ import annotations

import importlib.util
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from packages.auth import entra_demo_login as login
from packages.auth import oidc as oidc_module
from packages.auth.oidc import OidcProviderClient

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"
DOMAIN = "neuralmatrix093.onmicrosoft.com"
CLIENT = "test-entra-rag-client"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
ALICE = f"alice@{DOMAIN}"
BOB = f"bob@{DOMAIN}"
ALICE_ID = "11111111-1111-4111-8111-111111111111"
BOB_ID = "22222222-2222-4222-8222-222222222222"


def load_rag(monkeypatch):
    for key, value in {
        "ACCESSPROOF_DEMO_SOURCE_PROVIDER": "microsoft365",
        "ACCESSPROOF_DEMO_ENTRA_TENANT_ID": TENANT,
        "ACCESSPROOF_DEMO_ENTRA_CLIENT_ID": CLIENT,
        "ACCESSPROOF_DEMO_ENTRA_CLIENT_SECRET": "test-client-secret",
        "ACCESSPROOF_DEMO_ENTRA_REDIRECT_URI":
            "http://localhost:8200/v1/auth/entra/callback",
        "ACCESSPROOF_DEMO_ENTRA_DOMAIN": DOMAIN,
        "ACCESSPROOF_DEMO_ENTRA_ALICE_EMAIL": ALICE,
        "ACCESSPROOF_DEMO_ENTRA_BOB_EMAIL": BOB,
        "ACCESSPROOF_DEMO_GUARD_URL": "https://guard.example.test",
        "ACCESSPROOF_DEMO_SOURCE_ID": "test-sharepoint",
        "ACCESSPROOF_DEMO_APPLICATION_ID": "test-rag",
        "DRIVE_OWNER_TOKEN": "synthetic",
        "DRIVE_ROOT_FOLDER_ID": "test-root",
        "ACCESSPROOF_ENV": "development",
    }.items():
        monkeypatch.setenv(key, value)
    filename = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = importlib.util.spec_from_file_location("entra_rag_test_app", filename)
    assert spec is not None and spec.loader is not None
    rag = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rag)
    rag.cached_files = [
        {"id": "shared", "name": "Shared.txt", "content": "SHARED-SYNTHETIC-CANARY"},
        {"id": "alice", "name": "Alice.txt", "content": "ALICE-SYNTHETIC-CANARY"},
    ]
    rag.last_refresh = time.monotonic()
    return rag


@pytest.fixture
def mock_entra(monkeypatch):
    with login._lock:
        login._pending.clear()
        login._sessions.clear()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": "entra-test-key", "alg": "RS256", "use": "sig"})
    pending = {}
    monkeypatch.setattr(oidc_module, "_pin_https_url",
                        lambda u: (u, urlsplit(u).hostname, urlsplit(u).hostname))

    def handler(request):
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/certs",
            })
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [jwk]})
        if path.endswith("/token"):
            fields = parse_qs(request.content.decode())
            name = fields["code"][0]
            oid, email = (ALICE_ID, ALICE) if name == "alice" else (BOB_ID, BOB)
            if name == "alice-with-bob-token":
                oid, email = BOB_ID, BOB
            now = int(time.time())
            claims = {
                "iss": ISSUER, "aud": CLIENT, "tid": TENANT,
                "sub": "entra-sub-" + oid,
                "oid": oid, "preferred_username": email,
                "nonce": pending["nonce"],
                "iat": now, "exp": now + 3600,
            }
            return httpx.Response(200, json={
                "id_token": jwt.encode(claims, key, algorithm="RS256",
                                       headers={"kid": "entra-test-key"})
            })
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(login, "_provider",
                        lambda tenant: OidcProviderClient(ISSUER, transport=transport))

    def authenticate(client, role, code=None):
        started = client.get(f"/v1/auth/entra/start?as_user={role}",
                             follow_redirects=False)
        assert started.status_code == 302
        q = parse_qs(urlsplit(started.headers["location"]).query)
        # After switching tiles, no old employee cookie may remain valid.
        assert client.get("/v1/auth/entra/me").status_code == 401
        pending["nonce"] = q["nonce"][0]
        assert q["login_hint"] == [ALICE if role == "alice" else BOB]
        assert q["prompt"] == ["select_account"]
        return client.get("/v1/auth/entra/callback", params={
            "state": q["state"][0], "code": code or role,
        }, follow_redirects=False)

    authenticate.handler = handler
    yield authenticate
    with login._lock:
        login._pending.clear()
        login._sessions.clear()


def test_enta_login_without_real_client_configuration_fails_closed(monkeypatch):
    for key in ("ACCESSPROOF_DEMO_ENTRA_CLIENT_ID", "ACCESSPROOF_DEMO_ENTRA_CLIENT_SECRET"):
        monkeypatch.delenv(key, raising=False)
    rag = load_rag(monkeypatch)
    monkeypatch.delenv("ACCESSPROOF_DEMO_ENTRA_CLIENT_SECRET")
    with TestClient(rag.app) as client:
        response = client.get("/v1/auth/entra/start?as_user=alice")
    assert response.status_code == 503
    assert response.json()["detail"] == "ENTRA_DEMO_LOGIN_NOT_CONFIGURED"


def test_switching_accounts_invalidates_prior_session_and_checks_signed_identity(
    monkeypatch, mock_entra,
):
    rag = load_rag(monkeypatch)
    with TestClient(rag.app) as client:
        assert client.get("/v1/auth/entra/me").status_code == 401
        alice = mock_entra(client, "alice")
        assert alice.status_code == 303
        assert client.get("/v1/auth/entra/me").json()["object_id"] == ALICE_ID
        # The second tile forces a new Microsoft-authenticated identity.
        bob = mock_entra(client, "bob")
        assert bob.status_code == 303, bob.text
        assert client.get("/v1/auth/entra/me").json()["object_id"] == BOB_ID
        assert "alice" not in client.get("/v1/auth/entra/me").text
        assert client.post("/v1/auth/entra/logout").status_code == 200
        assert client.get("/v1/auth/entra/me").status_code == 401


def test_alice_tile_rejects_bob_token_no_impersonation(monkeypatch, mock_entra):
    rag = load_rag(monkeypatch)
    with TestClient(rag.app) as client:
        denied = mock_entra(client, "alice", code="alice-with-bob-token")
        assert denied.status_code == 403
        assert denied.json()["detail"] == "ENTRA_EMPLOYEE_IDENTITY_MISMATCH"
        assert client.get("/v1/auth/entra/me").status_code == 401
        assert client.get("/v1/auth/entra/start?as_user=admin").status_code == 400


def test_rag_rejects_no_login_and_shows_2_person_switcher(monkeypatch):
    rag = load_rag(monkeypatch)
    with TestClient(rag.app) as client:
        page = client.get("/demo/entra")
        assert page.status_code == 200
        assert "as_user=alice" in page.text and "as_user=bob" in page.text
        blocked = client.post("/v1/protected-chat", json={"message": "Finance?"})
        assert blocked.status_code == 401
        assert blocked.json()["detail"] == "VERIFIED_EMPLOYEE_TOKEN_REQUIRED"


def _install_source_attested_sharepoint_snapshot(monkeypatch, tmp_path) -> None:
    """Source-authenticated synthetic contents; Guard still applies the ACL."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from packages.rag_core.attestation import SourceAttestationSigner
    from packages.rag_core.ingestion import TrustedSourceIngestor, VerifiedSourceDocument
    from packages.demo_cache.trusted_snapshot import write_snapshot

    key = Ed25519PrivateKey.generate()
    ingester = TrustedSourceIngestor(SourceAttestationSigner(
        key_id="test-rag-key", private_key=key,
    ))
    resources = []
    for resource_id, content in (
        ("shared", "SHARED-SYNTHETIC-CANARY"),
        ("alice", "ALICE-SYNTHETIC-CANARY"),
        ("bob", "BOB-SYNTHETIC-CANARY"),
    ):
        resources.extend(ingester.attest_document(VerifiedSourceDocument(
            tenant_id=TENANT, application_id="test-rag",
            source_id="test-sharepoint", resource_id=resource_id,
            content_version="v1", content=content,
            provider_identity_verified=True,
        )))
    destination = tmp_path / "signed-sharepoint.snapshot.json"
    write_snapshot(destination, tenant_id=TENANT, application_id="test-rag",
                   source_id="test-sharepoint", resources=resources)
    monkeypatch.setenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT", "1")
    monkeypatch.setenv("ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH", str(destination))
    monkeypatch.setenv("ACCESSPROOF_DEMO_ATTESTATION_TENANT", TENANT)
    monkeypatch.setenv("ACCESSPROOF_DEMO_ATTESTATION_KEY_ID", "test-rag-key")
    monkeypatch.setenv("ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64", base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode())


def test_entra_alice_bob_signed_sessions_real_guard_and_revocation(monkeypatch, mock_entra, tmp_path):
    """Real local Guard stack; signed tenant-specific Microsoft tokens are simulated."""
    from apps.guard.accessproof_guard import app as guard_app
    from apps.guard.accessproof_guard.cache import PolicyCache
    from apps.guard.accessproof_guard.identity import OidcVerifier
    from packages.rag_core import GuardClient

    rag = load_rag(monkeypatch)
    rag.cached_files.append({"id": "bob", "name": "Bob.txt", "content": "BOB-SYNTHETIC-CANARY"})
    _install_source_attested_sharepoint_snapshot(monkeypatch, tmp_path)
    policy = PolicyCache(str(tmp_path / "entra-test-guard.db"))
    policy.install(1, [
        {"subject_id": ALICE_ID, "source_id": "test-sharepoint", "resource_id": "shared", "decision": "allow"},
        {"subject_id": BOB_ID, "source_id": "test-sharepoint", "resource_id": "shared", "decision": "allow"},
        {"subject_id": ALICE_ID, "source_id": "test-sharepoint", "resource_id": "alice", "decision": "allow"},
        {"subject_id": BOB_ID, "source_id": "test-sharepoint", "resource_id": "alice", "decision": "deny"},
        {"subject_id": ALICE_ID, "source_id": "test-sharepoint", "resource_id": "bob", "decision": "deny"},
        {"subject_id": BOB_ID, "source_id": "test-sharepoint", "resource_id": "bob", "decision": "allow"},
    ])
    policy.set_application_bindings([{
        "application_id": "test-rag", "source_id": "test-sharepoint",
        "mode": "protect", "source_acl_healthy": True,
    }])
    policy.set_identity_mappings([
        {"source_id": "test-sharepoint", "issuer": ISSUER, "subject": user_id,
         "tenant_id": TENANT, "source_subject_id": user_id}
        for user_id in (ALICE_ID, BOB_ID)
    ])
    policy.mark_sync_success()
    verifier = OidcVerifier(
        issuer=ISSUER, audience=CLIENT, subject_claim="oid", tenant_id=TENANT,
        client=httpx.Client(transport=httpx.MockTransport(mock_entra.handler)),
    )
    for name, value in {
        "cache": policy, "identity_mode": "oidc", "issuer": ISSUER,
        "audience": CLIENT, "subject_claim": "oid", "expected_tenant": TENANT,
        "verification_key": None, "_oidc_verifier": verifier,
        "guard_id": "test-guard", "guard_credential": "test-machine-secret",
        "max_policy_age_seconds": 180,
    }.items():
        monkeypatch.setattr(guard_app, name, value)

    with TestClient(guard_app.app) as guard_client:
        def forward(request):
            response = guard_client.request(
                request.method, request.url.path, content=request.content,
                headers={"Authorization": request.headers.get("Authorization", ""), "Content-Type": request.headers.get("Content-Type", "")},
            )
            return httpx.Response(response.status_code, content=response.content)

        monkeypatch.setattr(rag, "GuardClient", lambda _: GuardClient(
            "https://guard.example.test", client=httpx.Client(transport=httpx.MockTransport(forward)),
        ))
        with TestClient(rag.app) as alice_client, TestClient(rag.app) as bob_client:
            assert mock_entra(alice_client, "alice").status_code == 303
            assert mock_entra(bob_client, "bob").status_code == 303
            alice_result = alice_client.post("/v1/protected-chat", json={"message": "Show my permitted documents"})
            bob_result = bob_client.post("/v1/protected-chat", json={"message": "Show my permitted documents"})
            assert alice_result.status_code == 200, alice_result.text
            assert bob_result.status_code == 200, bob_result.text
            assert "SHARED-SYNTHETIC-CANARY" in alice_result.text
            assert "SHARED-SYNTHETIC-CANARY" in bob_result.text
            assert "ALICE-SYNTHETIC-CANARY" in alice_result.text
            assert "ALICE-SYNTHETIC-CANARY" not in bob_result.text
            assert "BOB-SYNTHETIC-CANARY" in bob_result.text
            assert "BOB-SYNTHETIC-CANARY" not in alice_result.text
            # Same browser: switching roles always requires a new signed
            # Microsoft OIDC flow; no prior Alice claims survive Bob's login.
            assert mock_entra(alice_client, "bob").status_code == 303
            assert alice_client.get("/v1/auth/entra/me").json()["object_id"] == BOB_ID
            switched = alice_client.post("/v1/protected-chat", json={"message": "Show my permitted documents"})
            assert switched.status_code == 200
            assert "BOB-SYNTHETIC-CANARY" in switched.text
            assert "ALICE-SYNTHETIC-CANARY" not in switched.text
            assert mock_entra(alice_client, "alice").status_code == 303
            policy.install(2, [
                {"subject_id": ALICE_ID, "source_id": "test-sharepoint",
                 "resource_id": "alice", "decision": "deny", "reason": "SOURCE_ACCESS_REVOKED"},
            ])
            revoked = alice_client.post("/v1/protected-chat", json={"message": "finance?"})
            assert revoked.status_code == 200, revoked.text
            assert "ALICE-SYNTHETIC-CANARY" not in revoked.text
            # The indexed text remains; Guard, not a manual removal from RAG, denies it.
            assert any(x["id"] == "alice" for x in rag.cached_files)


def test_sharepoint_refuses_google_legacy_content_after_microsoft_login(monkeypatch, mock_entra):
    rag = load_rag(monkeypatch)
    with TestClient(rag.app) as client:
        assert mock_entra(client, "alice").status_code == 303
        response = client.post("/v1/protected-chat", json={"message": "finance?"})
        assert response.status_code == 503
        assert response.json()["detail"] == "SHAREPOINT_SIGNED_SOURCE_REQUIRED"
        assert "ALICE-SYNTHETIC-CANARY" not in response.text
