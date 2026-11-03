"""Managed Google employee browser login -> signed OIDC -> real Guard policy -> RAG.

The Google issuer, JWKS and OAuth token endpoint are realistically emulated
with an RSA signing key. NOT a live Cloud Identity Free tenant certification.
"""
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

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.identity import OidcVerifier
from packages.auth import google_demo_login as login
from packages.auth import oidc as oidc_module
from packages.auth.oidc import OidcProviderClient
from packages.rag_core import GuardClient


GOOGLE = "https://accounts.google.com"
CLIENT_ID = "demo-cloud-identity-client"
DOMAIN = "demo.example"
SOURCE = "demo-drive"
APP = "protected-rag"
ISSUER_JWKS = "https://www.googleapis.com/oauth2/v3/certs"


def _load_rag(monkeypatch):
    config = {
        "ACCESSPROOF_DEMO_GOOGLE_CLIENT_ID": CLIENT_ID,
        "ACCESSPROOF_DEMO_GOOGLE_CLIENT_SECRET": "test-secret-not-real",
        "ACCESSPROOF_DEMO_GOOGLE_HOSTED_DOMAIN": DOMAIN,
        "ACCESSPROOF_DEMO_GOOGLE_REDIRECT_URI":
            "http://localhost:8200/v1/auth/google/callback",
        "DRIVE_OWNER_TOKEN": "synthetic-test-token",
        "DRIVE_ROOT_FOLDER_ID": "synthetic-root",
        "ACCESSPROOF_DEMO_GUARD_URL": "https://guard.example.test",
        "ACCESSPROOF_DEMO_SOURCE_ID": SOURCE,
        "ACCESSPROOF_DEMO_APPLICATION_ID": APP,
        "ACCESSPROOF_ENV": "development",
    }
    for key, value in config.items():
        monkeypatch.setenv(key, value)
    filename = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = importlib.util.spec_from_file_location("google_managed_rag_demo", filename)
    assert spec and spec.loader
    rag = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rag)
    rag.cached_files = [{"id": "salary", "name": "salary.txt", "content": "SYNTHETIC SALARY CANARY"}]
    rag.last_refresh = time.monotonic()
    return rag


@pytest.fixture()
def google_identity(monkeypatch):
    """Mock Google's wire protocol, but issue real signed RSA ID tokens."""
    with login._lock:
        login._pending.clear()
        login._sessions.clear()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public_jwk.update({"kid": "google-test-kid", "alg": "RS256", "use": "sig"})
    oauth_challenge = {"nonce": "", "code_challenge": "", "state": ""}

    # Only synthetic mock transport is used in this fixture; no Google requests.
    monkeypatch.setattr(oidc_module, "_pin_https_url", lambda url: (
        url, urlsplit(url).hostname, urlsplit(url).hostname,
    ))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={
                "issuer": GOOGLE,
                "authorization_endpoint": GOOGLE + "/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "jwks_uri": ISSUER_JWKS,
            })
        if request.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [public_jwk]})
        if request.url.path == "/token":
            data = parse_qs(request.content.decode())
            assert data["code_verifier"] and data["client_id"] == [CLIENT_ID]
            code = data["code"][0]
            now = int(time.time())
            users = {
                "alice": ("google-alice-immutable-id", "alice@" + DOMAIN, DOMAIN, True),
                "bob": ("google-bob-immutable-id", "bob@" + DOMAIN, DOMAIN, True),
                "personal": ("personal-sub", "alice@gmail.com", "", True),
                "different-company": ("foreign-sub", "alice@foreign.example", "foreign.example", True),
                "unverified": ("unverified-sub", "alice@" + DOMAIN, DOMAIN, False),
                "bad-nonce": ("bad-sub", "alice@" + DOMAIN, DOMAIN, True),
            }
            sub, email, hosted_domain, verified = users[code]
            claims = {
                "iss": GOOGLE, "aud": CLIENT_ID, "sub": sub,
                "email": email, "email_verified": verified,
                "iat": now, "exp": now + 3600, "nonce": oauth_challenge["nonce"],
            }
            if hosted_domain:
                claims["hd"] = hosted_domain
            if code == "bad-nonce":
                claims.update({"sub": "bad", "email": "bad@" + DOMAIN,
                               "hd": DOMAIN, "nonce": "another-nonce"})
            encoded = jwt.encode(claims, key, algorithm="RS256",
                                 headers={"kid": "google-test-kid"})
            return httpx.Response(200, json={"id_token": encoded})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(login, "_provider",
                        lambda: OidcProviderClient(GOOGLE, transport=transport))

    def authorize(client: TestClient, code: str):
        begin = client.get("/v1/auth/google/start", follow_redirects=False)
        assert begin.status_code == 302, begin.text
        query = parse_qs(urlsplit(begin.headers["location"]).query)
        assert query["hd"] == [DOMAIN]
        assert query["code_challenge_method"] == ["S256"]
        oauth_challenge.update(
            {"nonce": query["nonce"][0], "state": query["state"][0],
             "code_challenge": query["code_challenge"][0]}
        )
        callback = client.get("/v1/auth/google/callback",
                              params={"state": query["state"][0], "code": code},
                              follow_redirects=False)
        return callback, query

    yield {"authorize": authorize, "handler": handler}
    with login._lock:
        login._pending.clear()
        login._sessions.clear()


def test_missing_cloud_identity_oauth_configuration_fails_closed(monkeypatch):
    rag = _load_rag(monkeypatch)
    monkeypatch.delenv("ACCESSPROOF_DEMO_GOOGLE_CLIENT_ID")
    with TestClient(rag.app) as client:
        result = client.get("/v1/auth/google/start", follow_redirects=False)
    assert result.status_code == 503
    assert result.json()["detail"] == "GOOGLE_EMPLOYEE_LOGIN_NOT_CONFIGURED"


@pytest.mark.parametrize("code", ["personal", "different-company", "unverified", "bad-nonce"])
def test_google_managed_employee_auth_rejects_foreign_or_unverified_accounts(
    monkeypatch, google_identity, code,
):
    rag = _load_rag(monkeypatch)
    with TestClient(rag.app) as client:
        callback, _query = google_identity["authorize"](client, code)
        assert callback.status_code in (401, 403), callback.text
        assert client.get("/v1/auth/google/me").status_code == 401


def test_google_login_state_cookie_and_replay_protection(monkeypatch, google_identity):
    rag = _load_rag(monkeypatch)
    with TestClient(rag.app) as client:
        begin = client.get("/v1/auth/google/start", follow_redirects=False)
        query = parse_qs(urlsplit(begin.headers["location"]).query)
        # A cross-browser callback with stolen state must not exchange its code.
        with TestClient(rag.app) as attacker:
            denied = attacker.get("/v1/auth/google/callback", params={
                "state": query["state"][0], "code": "alice",
            })
            assert denied.status_code == 401
        # The legitimate login is still possible.
        # Complete the auth using the actual first flow challenge.
        google_identity["authorize"](client, "alice")
        repeated = client.get("/v1/auth/google/callback", params={
            "state": query["state"][0], "code": "alice",
        })
        assert repeated.status_code == 401


def test_signed_google_employee_cookie_real_guard_and_revocation(
    monkeypatch, google_identity, tmp_path,
):
    rag = _load_rag(monkeypatch)
    policy = PolicyCache(str(tmp_path / "google-guard-policy.db"))
    policy.install(1, [
        {"subject_id": "google-alice-immutable-id", "source_id": SOURCE,
         "resource_id": "salary", "decision": "allow"},
        {"subject_id": "google-bob-immutable-id", "source_id": SOURCE,
         "resource_id": "salary", "decision": "deny"},
    ])
    policy.set_application_bindings([{
        "application_id": APP, "source_id": SOURCE,
        "mode": "protect", "source_acl_healthy": True,
    }])
    policy.set_identity_mappings([
        {"source_id": SOURCE, "issuer": GOOGLE, "subject": sub,
         "tenant_id": "", "source_subject_id": sub}
        for sub in ("google-alice-immutable-id", "google-bob-immutable-id")
    ])
    policy.mark_sync_success()

    verifier = OidcVerifier(
        issuer=GOOGLE, audience=CLIENT_ID, subject_claim="sub",
        client=httpx.Client(transport=httpx.MockTransport(
            google_identity["handler"]
        )),
    )
    for name, value in {
        "cache": policy, "identity_mode": "oidc", "issuer": GOOGLE,
        "audience": CLIENT_ID, "subject_claim": "sub",
        "verification_key": None, "expected_tenant": None,
        "_oidc_verifier": verifier,
        "guard_id": "synced-guard", "guard_credential": "test-machine-credential",
        "max_policy_age_seconds": 180,
    }.items():
        monkeypatch.setattr(guard_app, name, value)

    with TestClient(guard_app.app) as guard_client:
        def forward(request: httpx.Request) -> httpx.Response:
            resp = guard_client.request(
                request.method, request.url.path, content=request.content,
                headers={"Authorization": request.headers.get("Authorization", ""), "Content-Type": request.headers.get("Content-Type", "")},
            )
            return httpx.Response(resp.status_code, content=resp.content)

        monkeypatch.setattr(rag, "GuardClient", lambda _: GuardClient(
            "https://guard.example.test",
            client=httpx.Client(transport=httpx.MockTransport(forward)),
        ))
        with TestClient(rag.app) as alice:
            demo_ui = alice.get("/demo")
            assert demo_ui.status_code == 200
            assert "Sign in with Google" in demo_ui.text

            callback, query = google_identity["authorize"](alice, "alice")
            assert callback.status_code == 303, callback.text
            assert callback.headers["location"] == "/demo"
            assert query["nonce"][0]
            assert alice.get("/v1/auth/google/me").json()["subject"] == (
                "google-alice-immutable-id"
            )
            assert "id_token" not in alice.get("/v1/auth/google/me").text

            permitted = alice.post("/v1/protected-chat", json={"message": "salary?"})
            assert permitted.status_code == 200, permitted.text
            assert "SYNTHETIC SALARY CANARY" in permitted.json()["answer"]
            assert permitted.json()["citations"] == ["salary"]

            # An authentic Google identity is NOT an authorization grant.
            with TestClient(rag.app) as bob:
                bob_callback, _ = google_identity["authorize"](bob, "bob")
                assert bob_callback.status_code == 303
                denied = bob.post("/v1/protected-chat", json={"message": "salary?"})
                assert denied.status_code == 200
                assert "SYNTHETIC SALARY CANARY" not in denied.text

            # Now revoke Alice but keep the indexed salary text in the RAG.
            policy.install(2, [
                {"subject_id": "google-alice-immutable-id", "source_id": SOURCE,
                 "resource_id": "salary", "decision": "deny",
                 "reason": "SOURCE_ACCESS_REVOKED"},
            ])
            after = alice.post("/v1/protected-chat", json={"message": "salary?"})
            assert after.status_code == 200, after.text
            assert "SYNTHETIC SALARY CANARY" not in after.text
            assert not after.json()["citations"]
            assert rag.cached_files[0]["content"] == "SYNTHETIC SALARY CANARY"

            assert alice.post("/v1/auth/google/logout").status_code == 200
            assert alice.get("/v1/auth/google/me").status_code == 401
            assert alice.post("/v1/protected-chat",
                              json={"message": "salary?"}).status_code == 401

    assert any(x.get("result") == "block" for x in policy.pending_audit(limit=100))
