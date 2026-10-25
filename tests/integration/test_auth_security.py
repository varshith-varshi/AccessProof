from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine
from packages.crypto.totp import totp_code
from urllib.parse import urlparse, parse_qs


def test_email_verify_password_reset_sessions_and_mfa():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        s = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "secure@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Secure Org",
            },
        ).json()
        assert c.post(
            "/api/v1/auth/verify-email", json={"token": s["development_verification_token"]}
        ).json()["verified"]
        h = {
            "Authorization": f"Bearer {s['session_token']}",
            "X-Organization-ID": s["organization_id"],
        }
        setup = c.post("/api/v1/auth/mfa/setup", headers=h).json()
        secret = parse_qs(urlparse(setup["provisioning_uri"]).query)["secret"][0]
        assert (
            c.post(
                "/api/v1/auth/mfa/enable", headers=h, json={"code": totp_code(secret)}
            ).status_code
            == 200
        )
        no_mfa = c.post(
            "/api/v1/auth/login",
            json={"email": "secure@example.com", "password": "correct horse battery staple"},
        )
        assert no_mfa.status_code == 401
        with_mfa = c.post(
            "/api/v1/auth/login",
            json={
                "email": "secure@example.com",
                "password": "correct horse battery staple",
                "totp_code": totp_code(secret),
            },
        )
        assert with_mfa.status_code == 200
        forgot = c.post("/api/v1/auth/forgot-password", json={"email": "secure@example.com"}).json()
        assert "development_reset_token" in forgot
        assert (
            c.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": forgot["development_reset_token"],
                    "new_password": "another correct horse battery",
                },
            ).status_code
            == 200
        )
        assert (
            c.post(
                "/api/v1/auth/login",
                json={
                    "email": "secure@example.com",
                    "password": "correct horse battery staple",
                    "totp_code": totp_code(secret),
                },
            ).status_code
            == 401
        )


def test_login_rejects_unbounded_password_payloads():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        response = c.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "x" * 257},
        )
    assert response.status_code == 422
