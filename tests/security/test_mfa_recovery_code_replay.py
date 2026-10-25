"""MFA recovery codes must be one-time for disabling MFA as well as login.

Runs only against the isolated test database configured by tests/conftest.py.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine
from packages.crypto.totp import totp_code


def test_mfa_disable_consumes_recovery_code_and_does_not_break_other_codes() -> None:
    Base.metadata.create_all(engine)
    email = f"mfa-replay-{uuid4().hex[:12]}@example.com"
    with TestClient(app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": email, "password": "synthetic robust example password",
            "organization_name": "Local Synthetic MFA",
        })
        assert signup.status_code in (200, 201), signup.text
        session = signup.json()
        assert client.post("/api/v1/auth/verify-email", json={
            "token": session["development_verification_token"],
        }).status_code == 200
        headers = {
            "Authorization": f"Bearer {session['session_token']}",
            "X-Organization-ID": session["organization_id"],
        }
        setup = client.post("/api/v1/auth/mfa/setup", headers=headers)
        assert setup.status_code == 200
        payload = setup.json()
        code1, code2 = payload["recovery_codes"][:2]
        secret = parse_qs(urlparse(payload["provisioning_uri"]).query)["secret"][0]
        valid_totp = totp_code(secret)
        assert client.post("/api/v1/auth/mfa/enable", headers=headers, json={
            "code": valid_totp,
        }).status_code == 200

        # A used recovery code can never be accepted twice, even if MFA was
        # enabled again with the account's existing TOTP secret.
        first = client.post("/api/v1/auth/mfa/disable", headers=headers, json={
            "code": code1,
        })
        assert first.status_code == 200, first.text
        assert client.post("/api/v1/auth/mfa/enable", headers=headers, json={
            "code": valid_totp,
        }).status_code == 200
        replay = client.post("/api/v1/auth/mfa/disable", headers=headers, json={
            "code": code1,
        })
        assert replay.status_code == 400
        assert "Invalid MFA or recovery code" in replay.text

        fresh = client.post("/api/v1/auth/mfa/disable", headers=headers, json={
            "code": code2,
        })
        assert fresh.status_code == 200, fresh.text
