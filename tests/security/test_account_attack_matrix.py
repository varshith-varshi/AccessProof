"""Account-security attack matrix (isolated, synthetic accounts).

Each test states the secure behaviour; a failure is a finding.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine
from packages.crypto.totp import totp_code as totp

PASSWORD = "correct horse battery staple"


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        yield c


def _signup(c: TestClient, email: str, org: str) -> dict[str, str]:
    body = c.post("/api/v1/auth/signup", json={"email": email, "password": PASSWORD,
                                                "organization_name": org}).json()
    return {"Authorization": f"Bearer {body['session_token']}", "X-Organization-ID": body["organization_id"]}


def _join(c: TestClient, owner: dict[str, str], email: str, role: str) -> dict[str, str]:
    invite = c.post("/api/v1/organization/invitations", headers=owner, json={"email": email, "role": role}).json()
    member = _signup(c, email, f"{role.title()} personal")
    accepted = c.post("/api/v1/auth/invitations/accept", headers={"Authorization": member["Authorization"]},
                      json={"token": invite["development_invitation_token"]})
    assert accepted.status_code == 200
    return {"Authorization": member["Authorization"], "X-Organization-ID": owner["X-Organization-ID"]}


def _enable_mfa(c: TestClient, h: dict[str, str]) -> str:
    setup = c.post("/api/v1/auth/mfa/setup", headers=h).json()
    secret = setup["provisioning_uri"].split("secret=")[1].split("&")[0]
    assert c.post("/api/v1/auth/mfa/enable", headers=h, json={"code": totp(secret)}).status_code == 200
    return secret


def test_totp_code_cannot_be_replayed_for_a_second_login(client):
    owner = _signup(client, "mfa@example.com", "MFA Org")
    secret = _enable_mfa(client, owner)
    # Wait for a fresh time step so the enable code is not the one reused.
    step = int(time.time()) // 30
    while int(time.time()) // 30 == step:
        time.sleep(0.2)
    code = totp(secret)
    first = client.post("/api/v1/auth/login", json={"email": "mfa@example.com", "password": PASSWORD, "totp_code": code})
    assert first.status_code == 200
    replay = client.post("/api/v1/auth/login", json={"email": "mfa@example.com", "password": PASSWORD, "totp_code": code})
    assert replay.status_code == 401, "an observed TOTP code must not authenticate a second session"


def test_password_reset_token_is_single_use_and_revokes_sessions(client):
    owner = _signup(client, "reset@example.com", "Reset Org")
    token = client.post("/api/v1/auth/forgot-password", json={"email": "reset@example.com"}).json()["development_reset_token"]
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "another long passphrase 1"}).status_code == 200
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "attacker passphrase 22"}).status_code == 400
    assert client.get("/api/v1/auth/me", headers=owner).status_code == 401


def test_invitation_is_single_use_and_bound_to_its_email(client):
    owner = _signup(client, "owner@example.com", "Invite Org")
    invite = client.post("/api/v1/organization/invitations", headers=owner,
                         json={"email": "invitee@example.com", "role": "ADMIN"}).json()
    token = invite["development_invitation_token"]
    intruder = _signup(client, "intruder@example.com", "Intruder Org")
    assert client.post("/api/v1/auth/invitations/accept", headers={"Authorization": intruder["Authorization"]},
                       json={"token": token}).status_code == 403
    invitee = _signup(client, "Invitee@Example.com", "Invitee Org")
    assert client.post("/api/v1/auth/invitations/accept", headers={"Authorization": invitee["Authorization"]},
                       json={"token": token}).status_code == 200
    assert client.post("/api/v1/auth/invitations/accept", headers={"Authorization": invitee["Authorization"]},
                       json={"token": token}).status_code == 400


@pytest.mark.parametrize("role", ["VIEWER", "AUDITOR", "ENGINEER"])
def test_non_admin_roles_cannot_escalate_or_administer(client, role):
    owner = _signup(client, "owner@example.com", "Role Org")
    member = _join(client, owner, f"{role.lower()}@example.com", role)
    members = client.get("/api/v1/organization/members", headers=owner).json()
    own = next(m for m in members if m["email"] == f"{role.lower()}@example.com")
    assert client.patch(f"/api/v1/organization/members/{own['membership_id']}", headers=member,
                        json={"role": "ADMIN"}).status_code == 403
    assert client.post("/api/v1/organization/invitations", headers=member,
                       json={"email": "friend@example.com", "role": "ADMIN"}).status_code == 403
    assert client.patch("/api/v1/organization", headers=member, json={"name": "Hijacked"}).status_code == 403
    assert client.post("/api/v1/organization/onboarding-reset", headers=member, json={}).status_code in {403, 422}
    assert client.delete("/api/v1/organization", headers=member).status_code in {403, 422}


def test_admin_cannot_seize_or_demote_ownership(client):
    owner = _signup(client, "owner@example.com", "Owner Org")
    admin = _join(client, owner, "admin@example.com", "ADMIN")
    members = client.get("/api/v1/organization/members", headers=owner).json()
    owner_row = next(m for m in members if m["role"] == "OWNER")
    admin_row = next(m for m in members if m["email"] == "admin@example.com")
    assert client.patch(f"/api/v1/organization/members/{owner_row['membership_id']}", headers=admin,
                        json={"role": "VIEWER"}).status_code == 409
    assert client.patch(f"/api/v1/organization/members/{admin_row['membership_id']}", headers=admin,
                        json={"role": "OWNER"}).status_code == 409
    assert client.post("/api/v1/organization/invitations", headers=admin,
                       json={"email": "x@example.com", "role": "OWNER"}).status_code == 422


def test_api_key_loses_authority_when_its_creator_is_downgraded(client):
    owner = _signup(client, "owner@example.com", "Key Org")
    engineer = _join(client, owner, "eng@example.com", "ENGINEER")
    key = client.post("/api/v1/api-keys", headers=engineer, json={"label": "ci", "scopes": ["projects:write", "projects:read"]})
    assert key.status_code == 201
    machine = {"Authorization": f"Bearer {key.json()['api_key']}", "X-Organization-ID": owner["X-Organization-ID"]}
    assert client.post("/api/v1/projects", headers=machine, json={"name": "allowed"}).status_code in {200, 201}
    members = client.get("/api/v1/organization/members", headers=owner).json()
    eng_row = next(m for m in members if m["email"] == "eng@example.com")
    assert client.patch(f"/api/v1/organization/members/{eng_row['membership_id']}", headers=owner,
                        json={"role": "VIEWER"}).status_code == 200
    assert client.post("/api/v1/projects", headers=machine, json={"name": "after downgrade"}).status_code == 403


def test_cookie_session_mutation_requires_csrf_token(client):
    login = client.post("/api/v1/auth/signup", json={"email": "csrf@example.com", "password": PASSWORD,
                                                     "organization_name": "CSRF Org"}).json()
    org = login["organization_id"]
    client.cookies.set("accessproof_session", login["session_token"])
    assert client.patch("/api/v1/organization", headers={"X-Organization-ID": org},
                        json={"name": "Forged"}).status_code == 403
    client.cookies.set("accessproof_csrf", "abc")
    assert client.patch("/api/v1/organization", headers={"X-Organization-ID": org, "X-CSRF-Token": "xyz"},
                        json={"name": "Forged"}).status_code == 403


def test_protect_approval_rejects_admin_and_owner_api_key(client):
    """D-28: only an interactive OWNER session may approve Protect."""
    owner = _signup(client, "approve-owner@example.com", "Approval Org")
    admin = _join(client, owner, "approve-admin@example.com", "ADMIN")
    assert client.post("/api/v1/current/ai-applications", headers=owner,
                       json={"application_id": "rag", "name": "RAG"}).status_code == 201
    key = client.post("/api/v1/api-keys", headers=owner, json={"label": "ci", "expires_in_days": 1})
    assert key.status_code == 201
    api = {"Authorization": f"Bearer {key.json()['api_key']}", "X-Organization-ID": owner["X-Organization-ID"]}
    body = {"confirm_text": "APPROVE PROTECT rag", "reviewer": "Impersonator"}
    url = "/api/v1/current/ai-applications/rag/protection/approve"
    as_admin = client.post(url, headers=admin, json=body)
    assert as_admin.status_code == 403 and as_admin.json()["detail"] == "OWNER_SESSION_REQUIRED"
    assert client.post(url, headers=api, json=body).status_code in (401, 403)
    # The owner reaches the next gate (no certified route), proving the 403s above are role refusals.
    assert client.post(url, headers=owner, json=body).json()["detail"] == "ROUTE_CERTIFICATE_REQUIRED_BEFORE_APPROVAL"
