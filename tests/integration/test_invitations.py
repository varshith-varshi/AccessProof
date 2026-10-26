from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def test_invitation_acceptance_adds_member_without_cross_org_trust():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        owner = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Primary",
            },
        ).json()
        invited = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "dev@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Personal",
            },
        ).json()
        oh = {
            "Authorization": f"Bearer {owner['session_token']}",
            "X-Organization-ID": owner["organization_id"],
        }
        inv = c.post(
            "/api/v1/organization/invitations",
            headers=oh,
            json={"email": "dev@example.com", "role": "ENGINEER"},
        )
        assert inv.status_code == 201
        token = inv.json()["development_invitation_token"]
        user_only = {"Authorization": f"Bearer {invited['session_token']}"}
        accepted = c.post(
            "/api/v1/auth/invitations/accept", headers=user_only, json={"token": token}
        )
        assert accepted.status_code == 200
        target_org = accepted.json()["organization_id"]
        assert target_org == owner["organization_id"]
        dh = {
            "Authorization": f"Bearer {invited['session_token']}",
            "X-Organization-ID": target_org,
        }
        assert c.get("/api/v1/projects", headers=dh).status_code == 200
