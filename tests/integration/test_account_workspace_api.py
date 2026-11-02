"""Account (/auth/me) and workspace rename used by the web console."""
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import AuditEvent, Base, SessionLocal, engine

PASSWORD = "correct horse battery staple"


def _signup(c: TestClient, email: str, org: str) -> dict:
    body = c.post("/api/v1/auth/signup", json={"email": email, "password": PASSWORD,
                                                "organization_name": org}).json()
    return {"Authorization": f"Bearer {body['session_token']}",
            "X-Organization-ID": body["organization_id"], "_org": body["organization_id"],
            "_token": body["session_token"]}


def _h(h: dict) -> dict:
    return {k: v for k, v in h.items() if not k.startswith("_")}


def test_me_lists_only_own_workspaces_and_rename_is_admin_only_and_audited():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        owner = _signup(c, "owner@example.com", "Northwind Labs")
        other = _signup(c, "other@example.com", "Contoso")
        me = c.get("/api/v1/auth/me", headers=_h(owner))
        assert me.status_code == 200
        body = me.json()
        assert body["user"]["email"] == "owner@example.com"
        assert body["user"]["mfa_enabled"] is False
        assert body["role"] == "OWNER" and body["active_organization_id"] == owner["_org"]
        assert [o["name"] for o in body["organizations"]] == ["Northwind Labs"]
        assert "password_hash" not in str(body)

        # Rename: trims whitespace, persists, audited.
        renamed = c.patch("/api/v1/organization", headers=_h(owner), json={"name": "  Northwind   AI  "})
        assert renamed.status_code == 200 and renamed.json()["name"] == "Northwind AI"
        assert c.get("/api/v1/organization", headers=_h(owner)).json()["name"] == "Northwind AI"
        with SessionLocal() as db:
            assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "ORGANIZATION_RENAMED")) is not None
        assert c.patch("/api/v1/organization", headers=_h(owner), json={"name": " "}).status_code == 422
        assert c.patch("/api/v1/organization", headers=_h(owner), json={"name": "ok", "extra": 1}).status_code == 422

        # Cross-tenant: another user cannot act on, or see, this workspace.
        forged = {"Authorization": f"Bearer {other['_token']}", "X-Organization-ID": owner["_org"]}
        assert c.patch("/api/v1/organization", headers=forged, json={"name": "Hijacked"}).status_code in {401, 403}
        assert c.get("/api/v1/auth/me", headers=forged).status_code in {401, 403}
        assert [o["name"] for o in c.get("/api/v1/auth/me", headers=_h(other)).json()["organizations"]] == ["Contoso"]

        # A VIEWER member cannot rename.
        invite = c.post("/api/v1/organization/invitations", headers=_h(owner),
                        json={"email": "viewer@example.com", "role": "VIEWER"}).json()
        viewer = _signup(c, "viewer@example.com", "Viewer personal")
        accepted = c.post("/api/v1/auth/invitations/accept",
                          headers={"Authorization": f"Bearer {viewer['_token']}"},
                          json={"token": invite["development_invitation_token"]})
        assert accepted.status_code == 200
        vh = {"Authorization": f"Bearer {viewer['_token']}", "X-Organization-ID": owner["_org"]}
        assert c.patch("/api/v1/organization", headers=vh, json={"name": "Nope"}).status_code == 403
        viewer_me = c.get("/api/v1/auth/me", headers=vh).json()
        assert viewer_me["role"] == "VIEWER"
        assert sorted(o["name"] for o in viewer_me["organizations"]) == ["Northwind AI", "Viewer personal"]
