"""D-19 control plane: only a never-activated, single-source Microsoft app whose
ONLY missing requirement is the certificate is granted a certification window."""
import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.db import (
    AIApplication, Base, engine, SessionLocal, SourceConnection, ProviderSyncCursor, Project,
)


def test_certification_window_only_for_pending_uncertified_fresh_microsoft_app():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        account = client.post("/api/v1/auth/signup", json={
            "email": "ms-window@example.com", "password": "correct horse battery staple",
            "organization_name": "Window Test"}).json()
        org = account["organization_id"]
        owner = {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": org}
        with SessionLocal() as db:
            project = db.query(Project).filter(Project.organization_id == org).first()
            if project is None:
                project = Project(organization_id=org, name="p")
                db.add(project)
                db.flush()
            source = SourceConnection(
                organization_id=org, project_id=project.id, name="SharePoint lab", provider="sharepoint",
                boundary="root", status="connected", last_validated_at=datetime.now(timezone.utc),
                encrypted_credentials=api_module._secret_box.encrypt(json.dumps({
                    "grant_type": "client_credentials", "tenant_id": "11111111-2222-3333-4444-555555555555",
                    "drive_id": "d", "test_root_item_id": "root"})))
            db.add(source)
            db.flush()
            for kind in ("acl", "directory"):
                db.add(ProviderSyncCursor(organization_id=org, source_id=source.id, provider="sharepoint",
                                          sync_kind=kind, status="connected",
                                          last_success_at=datetime.now(timezone.utc)))
            db.commit()
            source_id = source.id
        guard_id = client.post("/api/v1/guards", headers=owner, json={"name": "g"}).json()["id"]
        r = client.post("/api/v1/current/ai-applications", headers=owner, json={
            "application_id": "sp-rag", "name": "SP RAG", "guard_id": guard_id,
            "source_id": source_id, "adapter_type": "accessproof-gateway"})
        assert r.status_code == 201, r.text
        token = client.post(f"/api/v1/guards/{guard_id}/enrollments", headers=owner, json={}).json()["enrollment_token"]
        cred = client.post("/api/v1/guards/exchange", json={"enrollment_token": token, "version": "1.0.0"}).json()["guard_credential"]
        machine = {"Authorization": f"Bearer {cred}"}

        def binding():
            resp = client.get(f"/api/v1/guards/{guard_id}/policies", headers=machine)
            assert resp.status_code == 200, resp.text
            (b,) = resp.json()["applications"]
            return b

        def set_mode(mode):
            with SessionLocal() as db:
                db.query(AIApplication).filter(AIApplication.application_id == "sp-rag").update({"mode": mode})
                db.commit()

        # Shadow: never a window.
        assert binding()["certification_window"] is False
        # Never-activated Protect request, fresh syncs, no certificate -> window, health false.
        set_mode("protect_pending")
        b = binding()
        assert b["mode"] == "protect" and b["source_acl_healthy"] is False and b["certification_window"] is True
        # An ACTIVATED app never gets a window, even with the same source.
        set_mode("protect")
        assert binding()["certification_window"] is False
        # Stale ACL sync: the certificate is no longer the only missing piece.
        set_mode("protect_pending")
        with SessionLocal() as db:
            db.query(ProviderSyncCursor).filter(ProviderSyncCursor.sync_kind == "acl").update(
                {"last_success_at": datetime.now(timezone.utc) - timedelta(days=1)})
            db.commit()
        assert binding()["certification_window"] is False
        # Disconnected source: no window.
        with SessionLocal() as db:
            db.query(ProviderSyncCursor).update({"last_success_at": datetime.now(timezone.utc)})
            db.query(SourceConnection).filter(SourceConnection.id == source_id).update({"status": "error"})
            db.commit()
        assert binding()["certification_window"] is False
