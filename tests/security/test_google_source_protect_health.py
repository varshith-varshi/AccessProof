"""Protect must not trust directory/ACL cursors for an uncredentialed Drive source."""
import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, SourceConnection, ProviderSyncCursor, GuardPermissionEvent, GuardSubject, GuardGroup,
)


def test_google_policy_binding_unhealthy_without_usable_credentials(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": "drive-protect-health@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Source Health Test",
        })
        assert signup.status_code == 201, signup.text
        account = signup.json()
        owner_headers = {
            "Authorization": f"Bearer {account['session_token']}",
            "X-Organization-ID": account["organization_id"],
        }
        source_result = client.post("/api/v1/current/sources", headers=owner_headers, json={
            "provider": "google-drive", "name": "No Credentials",
            "boundary": "approved-root", "credentials": {},
        })
        assert source_result.status_code == 201, source_result.text
        source_id = source_result.json()["id"]
        guard_result = client.post("/api/v1/guards", headers=owner_headers, json={"name": "staging-guard"})
        assert guard_result.status_code == 201, guard_result.text
        guard_id = guard_result.json()["id"]
        application_result = client.post("/api/v1/current/ai-applications", headers=owner_headers, json={
            "application_id": "employee-rag", "name": "Employee RAG",
            "guard_id": guard_id, "source_id": source_id, "adapter_type": "generic-python",
        })
        assert application_result.status_code == 201, application_result.text
        enrollment = client.post(
            f"/api/v1/guards/{guard_id}/enrollments", headers=owner_headers, json={}
        )
        assert enrollment.status_code == 201, enrollment.text
        exchange = client.post("/api/v1/guards/exchange", json={
            "enrollment_token": enrollment.json()["enrollment_token"], "version": "1.0.0",
        })
        assert exchange.status_code == 201, exchange.text
        machine_headers = {"Authorization": f"Bearer {exchange.json()['guard_credential']}"}

        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            source.status = "connected"
            source.last_validated_at = datetime.now(timezone.utc)
            # Simulate healthy-looking, fresh snapshots that were generated
            # before a credential was removed or a source was disconnected.
            for kind in ("acl", "directory"):
                db.add(ProviderSyncCursor(
                    organization_id=account["organization_id"],
                    source_id=source_id, provider="google-drive",
                    sync_kind=kind, status="connected",
                    last_success_at=datetime.now(timezone.utc),
                ))
            db.commit()

        def binding_health():
            response = client.get(f"/api/v1/guards/{guard_id}/policies", headers=machine_headers)
            assert response.status_code == 200, response.text
            bindings = response.json()["applications"]
            assert len(bindings) == 1
            return bindings[0]["source_acl_healthy"]

        assert binding_health() is False
        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            source.encrypted_credentials = api_module._secret_box.encrypt(json.dumps({
                "access_token": "synthetic-only",
                "test_root_folder_id": "approved-root",
            }))
            db.commit()
        assert binding_health() is True
        # Production must not trust pre-migration directory IDs as Drive ACL
        # permission IDs, even if all sync timestamps appear healthy.
        from apps.api.accessproof_api.config import Settings
        with monkeypatch.context() as patch:
            patch.setattr(api_module, "settings", Settings(env="production"))
            assert binding_health() is False
            with SessionLocal() as db:
                db.add(GuardSubject(
                    organization_id=account["organization_id"], provider="google-drive",
                    provider_subject_id="workspace-alice", status="active",
                ))
                db.add(GuardGroup(
                    organization_id=account["organization_id"], provider="google-drive",
                    provider_group_id="workspace-finance", status="active",
                ))
                db.commit()
            assert binding_health() is False
            with SessionLocal() as db:
                employee = db.query(GuardSubject).filter_by(provider_subject_id="workspace-alice").one()
                group = db.query(GuardGroup).filter_by(provider_group_id="workspace-finance").one()
                employee.drive_permission_id = "drive-alice"
                group.drive_permission_id = "drive-finance"
                db.commit()
            assert binding_health() is True

        # A completed provider snapshot does NOT mean queued revocations have
        # reached the Guard. Stay fail-closed through the event-processing gap.
        with SessionLocal() as db:
            event = GuardPermissionEvent(
                organization_id=account["organization_id"], source_id=source_id,
                provider="google-drive", provider_revision=1,
                subject_id="synthetic-subject", resource_id="synthetic-resource",
                change_type="grant_revoke", dedupe_key="queued-revoke-test",
                processing_status="queued",
            )
            db.add(event)
            db.commit()
            event_id = event.id
        assert binding_health() is False
        with SessionLocal() as db:
            event = db.get(GuardPermissionEvent, event_id)
            event.processing_status = "resolved"
            db.commit()
        assert binding_health() is True

        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            source.status = "degraded"
            db.commit()
        assert binding_health() is False
