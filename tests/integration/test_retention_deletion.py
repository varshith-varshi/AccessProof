from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.worker.accessproof_worker.main import process_all_retention
from apps.api.accessproof_api.db import (
    AuditEvent,
    Base,
    DeletionReceipt,
    EvidenceItem,
    Organization,
    Report,
    SessionLocal,
    TestRun as DbTestRun,
    engine,
)


def _signup(client: TestClient, email: str, org: str):
    body = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "correct horse battery staple", "organization_name": org},
    ).json()
    headers = {
        "Authorization": f"Bearer {body['session_token']}",
        "X-Organization-ID": body["organization_id"],
    }
    return body, headers


def test_project_deletion_refuses_active_run_then_deletes_tenant_project_records():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner, headers = _signup(client, "delete-project@example.com", "Deletion Org")
        project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Disposable"}
        ).json()
        suite = client.post(
            "/api/v1/suites",
            headers=headers,
            json={
                "project_id": project["id"],
                "name": "Suite",
                "scenario": {
                    "name": "direct",
                    "mutation": "direct_user_revoke",
                    "slo": {"maximum_seconds": 60},
                    "polling": {"initial_interval_seconds": 1, "maximum_interval_seconds": 2},
                    "timeout_seconds": 120,
                },
            },
        ).json()
        run = client.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project["id"], "suite_id": suite["id"]},
        ).json()
        blocked = client.request(
            "DELETE",
            f"/api/v1/projects/{project['id']}",
            headers=headers,
            json={"confirmation": "Disposable"},
        )
        assert blocked.status_code == 409
        with SessionLocal() as db:
            row = db.get(DbTestRun, run["id"])
            row.state = "FAILED"
            row.outcome = "FAIL"
            db.commit()
        deleted = client.request(
            "DELETE",
            f"/api/v1/projects/{project['id']}",
            headers=headers,
            json={"confirmation": "Disposable"},
        )
        assert deleted.status_code == 204
        assert client.get("/api/v1/projects", headers=headers).json() == []


def test_retention_purge_redacts_old_detailed_evidence_and_reports_but_keeps_run_metadata():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    old = datetime.now(timezone.utc) - timedelta(days=10)
    with TestClient(app) as client:
        owner, headers = _signup(client, "retention@example.com", "Retention Org")
        project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Retention Project"}
        ).json()
        suite = client.post(
            "/api/v1/suites",
            headers=headers,
            json={
                "project_id": project["id"],
                "name": "Suite",
                "scenario": {
                    "name": "direct",
                    "mutation": "direct_user_revoke",
                    "slo": {"maximum_seconds": 60},
                    "polling": {"initial_interval_seconds": 1, "maximum_interval_seconds": 2},
                    "timeout_seconds": 120,
                },
            },
        ).json()
        run = client.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project["id"], "suite_id": suite["id"]},
        ).json()
        with SessionLocal() as db:
            row = db.get(DbTestRun, run["id"])
            row.created_at = old
            row.state = "FAILED"
            row.outcome = "FAIL"
            row.result_json = '{"sensitive_detail":"derived-evidence"}'
            db.add(
                EvidenceItem(
                    organization_id=owner["organization_id"],
                    run_id=row.id,
                    observed_at=old.isoformat(),
                    exposed=True,
                )
            )
            db.add(
                Report(
                    organization_id=owner["organization_id"],
                    project_id=project["id"],
                    run_id=row.id,
                    report_hash="a" * 64,
                    generated_at=old,
                )
            )
            db.add(
                AuditEvent(
                    organization_id=owner["organization_id"],
                    action="old.event",
                    target_type="test",
                    created_at=old,
                )
            )
            db.commit()
        updated = client.patch(
            "/api/v1/organization/retention",
            headers=headers,
            json={"detailed_evidence_days": 1, "report_days": 1, "audit_days": 1},
        )
        assert updated.status_code == 200
        purge = client.post("/api/v1/organization/retention/purge", headers=headers)
        assert purge.status_code == 200
        counts = purge.json()
        assert counts["evidence_deleted"] >= 1
        assert counts["run_results_redacted"] >= 1
        assert counts["reports_deleted"] >= 1
        assert counts["audit_events_deleted"] >= 1
        with SessionLocal() as db:
            row = db.get(DbTestRun, run["id"])
            assert row is not None and row.result_json is None
            assert db.scalar(select(Report).where(Report.run_id == run["id"])) is None


def test_owner_can_delete_organization_after_cleanup_and_receipt_contains_only_hashes():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner, headers = _signup(client, "delete-org@example.com", "Delete Me Org")
        client.post("/api/v1/projects", headers=headers, json={"name": "Disposable"})
        response = client.request(
            "DELETE",
            "/api/v1/organization",
            headers=headers,
            json={"confirmation": "Delete Me Org"},
        )
        assert response.status_code == 204
    with SessionLocal() as db:
        assert db.get(Organization, owner["organization_id"]) is None
        receipt = db.scalar(select(DeletionReceipt))
        assert receipt is not None
        assert len(receipt.organization_id_hash) == 64
        assert owner["organization_id"] not in receipt.organization_id_hash


def test_worker_retention_sweep_applies_configured_policy_without_manual_api_call():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    old = datetime.now(timezone.utc) - timedelta(days=10)
    with TestClient(app) as client:
        owner, headers = _signup(client, "retention-worker@example.com", "Retention Worker Org")
        project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Retention Project"}
        ).json()
        suite = client.post(
            "/api/v1/suites",
            headers=headers,
            json={
                "project_id": project["id"],
                "name": "Suite",
                "scenario": {
                    "name": "direct",
                    "mutation": "direct_user_revoke",
                    "slo": {"maximum_seconds": 60},
                    "polling": {"initial_interval_seconds": 1, "maximum_interval_seconds": 2},
                    "timeout_seconds": 120,
                },
            },
        ).json()
        run = client.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project["id"], "suite_id": suite["id"]},
        ).json()
        with SessionLocal() as db:
            row = db.get(DbTestRun, run["id"])
            row.created_at = old
            row.state = "FAILED"
            row.outcome = "FAIL"
            row.result_json = '{"detail":"old"}'
            db.add(
                EvidenceItem(
                    organization_id=owner["organization_id"],
                    run_id=row.id,
                    observed_at=old.isoformat(),
                    exposed=True,
                )
            )
            db.add(
                Report(
                    organization_id=owner["organization_id"],
                    project_id=project["id"],
                    run_id=row.id,
                    report_hash="b" * 64,
                    generated_at=old,
                )
            )
            db.commit()
        assert (
            client.patch(
                "/api/v1/organization/retention",
                headers=headers,
                json={"detailed_evidence_days": 1, "report_days": 1, "audit_days": 365},
            ).status_code
            == 200
        )
    summary = process_all_retention()
    assert owner["organization_id"] in summary
    assert summary[owner["organization_id"]]["evidence_deleted"] >= 1
    with SessionLocal() as db:
        assert db.get(DbTestRun, run["id"]).result_json is None
        assert db.scalar(select(Report).where(Report.run_id == run["id"])) is None
