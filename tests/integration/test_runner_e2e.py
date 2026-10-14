import asyncio
from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base,
    Report,
    RunStateTransition,
    EvidenceItem,
    TestRun as DbTestRun,
    engine,
    SessionLocal,
)
from apps.runner.accessproof_runner.main import execute_job


def test_control_plane_runner_mock_end_to_end():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        s = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "runner@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Runner Org",
            },
        ).json()
        h = {
            "Authorization": f"Bearer {s['session_token']}",
            "X-Organization-ID": s["organization_id"],
        }
        project = c.post("/api/v1/projects", headers=h, json={"name": "Mock Project"}).json()["id"]
        suite = c.post(
            "/api/v1/suites",
            headers=h,
            json={
                "project_id": project,
                "name": "Mock Revoke",
                "scenario": {
                    "name": "mock_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 180,
                    "polling": {
                        "initial_interval_seconds": 10,
                        "maximum_interval_seconds": 10,
                        "backoff_multiplier": 1,
                        "jitter_ratio": 0,
                        "maximum_probes": 100,
                    },
                    "stability": {
                        "required_clean_observations": 3,
                        "required_clean_duration_seconds": 20,
                    },
                },
            },
        ).json()["id"]
        reg = c.post(
            "/api/v1/runners/registrations", headers=h, json={"project_id": project}
        ).json()["registration_token"]
        runner = c.post(
            "/api/v1/runners/exchange", json={"registration_token": reg, "name": "local-runner"}
        ).json()
        run_id = c.post(
            "/api/v1/runs",
            headers=h,
            json={"project_id": project, "suite_id": suite, "release": "v1"},
        ).json()["id"]
        lease = c.post(
            "/api/v1/runners/lease",
            headers={"Authorization": f"Bearer {runner['runner_secret']}"}, json={"runner_id": runner["runner_id"]},
        )
        assert lease.status_code == 200
        job = lease.json()["job"]
        assert job["run_id"] == run_id and job["type"] == "permission_regression_v1"
        result = asyncio.run(execute_job(job))
        assert result["outcome"] == "FAIL"
        done = c.post(
            "/api/v1/runners/complete",
            headers={"Authorization": f"Bearer {runner['runner_secret']}"},
            json={
                "runner_id": runner["runner_id"],
                "run_id": run_id,
                "result": result,
            },
        )
        assert done.status_code == 200
        detail = c.get(f"/api/v1/runs/{run_id}", headers=h).json()
        assert detail["outcome"] == "FAIL"
        assert c.get(f"/api/v1/reports/{run_id}.json", headers=h).status_code == 200
        assert c.get(f"/api/v1/reports/{run_id}.html", headers=h).status_code == 200
        assert c.get(f"/api/v1/reports/{run_id}.pdf", headers=h).content.startswith(b"%PDF")
        assert c.get(f"/api/v1/reports/{run_id}.junit.xml", headers=h).status_code == 200
        sarif = c.get(f"/api/v1/reports/{run_id}.sarif.json", headers=h)
        assert sarif.status_code == 200 and sarif.json()["version"] == "2.1.0"
        integrity = c.get(f"/api/v1/reports/{run_id}/integrity", headers=h)
        assert integrity.status_code == 200 and integrity.json()["verified"] is True
    with SessionLocal() as db:
        assert db.query(Report).filter(Report.run_id == run_id).count() == 1
        assert db.query(RunStateTransition).filter(RunStateTransition.run_id == run_id).count() > 0
        assert db.query(EvidenceItem).filter(EvidenceItem.run_id == run_id).count() > 0


def test_expired_lease_recovery_preserves_checkpoint_and_mutation_journal():
    from datetime import datetime, timedelta, timezone
    from apps.api.accessproof_api.db import MutationJournal, RunnerCheckpoint

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        s = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "recover@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Recover Org",
            },
        ).json()
        h = {
            "Authorization": f"Bearer {s['session_token']}",
            "X-Organization-ID": s["organization_id"],
        }
        project = c.post("/api/v1/projects", headers=h, json={"name": "Recover Project"}).json()[
            "id"
        ]
        suite = c.post(
            "/api/v1/suites",
            headers=h,
            json={
                "project_id": project,
                "name": "Recover Revoke",
                "scenario": {
                    "name": "recover_revoke",
                    "mutation": "direct_user_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 180,
                },
            },
        ).json()["id"]
        reg1 = c.post(
            "/api/v1/runners/registrations", headers=h, json={"project_id": project}
        ).json()["registration_token"]
        r1 = c.post(
            "/api/v1/runners/exchange", json={"registration_token": reg1, "name": "runner-one"}
        ).json()
        run_id = c.post(
            "/api/v1/runs",
            headers=h,
            json={"project_id": project, "suite_id": suite, "release": "v-recover"},
        ).json()["id"]
        first_lease = c.post(
            "/api/v1/runners/lease",
            headers={"Authorization": f"Bearer {r1['runner_secret']}"}, json={"runner_id": r1["runner_id"]},
        ).json()["job"]
        assert first_lease["run_id"] == run_id

        now = datetime.now(timezone.utc)
        checkpoint = {
            "run_id": run_id,
            "phase": "mutation_requested",
            "resource": {
                "provider_id": "mock-resource-1",
                "name": "secret.txt",
                "marker": "accessproof-generated",
                "canary": "AP-CANARY-X",
                "metadata": {},
            },
            "metrics": {
                "mutation_requested_at": now.isoformat(),
                "mutation_provider_acknowledged_at": None,
                "source_ground_truth_changed_at": None,
                "first_post_mutation_probe_at": None,
                "last_observed_exposure_at": None,
                "first_observed_denial_at": None,
                "stable_denial_at": None,
                "completed_at": None,
            },
            "observations": [],
            "timeline": [],
            "probe_count": 0,
            "polling_interval_seconds": 10,
            "clean_count": 0,
            "clean_started_at": None,
            "mutation_operation_id": "op-recovery-1",
            "mutation_provider_request_id": "provider-req-123",
            "mutation_acknowledged": False,
            "source_confirmed": False,
        }
        saved = c.post(
            "/api/v1/runners/checkpoint",
            headers={"Authorization": f"Bearer {r1['runner_secret']}"},
            json={
                "runner_id": r1["runner_id"],
                "run_id": run_id,
                "checkpoint": checkpoint,
            },
        )
        assert saved.status_code == 200

        with SessionLocal() as db:
            run = db.get(DbTestRun, run_id)
            run.state = "RUNNING"
            run.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
            db.commit()

        reg2 = c.post(
            "/api/v1/runners/registrations", headers=h, json={"project_id": project}
        ).json()["registration_token"]
        r2 = c.post(
            "/api/v1/runners/exchange", json={"registration_token": reg2, "name": "runner-two"}
        ).json()
        recovered = c.post(
            "/api/v1/runners/lease",
            headers={"Authorization": f"Bearer {r2['runner_secret']}"}, json={"runner_id": r2["runner_id"]},
        )
        assert recovered.status_code == 200
        recovered_job = recovered.json()["job"]
        assert recovered_job["run_id"] == run_id
        assert recovered_job["checkpoint"]["phase"] == "mutation_requested"
        assert recovered_job["checkpoint"]["mutation_operation_id"] == "op-recovery-1"

        confirmed = dict(checkpoint)
        confirmed["phase"] = "source_confirmed"
        confirmed["mutation_acknowledged"] = True
        confirmed["source_confirmed"] = True
        confirmed["metrics"] = dict(checkpoint["metrics"])
        confirmed["metrics"]["mutation_provider_acknowledged_at"] = (
            now + timedelta(seconds=1)
        ).isoformat()
        confirmed["metrics"]["source_ground_truth_changed_at"] = (
            now + timedelta(seconds=2)
        ).isoformat()
        saved2 = c.post(
            "/api/v1/runners/checkpoint",
            headers={"Authorization": f"Bearer {r2['runner_secret']}"},
            json={
                "runner_id": r2["runner_id"],
                "run_id": run_id,
                "checkpoint": confirmed,
            },
        )
        assert saved2.status_code == 200

    with SessionLocal() as db:
        cp = db.get(RunnerCheckpoint, run_id)
        assert cp is not None and cp.phase == "source_confirmed" and cp.runner_id == r2["runner_id"]
        journal = (
            db.query(MutationJournal).filter(MutationJournal.operation_id == "op-recovery-1").one()
        )
        assert journal.status == "confirmed"
        assert journal.requested_at is not None
        assert journal.acknowledged_at is not None
        assert journal.confirmed_at is not None
        assert journal.provider_request_id == "provider-req-123"


def test_report_signature_detects_tampering():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        s = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "integrity@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Integrity Org",
            },
        ).json()
        h = {
            "Authorization": f"Bearer {s['session_token']}",
            "X-Organization-ID": s["organization_id"],
        }
        project = c.post("/api/v1/projects", headers=h, json={"name": "Integrity Project"}).json()[
            "id"
        ]
        suite = c.post(
            "/api/v1/suites",
            headers=h,
            json={
                "project_id": project,
                "name": "Integrity Suite",
                "scenario": {
                    "name": "integrity_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 180,
                },
            },
        ).json()["id"]
        reg = c.post(
            "/api/v1/runners/registrations", headers=h, json={"project_id": project}
        ).json()["registration_token"]
        runner = c.post(
            "/api/v1/runners/exchange", json={"registration_token": reg, "name": "integrity-runner"}
        ).json()
        run_id = c.post(
            "/api/v1/runs", headers=h, json={"project_id": project, "suite_id": suite}
        ).json()["id"]
        job = c.post(
            "/api/v1/runners/lease",
            headers={"Authorization": f"Bearer {runner['runner_secret']}"}, json={"runner_id": runner["runner_id"]},
        ).json()["job"]
        result = asyncio.run(execute_job(job))
        c.post(
            "/api/v1/runners/complete",
            headers={"Authorization": f"Bearer {runner['runner_secret']}"},
            json={
                "runner_id": runner["runner_id"],
                "run_id": run_id,
                "result": result,
            },
        ).raise_for_status()
        assert c.get(f"/api/v1/reports/{run_id}/integrity", headers=h).json()["verified"] is True
        with SessionLocal() as db:
            run = db.get(DbTestRun, run_id)
            payload = __import__("json").loads(run.result_json)
            payload["reason"] = "tampered after signing"
            run.result_json = __import__("json").dumps(payload, sort_keys=True)
            db.commit()
        assert c.get(f"/api/v1/reports/{run_id}/integrity", headers=h).json()["verified"] is False
