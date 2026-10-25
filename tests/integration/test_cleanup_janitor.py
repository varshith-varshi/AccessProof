import asyncio
import json

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, CleanupTask, SessionLocal, TestRun, engine
from apps.worker.accessproof_worker.main import process_cleanup_task


def test_cleanup_failure_creates_durable_task_and_janitor_reconciles_it():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        signup = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "janitor@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Janitor Org",
            },
        ).json()
        headers = {
            "Authorization": f"Bearer {signup['session_token']}",
            "X-Organization-ID": signup["organization_id"],
        }
        project = c.post(
            "/api/v1/projects", headers=headers, json={"name": "Cleanup Project"}
        ).json()["id"]
        source = c.post(
            "/api/v1/sources",
            headers=headers,
            json={
                "project_id": project,
                "provider": "mock",
                "name": "Mock Source",
                "boundary": "mock-root",
                "credentials": {},
                "mutation_acknowledged": True,
            },
        ).json()["id"]
        suite = c.post(
            "/api/v1/suites",
            headers=headers,
            json={
                "project_id": project,
                "name": "Cleanup",
                "scenario": {
                    "name": "cleanup_test",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 180,
                },
            },
        ).json()["id"]
        reg = c.post(
            "/api/v1/runners/registrations", headers=headers, json={"project_id": project}
        ).json()["registration_token"]
        runner = c.post(
            "/api/v1/runners/exchange", json={"registration_token": reg, "name": "janitor-runner"}
        ).json()
        run_id = c.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project, "suite_id": suite, "source_connection_id": source},
        ).json()["id"]
        leased = c.post(
            "/api/v1/runners/lease",
            headers={"Authorization": f"Bearer {runner['runner_secret']}"}, json={"runner_id": runner["runner_id"]},
        ).json()["job"]
        assert leased["run_id"] == run_id
        result = {
            "run_id": run_id,
            # This test exercises durable cleanup, not security validation.
            # With no stable denial/source proof, a PASS must be rejected.
            "outcome": "INCONCLUSIVE",
            "reason": "Provider cleanup failed; the security result is not certified",
            "timeline": [
                {
                    "state": "CLEANING_UP",
                    "at": "2026-09-30T12:00:00+00:00",
                    "detail": "Cleanup pending: provider deletion failed",
                }
            ],
            "observations": [],
            "synthetic_resource": {
                "provider_id": "mock-orphan-1",
                "name": "AP_TEST_orphan.txt",
                "marker": "accessproof-generated",
                "canary": "REDACTED",
                "metadata": {},
            },
        }
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

    with SessionLocal() as db:
        run = db.get(TestRun, run_id)
        assert run.outcome == "INCONCLUSIVE"
        # This record is signed and stored: incomplete provider cleanup must
        # never make the server validator announce a successful security run.
        validation = json.loads(run.result_json)["server_validation"]
        assert validation["contract"] == "runner-attested-v1"
        assert validation["passed"] is False
        task = db.query(CleanupTask).filter(CleanupTask.run_id == run_id).one()
        assert task.status == "pending"
        task_id = task.id

    asyncio.run(process_cleanup_task(task_id))

    with SessionLocal() as db:
        task = db.get(CleanupTask, task_id)
        assert task.status == "completed"
        assert task.completed_at is not None
