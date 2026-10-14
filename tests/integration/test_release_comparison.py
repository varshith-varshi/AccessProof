from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def test_release_comparison_detects_blocking_latency_regression():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        signup = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "releases@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Release Org",
            },
        ).json()
        h = {
            "Authorization": f"Bearer {signup['session_token']}",
            "X-Organization-ID": signup["organization_id"],
        }
        project = c.post("/api/v1/projects", headers=h, json={"name": "Release Project"}).json()[
            "id"
        ]
        suite = c.post(
            "/api/v1/suites",
            headers=h,
            json={
                "project_id": project,
                "name": "Group revoke",
                "scenario": {
                    "name": "group_revoke",
                    "maximum_slo_seconds": 300,
                    "timeout_seconds": 600,
                    "severity": "REQUIRED",
                },
            },
        ).json()["id"]
        reg = c.post(
            "/api/v1/runners/registrations", headers=h, json={"project_id": project}
        ).json()["registration_token"]
        runner = c.post(
            "/api/v1/runners/exchange", json={"registration_token": reg, "name": "release-runner"}
        ).json()

        def finish(release, latency):
            run_id = c.post(
                "/api/v1/runs",
                headers=h,
                json={"project_id": project, "suite_id": suite, "release": release},
            ).json()["id"]
            job = c.post(
                "/api/v1/runners/lease",
                headers={"Authorization": f"Bearer {runner['runner_secret']}"}, json={"runner_id": runner["runner_id"]},
            ).json()["job"]
            assert job["run_id"] == run_id
            result = {
                "run_id": run_id,
                "outcome": "PASS",
                "reason": "synthetic completed run",
                "timeline": [],
                "observations": [],
                "synthetic_resource": None,
                "derived": {"stable_propagation_latency_seconds": latency},
                "source_capabilities": ["DIRECT_USER_REVOKE"],
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

        finish("4.7", 40)
        finish("4.8", 200)
        comparison = c.post(
            "/api/v1/releases/compare",
            headers=h,
            json={
                "project_id": project,
                "candidate_release": "4.8",
                "baseline_policy": "previous_successful",
                "maximum_absolute_regression_seconds": 30,
            },
        )
        assert comparison.status_code == 200
        data = comparison.json()
        assert data["decision"] == "FAIL"
        assert data["scenarios"][0]["absolute_regression_seconds"] == 160
        assert data["scenarios"][0]["blocking"] is True
