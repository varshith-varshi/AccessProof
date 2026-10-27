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
            checkpoint = {
                "run_id": run_id,
                "phase": "stable_denial",
                "source_confirmed": True,
                "resource": {"provider_id": "release-resource", "name": "release", "marker": job["oracle_canary"], "canary": job["oracle_canary"], "metadata": {}},
            }
            assert c.post(
                "/api/v1/runners/checkpoint",
                headers={"Authorization": f"Bearer {runner['runner_secret']}"},
                json={"runner_id": runner["runner_id"], "run_id": run_id, "checkpoint": checkpoint},
            ).status_code == 200
            observation = {"observed_at": "2026-01-01T00:00:00+00:00", "exposed": False, "response_hash": "a" * 64}
            result = {
                "run_id": run_id,
                "outcome": "PASS",
                "reason": "synthetic completed run",
                "source_ground_truth": "DENIED",
                "expected_slo_seconds": 300,
                "timeline": [
                    {"state": "VERIFYING_SOURCE_GROUND_TRUTH", "at": "2026-01-01T00:00:00+00:00"},
                    {"state": "VERIFYING_STABLE_DENIAL", "at": "2026-01-01T00:00:01+00:00"},
                    {"state": "PASSED", "at": "2026-01-01T00:00:02+00:00"},
                ],
                "observations": [observation, observation, observation],
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


def test_release_comparison_never_ignores_missing_required_suite():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        signup = c.post("/api/v1/auth/signup", json={
            "email": "missing-suite@example.com", "password": "correct horse battery staple",
            "organization_name": "Missing Suite Org",
        }).json()
        headers = {"Authorization": f"Bearer {signup['session_token']}", "X-Organization-ID": signup["organization_id"]}
        project = c.post("/api/v1/projects", headers=headers, json={"name": "Release Project"}).json()["id"]
        c.post("/api/v1/suites", headers=headers, json={"project_id": project, "name": "Required", "scenario": {
            "name": "required_scenario", "maximum_slo_seconds": 30, "timeout_seconds": 60, "severity": "REQUIRED",
        }}).raise_for_status()
        decision = c.post("/api/v1/releases/compare", headers=headers, json={
            "project_id": project, "candidate_release": "v-next", "block_on_inconclusive": False,
        })
        assert decision.status_code == 200
        body = decision.json()
        assert body["decision"] != "PASS"
        assert body["scenarios"][0]["candidate_outcome"] == "INCONCLUSIVE"
