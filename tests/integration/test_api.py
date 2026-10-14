from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def reset_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def signup(client: TestClient, email: str, org: str):
    r = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "correct horse battery staple", "organization_name": org},
    )
    assert r.status_code == 201, r.text
    return r.json()


def headers(session):
    return {
        "Authorization": f"Bearer {session['session_token']}",
        "X-Organization-ID": session["organization_id"],
    }


def test_signup_project_suite_run_flow():
    reset_db()
    with TestClient(app) as client:
        s = signup(client, "alice@example.com", "Acme")
        h = headers(s)
        p = client.post("/api/v1/projects", headers=h, json={"name": "RAG staging"})
        assert p.status_code == 201
        project = p.json()["id"]
        suite = client.post(
            "/api/v1/suites",
            headers=h,
            json={
                "project_id": project,
                "name": "Revoke",
                "scenario": {
                    "name": "direct_user_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 120,
                },
            },
        )
        assert suite.status_code == 201, suite.text
        run = client.post(
            "/api/v1/runs",
            headers=h,
            json={"project_id": project, "suite_id": suite.json()["id"], "release": "v1"},
        )
        assert run.status_code == 202, run.text
        detail = client.get(f"/api/v1/runs/{run.json()['id']}", headers=h)
        assert detail.status_code == 200
        assert detail.json()["release"] == "v1"


def test_mutation_requires_explicit_acknowledgement():
    reset_db()
    with TestClient(app) as client:
        s = signup(client, "alice@example.com", "Acme")
        h = headers(s)
        project = client.post("/api/v1/projects", headers=h, json={"name": "Proj"}).json()["id"]
        source = client.post(
            "/api/v1/sources",
            headers=h,
            json={
                "project_id": project,
                "provider": "microsoft365",
                "name": "test",
                "boundary": "site/test",
                "mutation_acknowledged": False,
                "credentials": {},
            },
        )
        assert source.status_code == 201
        suite = client.post(
            "/api/v1/suites",
            headers=h,
            json={
                "project_id": project,
                "name": "Revoke",
                "scenario": {
                    "name": "direct_user_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 120,
                },
            },
        ).json()["id"]
        run = client.post(
            "/api/v1/runs",
            headers=h,
            json={
                "project_id": project,
                "suite_id": suite,
                "source_connection_id": source.json()["id"],
            },
        )
        assert run.status_code == 409


def test_private_cloud_target_blocked_without_runner():
    reset_db()
    with TestClient(app) as client:
        s = signup(client, "alice@example.com", "Acme")
        h = headers(s)
        project = client.post("/api/v1/projects", headers=h, json={"name": "Proj"}).json()["id"]
        r = client.post(
            "/api/v1/targets",
            headers=h,
            json={
                "project_id": project,
                "name": "internal",
                "url": "http://127.0.0.1:9000/chat",
                "runner_mode": False,
            },
        )
        assert r.status_code == 422


def test_runner_registration_token_is_one_time():
    reset_db()
    with TestClient(app) as client:
        s = signup(client, "alice@example.com", "Acme")
        h = headers(s)
        project = client.post("/api/v1/projects", headers=h, json={"name": "Proj"}).json()["id"]
        reg = client.post("/api/v1/runners/registrations", headers=h, json={"project_id": project})
        assert reg.status_code == 201
        token = reg.json()["registration_token"]
        first = client.post(
            "/api/v1/runners/exchange",
            json={"registration_token": token, "name": "runner-1", "version": "0.1.0"},
        )
        assert first.status_code == 201
        second = client.post(
            "/api/v1/runners/exchange",
            json={"registration_token": token, "name": "runner-2", "version": "0.1.0"},
        )
        assert second.status_code == 401


def test_runner_enrollment_code_is_project_scoped_revocable_and_reports_capabilities():
    reset_db()
    with TestClient(app) as client:
        session = signup(client, "enrollment@example.com", "Enrollment Org")
        h = headers(session)
        project = client.post("/api/v1/projects", headers=h, json={"name": "Secure runner"}).json()["id"]
        issued = client.post(
            "/api/v1/runners/registrations",
            headers=h,
            json={"project_id": project, "display_name": "ubuntu-pilot", "expires_in_minutes": 15},
        )
        assert issued.status_code == 201
        code = issued.json()["registration_token"]
        assert code.startswith("AP-ENROLL-")
        listed = client.get(f"/api/v1/runners/registrations?project_id={project}", headers=h)
        assert listed.status_code == 200
        registration = listed.json()[0]
        assert registration["display_name"] == "ubuntu-pilot"
        assert registration["status"] == "active"
        revoked = client.post(f"/api/v1/runners/registrations/{registration['id']}/revoke", headers=h)
        assert revoked.status_code == 200
        rejected = client.post(
            "/api/v1/runners/exchange", json={"registration_token": code, "name": "blocked-runner"}
        )
        assert rejected.status_code == 401

        active = client.post(
            "/api/v1/runners/registrations",
            headers=h,
            json={"project_id": project, "display_name": "ubuntu-pilot"},
        ).json()["registration_token"]
        enrolled = client.post(
            "/api/v1/runners/exchange",
            json={
                "registration_token": active,
                "name": "ubuntu-pilot",
                "version": "1.0.0",
                "platform": "linux",
                "architecture": "x86_64",
                "capabilities": {"actions": ["ai_target.probe"]},
            },
        )
        assert enrolled.status_code == 201
        runner = enrolled.json()
        heartbeat = client.post(
            "/api/v1/runners/heartbeat",
            headers={"Authorization": f"Bearer {runner['runner_secret']}"},
            json={
                "runner_id": runner["runner_id"],
                "version": "1.0.0",
                "platform": "linux",
                "architecture": "x86_64",
                "capabilities": {"actions": ["ai_target.probe", "evidence.collect"]},
            },
        )
        assert heartbeat.status_code == 200
        discovered = client.get(f"/api/v1/runners?project_id={project}", headers=h).json()[0]
        assert discovered["platform"] == "linux"
        assert discovered["capabilities"]["actions"] == ["ai_target.probe", "evidence.collect"]


def test_run_history_and_bearer_runner_authentication():
    reset_db()
    with TestClient(app) as client:
        s = signup(client, "history@example.com", "History Org")
        h = headers(s)
        project = client.post("/api/v1/projects", headers=h, json={"name": "History"}).json()["id"]
        suite = client.post(
            "/api/v1/suites",
            headers=h,
            json={"project_id": project, "name": "Scenario", "scenario": {"name": "mock_revoke"}},
        ).json()["id"]
        first = client.post(
            "/api/v1/runs", headers=h, json={"project_id": project, "suite_id": suite, "release": "one"}
        ).json()["id"]
        second = client.post(
            "/api/v1/runs", headers=h, json={"project_id": project, "suite_id": suite, "release": "two"}
        ).json()["id"]
        history = client.get(f"/api/v1/runs?project_id={project}", headers=h)
        assert history.status_code == 200
        assert [row["id"] for row in history.json()] == [second, first]
        detail = client.get(f"/api/v1/runs/{second}", headers=h).json()
        assert detail["project_id"] == project and detail["state"] == "CREATED"

        registration = client.post(
            "/api/v1/runners/registrations", headers=h, json={"project_id": project}
        ).json()["registration_token"]
        runner = client.post(
            "/api/v1/runners/exchange", json={"registration_token": registration, "name": "secure-runner"}
        ).json()
        auth = {"Authorization": f"Bearer {runner['runner_secret']}"}
        heartbeat = client.post(
            "/api/v1/runners/heartbeat", headers=auth, json={"runner_id": runner["runner_id"], "version": "1.0.0"}
        )
        assert heartbeat.status_code == 200
        body_credential = client.post(
            "/api/v1/runners/heartbeat",
            json={
                "runner_id": runner["runner_id"],
                "runner_secret": runner["runner_secret"],
                "version": "1.0.0",
            },
        )
        assert body_credential.status_code == 422
        leased = client.post(
            "/api/v1/runners/lease", headers=auth, json={"runner_id": runner["runner_id"]}
        )
        assert leased.status_code == 200
        assert leased.json()["job"]["run_id"] == first
        secure_cancel = client.get(
            f"/api/v1/runners/runs/{first}/cancel-status",
            headers=auth,
            params={"runner_id": runner["runner_id"]},
        )
        assert secure_cancel.status_code == 200
        leaked = client.get(
            f"/api/v1/runners/runs/{first}/cancel-status",
            params={"runner_id": runner["runner_id"], "runner_secret": runner["runner_secret"]},
        )
        assert leaked.status_code == 400
