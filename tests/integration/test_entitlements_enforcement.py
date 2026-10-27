from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, Entitlement, SessionLocal, engine


def _signup(client: TestClient):
    s = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "quota@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Quota Org",
        },
    ).json()
    headers = {
        "Authorization": f"Bearer {s['session_token']}",
        "X-Organization-ID": s["organization_id"],
    }
    return s, headers


def _set_entitlement(org_id: str, key: str, value: str) -> None:
    with SessionLocal() as db:
        db.add(Entitlement(organization_id=org_id, key=key, value=value, source="test"))
        db.commit()


def test_plan_limits_and_connector_allowlist_are_enforced():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        signup, headers = _signup(client)
        org_id = signup["organization_id"]

        first = client.post("/api/v1/projects", headers=headers, json={"name": "Project One"})
        assert first.status_code == 201
        project_id = first.json()["id"]
        _set_entitlement(org_id, "projects", "1")
        blocked_project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Project Two"}
        )
        assert blocked_project.status_code == 402

        _set_entitlement(org_id, "connectors", '["google-drive"]')
        blocked_connector = client.post(
            "/api/v1/sources",
            headers=headers,
            json={
                "project_id": project_id,
                "provider": "microsoft365",
                "name": "No Microsoft",
                "boundary": "test",
                "credentials": {},
            },
        )
        assert blocked_connector.status_code == 402

        _set_entitlement(org_id, "source_connections", "1")
        allowed_source = client.post(
            "/api/v1/sources",
            headers=headers,
            json={
                "project_id": project_id,
                "provider": "google-drive",
                "name": "Drive",
                "boundary": "root",
                "credentials": {},
            },
        )
        assert allowed_source.status_code == 201
        blocked_source = client.post(
            "/api/v1/sources",
            headers=headers,
            json={
                "project_id": project_id,
                "provider": "google-drive",
                "name": "Drive 2",
                "boundary": "root2",
                "credentials": {},
            },
        )
        assert blocked_source.status_code == 402

        _set_entitlement(org_id, "runners", "0")
        runner = client.post(
            "/api/v1/runners/registrations", headers=headers, json={"project_id": project_id}
        )
        assert runner.status_code == 402

        suite = client.post(
            "/api/v1/suites",
            headers=headers,
            json={
                "project_id": project_id,
                "name": "Quota suite",
                "scenario": {
                    "name": "quota_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 180,
                },
            },
        )
        assert suite.status_code == 201
        _set_entitlement(org_id, "monthly_test_runs", "1")
        run1 = client.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project_id, "suite_id": suite.json()["id"]},
        )
        assert run1.status_code == 202
        run2 = client.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project_id, "suite_id": suite.json()["id"]},
        )
        assert run2.status_code == 402
