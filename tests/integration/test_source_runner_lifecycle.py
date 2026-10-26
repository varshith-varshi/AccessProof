from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def _signup(client: TestClient, email: str = "ops@example.com"):
    data = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": "correct horse battery staple",
            "organization_name": "Ops Org",
        },
    ).json()
    headers = {
        "Authorization": f"Bearer {data['session_token']}",
        "X-Organization-ID": data["organization_id"],
    }
    project = client.post("/api/v1/projects", headers=headers, json={"name": "Ops Project"}).json()[
        "id"
    ]
    return headers, project


def test_source_operational_metadata_rotation_and_disconnect():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        headers, project = _signup(client, "source-ops@example.com")
        source = client.post(
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
        ).json()
        source_id = source["id"]

        validated = client.post(f"/api/v1/sources/{source_id}/validate", headers=headers)
        assert validated.status_code == 200
        body = validated.json()
        assert body["status"] == "connected"
        assert body["provider_identity"]["provider"] == "mock"
        assert body["last_validated_at"] is not None
        assert body["last_capability_refresh_at"] is None
        assert body["last_error"] is None

        refreshed = client.post(
            f"/api/v1/sources/{source_id}/refresh-capabilities", headers=headers
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["last_capability_refresh_at"] is not None
        assert refreshed.json()["capabilities"]["DIRECT_USER_REVOKE"] == "SUPPORTED"

        rotated = client.post(
            f"/api/v1/sources/{source_id}/rotate-credential",
            headers=headers,
            json={"credentials": {"scopes": "Files.ReadWrite.All GroupMember.ReadWrite.All"}},
        )
        assert rotated.status_code == 200
        assert rotated.json()["status"] == "not_configured"
        assert rotated.json()["granted_scopes"] == [
            "Files.ReadWrite.All",
            "GroupMember.ReadWrite.All",
        ]
        assert rotated.json()["provider_identity"] == {}

        disconnected = client.post(f"/api/v1/sources/{source_id}/disconnect", headers=headers)
        assert disconnected.status_code == 200
        assert disconnected.json()["status"] == "disconnected"
        assert disconnected.json()["granted_scopes"] == []


def test_runner_version_rotation_disable_enable_and_revoke_releases_lease():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        headers, project = _signup(client, "runner-ops@example.com")
        suite = client.post(
            "/api/v1/suites",
            headers=headers,
            json={"project_id": project, "name": "Suite", "scenario": {"name": "revoke"}},
        ).json()["id"]

        registration = client.post(
            "/api/v1/runners/registrations", headers=headers, json={"project_id": project}
        ).json()["registration_token"]
        too_old = client.post(
            "/api/v1/runners/exchange",
            json={"registration_token": registration, "name": "old-runner", "version": "0.0.1"},
        )
        assert too_old.status_code == 409

        exchange = client.post(
            "/api/v1/runners/exchange",
            json={"registration_token": registration, "name": "runner-one", "version": "0.1.0"},
        )
        assert exchange.status_code == 201
        runner = exchange.json()

        listed = client.get(f"/api/v1/runners?project_id={project}", headers=headers)
        assert listed.status_code == 200
        assert listed.json()[0]["compatible"] is True
        assert listed.json()[0]["online"] is True

        rotated = client.post(
            f"/api/v1/runners/{runner['runner_id']}/rotate-credential", headers=headers
        )
        assert rotated.status_code == 200
        new_secret = rotated.json()["runner_secret"]
        assert new_secret != runner["runner_secret"]
        assert (
            client.post(
                "/api/v1/runners/heartbeat",
                headers={"Authorization": f"Bearer {runner['runner_secret']}"},
                json={
                    "runner_id": runner["runner_id"],
                    "version": "0.1.0",
                },
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/runners/heartbeat",
                headers={"Authorization": f"Bearer {new_secret}"},
                json={
                    "runner_id": runner["runner_id"],
                    "version": "0.1.0",
                },
            ).status_code
            == 200
        )

        assert (
            client.post(
                f"/api/v1/runners/{runner['runner_id']}/disable", headers=headers
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/runners/heartbeat",
                headers={"Authorization": f"Bearer {new_secret}"},
                json={
                    "runner_id": runner["runner_id"],
                    "version": "0.1.0",
                },
            ).status_code
            == 401
        )
        assert (
            client.post(
                f"/api/v1/runners/{runner['runner_id']}/enable", headers=headers
            ).status_code
            == 200
        )

        run_id = client.post(
            "/api/v1/runs",
            headers=headers,
            json={"project_id": project, "suite_id": suite},
        ).json()["id"]
        leased = client.post(
            "/api/v1/runners/lease",
            headers={"Authorization": f"Bearer {new_secret}"}, json={"runner_id": runner["runner_id"]},
        )
        assert leased.status_code == 200
        assert leased.json()["job"]["run_id"] == run_id

        revoked = client.post(
            f"/api/v1/runners/{runner['runner_id']}/revoke",
            headers=headers,
            json={"reason": "credential compromise drill"},
        )
        assert revoked.status_code == 200
        assert revoked.json()["released_runs"] == 1
        detail = client.get(f"/api/v1/runs/{run_id}", headers=headers).json()
        assert detail["state"] == "RUNNER_DISCONNECTED"
        assert (
            client.post(
                "/api/v1/runners/heartbeat",
                headers={"Authorization": f"Bearer {new_secret}"},
                json={
                    "runner_id": runner["runner_id"],
                    "version": "0.1.0",
                },
            ).status_code
            == 401
        )
