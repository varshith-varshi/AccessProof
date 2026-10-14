from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base,
    Project,
    Runner,
    SessionLocal,
    SourceConnection,
    TestRun as DbTestRun,
    TestSuite as DbTestSuite,
    engine,
)


def _signup(client: TestClient):
    r = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "dash@example.com",
            "password": "StrongPassword123!",
            "organization_name": "Dash Org",
        },
    )
    body = r.json()
    org = body["organization_id"]
    headers = {"Authorization": f"Bearer {body['session_token']}", "X-Organization-ID": org}
    return org, headers


def test_dashboard_uses_only_measured_run_data():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        org, headers = _signup(client)
        with SessionLocal() as db:
            p = Project(organization_id=org, name="P")
            db.add(p)
            db.flush()
            s = SourceConnection(
                organization_id=org,
                project_id=p.id,
                provider="mock",
                name="Mock source",
                boundary="test",
                encrypted_credentials=None,
                status="connected",
                mutation_acknowledged=True,
            )
            suite = DbTestSuite(
                organization_id=org, project_id=p.id, name="Group revoke", scenario_json="{}"
            )
            db.add_all([s, suite])
            db.flush()
            base = datetime.now(timezone.utc)
            for i, (outcome, stable) in enumerate(
                [("PASS", 20.0), ("FAIL", 100.0), ("PASS", 40.0)]
            ):
                payload = {"derived": {"stable_propagation_latency_seconds": stable}}
                db.add(
                    DbTestRun(
                        organization_id=org,
                        project_id=p.id,
                        suite_id=suite.id,
                        source_connection_id=s.id,
                        release=f"v{i}",
                        state="PASSED" if outcome == "PASS" else "FAILED",
                        outcome=outcome,
                        result_json=json.dumps(payload),
                        created_at=base + timedelta(seconds=i),
                    )
                )
            db.add(
                Runner(
                    organization_id=org,
                    project_id=p.id,
                    name="r1",
                    credential_hash="x",
                    version="0.1.0",
                    last_heartbeat_at=base,
                    revoked=False,
                    disabled=False,
                )
            )
            db.commit()
        r = client.get("/api/v1/dashboard", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["projects"] == 1
        assert body["latest_release_status"] == "PASS"
        assert body["slo_failures"] == 1
        assert body["median_revocation_latency_seconds"] == 40.0
        assert body["p95_revocation_latency_seconds"] == 94.0
        assert body["worst_source"]["name"] == "Mock source"
        assert body["worst_scenario"]["name"] == "Group revoke"
        assert len(body["recent_runs"]) == 3
