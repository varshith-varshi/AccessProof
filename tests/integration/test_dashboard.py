from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base,
    GuardProtectionDecision,
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


def test_current_dashboard_is_tenant_scoped_and_does_not_render_legacy_runs():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        org, headers = _signup(client)
        with SessionLocal() as db:
            project = Project(organization_id=org, name="Legacy should stay hidden")
            db.add(project)
            db.flush()
            suite = DbTestSuite(organization_id=org, project_id=project.id, name="Legacy", scenario_json="{}")
            db.add(suite)
            db.flush()
            db.add(DbTestRun(organization_id=org, project_id=project.id, suite_id=suite.id, state="FAILED", outcome="FAIL"))
            db.add(GuardProtectionDecision(
                organization_id=org, guard_id=None, application_id="rag-finance", subject_id="directory-user-1",
                request_id="request-1", policy_version=3, mode="protect", result="block", reason="PROVENANCE_REQUIRED",
            ))
            db.commit()
        response = client.get("/api/v1/current/dashboard", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["blocked_requests"] == 1
        assert body["ai_applications"] == 1
        assert "recent_runs" not in body
        assert body["recent_activity"][0]["type"] == "LAYER2_BLOCK"
