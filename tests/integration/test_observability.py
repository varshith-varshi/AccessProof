from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base,
    CleanupTask,
    EmailOutbox,
    Project,
    Runner,
    SessionLocal,
    SourceConnection,
    TestRun as DbTestRun,
    TestSuite as DbTestSuite,
    WebhookDelivery,
    WebhookEndpoint,
    engine,
)


def test_metrics_exposes_database_backed_operational_gauges():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        project = Project(organization_id="org-observe", name="Observe")
        db.add(project)
        db.flush()
        suite = DbTestSuite(
            organization_id="org-observe",
            project_id=project.id,
            name="suite",
            scenario_json='{"name":"direct_user_revoke","maximum_slo_seconds":30,"timeout_seconds":60}',
        )
        source = SourceConnection(
            organization_id="org-observe",
            project_id=project.id,
            provider="mock",
            name="mock",
            boundary="test",
            status="connected",
            mutation_acknowledged=True,
        )
        runner = Runner(
            organization_id="org-observe",
            project_id=project.id,
            name="runner",
            credential_hash="hash",
            version="0.1.0",
            last_heartbeat_at=now - timedelta(seconds=5),
        )
        db.add_all([suite, source, runner])
        db.flush()
        run = DbTestRun(
            organization_id="org-observe",
            project_id=project.id,
            suite_id=suite.id,
            source_connection_id=source.id,
            state="CREATED",
            release="metrics",
        )
        db.add(run)
        db.flush()
        db.add(
            CleanupTask(
                organization_id="org-observe",
                project_id=project.id,
                run_id=run.id,
                provider="mock",
                provider_resource_id="resource-1",
                resource_json="{}",
                status="pending",
            )
        )
        endpoint = WebhookEndpoint(
            organization_id="org-observe",
            project_id=project.id,
            url="https://example.com/hook",
            secret_hash="hash",
            encrypted_secret="encrypted",
        )
        db.add(endpoint)
        db.flush()
        db.add(
            WebhookDelivery(
                organization_id="org-observe",
                endpoint_id=endpoint.id,
                event_type="test",
                payload_json="{}",
                status="pending",
            )
        )
        db.add(
            EmailOutbox(
                organization_id="org-observe",
                recipient="ops@example.com",
                template="alert",
                subject="alert",
                encrypted_payload="encrypted",
                status="pending",
                next_attempt_at=now,
            )
        )
        db.commit()

    with TestClient(app) as client:
        response = client.get("/metrics")
        assert response.status_code == 200
        text = response.text
        assert 'accessproof_run_queue_depth{state="CREATED"} 1.0' in text
        assert 'accessproof_runner_health_count{health="online"} 1.0' in text
        assert 'accessproof_cleanup_queue_depth{status="pending"} 1.0' in text
        assert 'accessproof_webhook_queue_depth{status="pending"} 1.0' in text
        assert 'accessproof_email_queue_depth{status="pending"} 1.0' in text
        assert 'accessproof_source_connection_count{status="connected"} 1.0' in text
