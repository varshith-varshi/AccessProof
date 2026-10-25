from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AIApplication,
    AuthorizationRevision,
    Base,
    CleanupTask,
    EmailOutbox,
    GuardPermissionEvent,
    GuardRegistration,
    Project,
    ProviderSyncCursor,
    RAGRouteChallenge,
    Runner,
    SessionLocal,
    SourceConnection,
    TestRun as DbTestRun,
    TestSuite as DbTestSuite,
    WebhookDelivery,
    WebhookEndpoint,
    engine,
)
from apps.api.accessproof_api.route_certification import route_configuration_fingerprint


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


def _metric_value(text: str, name: str, labels: str = "") -> float:
    match = re.search(
        rf"^{re.escape(name)}{re.escape(labels)} (\S+)$", text, re.MULTILINE,
    )
    assert match is not None, (name, labels)
    return float(match.group(1))


def test_metrics_report_authorization_freshness_route_coverage_and_revision_lag():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        project = Project(organization_id="org-authz", name="Authz Observe")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id="org-authz", project_id=project.id,
            provider="google-drive", name="drive", boundary="root",
            status="connected", mutation_acknowledged=True,
        )
        guard = GuardRegistration(
            organization_id="org-authz", name="guard", status="enrolled",
            active_policy_version=3, enrolled_at=now, health="healthy",
        )
        db.add_all([source, guard])
        db.flush()
        for kind, age in (("acl", 120), ("directory", 60)):
            db.add(ProviderSyncCursor(
                organization_id="org-authz", source_id=source.id,
                provider="google-drive", sync_kind=kind, status="connected",
                last_success_at=now - timedelta(seconds=age),
            ))
        db.add(GuardPermissionEvent(
            organization_id="org-authz", source_id=source.id, provider="google-drive",
            subject_id="subject-1", resource_id="resource-1", change_type="grant_add",
            dedupe_key="metric-event", observed_at=now - timedelta(seconds=10),
            received_at=now,
        ))
        row = AIApplication(
            organization_id="org-authz", application_id="rag", name="RAG",
            mode="protect", guard_id=guard.id, source_id=source.id,
            adapter_type="accessproof-gateway",
        )
        db.add(row)
        db.flush()
        db.add(RAGRouteChallenge(
            organization_id="org-authz", application_row_id=row.id, guard_id=guard.id,
            source_id=source.id, nonce_digest="c" * 64,
            configuration_fingerprint=route_configuration_fingerprint(row, 3),
            status="cutover_verified", deployment_sha256="a" * 64,
            route_sha256="b" * 64, verified_at=now - timedelta(seconds=30),
            cutover_at=now - timedelta(seconds=30),
            expires_at=now + timedelta(hours=1),
        ))
        for revision, age in ((1, 60), (2, 30)):
            db.add(AuthorizationRevision(
                organization_id="org-authz", application_row_id=row.id,
                application_id="rag", guard_id=guard.id, revision=revision,
                state_hash=str(revision) * 64, revision_hash=str(revision) * 64,
                payload_json="{}", signing_key_id="key", signature="sig",
                signing_public_key="pub", signed_manifest_json="{}",
                generated_at=now - timedelta(seconds=age),
            ))
        guard.active_authorization_revisions_json = json.dumps({
            "rag": {"revision": 1, "revision_hash": "1" * 64},
        })
        db.commit()

    with TestClient(app) as client:
        text = client.get("/metrics").text
    acl_age = _metric_value(text, "accessproof_source_freshness_seconds", '{provider="google-drive"}')
    directory_age = _metric_value(
        text, "accessproof_directory_freshness_seconds", '{provider="google-drive"}'
    )
    event_lag = _metric_value(
        text, "accessproof_provider_event_lag_seconds", '{provider="google-drive"}'
    )
    certificate_age = _metric_value(text, "accessproof_route_certificate_age_seconds")
    coverage = _metric_value(text, "accessproof_protected_route_coverage_ratio")
    revision_lag = _metric_value(text, "accessproof_guard_revision_lag_seconds")
    assert 120 <= acl_age <= 125
    assert 60 <= directory_age <= 65
    assert 9.5 <= event_lag <= 12
    assert 30 <= certificate_age <= 35
    assert coverage == 1.0
    assert 30 <= revision_lag <= 35
