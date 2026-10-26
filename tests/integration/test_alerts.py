from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.alerts import queue_alert
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AlertRecord,
    Base,
    EmailOutbox,
    Runner,
    SessionLocal,
    WebhookDelivery,
    WebhookEndpoint,
    engine,
)
from apps.worker.accessproof_worker.main import scan_operational_alerts
from packages.crypto.secrets import SecretBox, hash_token
from apps.api.accessproof_api.config import settings


def _signup(client, email="alert@example.com"):
    data = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": "correct horse battery staple",
            "organization_name": "Alert Org",
        },
    ).json()
    return data, {
        "Authorization": f"Bearer {data['session_token']}",
        "X-Organization-ID": data["organization_id"],
    }


def test_alert_deduplicates_and_queues_admin_email_and_project_webhook():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner, headers = _signup(client)
        project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Alert Project"}
        ).json()
        with SessionLocal() as db:
            endpoint = WebhookEndpoint(
                organization_id=owner["organization_id"],
                project_id=project["id"],
                url="https://hooks.example.com/accessproof",
                secret_hash=hash_token("secret"),
                encrypted_secret=SecretBox.from_text(settings.secret_encryption_key).encrypt(
                    "secret"
                ),
            )
            db.add(endpoint)
            db.commit()
        with SessionLocal() as db:
            first = queue_alert(
                db,
                organization_id=owner["organization_id"],
                project_id=project["id"],
                kind="slo_exceeded",
                severity="critical",
                dedupe_key="run:1",
                subject="Regression",
                detail="Stable denial exceeded SLO",
            )
            second = queue_alert(
                db,
                organization_id=owner["organization_id"],
                project_id=project["id"],
                kind="slo_exceeded",
                severity="critical",
                dedupe_key="run:1",
                subject="Regression",
                detail="duplicate",
            )
            db.commit()
            assert first is True and second is False
            assert len(list(db.scalars(select(AlertRecord)))) == 1
            alert_emails = list(
                db.scalars(select(EmailOutbox).where(EmailOutbox.template == "operational_alert"))
            )
            assert len(alert_emails) == 1 and alert_emails[0].recipient == "alert@example.com"
            deliveries = list(
                db.scalars(
                    select(WebhookDelivery).where(
                        WebhookDelivery.event_type == "alert.slo_exceeded"
                    )
                )
            )
            assert len(deliveries) == 1


def test_stale_runner_scan_creates_one_deduplicated_offline_alert():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner, headers = _signup(client, "runner-alert@example.com")
        project = client.post(
            "/api/v1/projects", headers=headers, json={"name": "Runner Project"}
        ).json()
    stale = datetime.now(timezone.utc) - timedelta(seconds=settings.runner_offline_seconds + 60)
    with SessionLocal() as db:
        db.add(
            Runner(
                organization_id=owner["organization_id"],
                project_id=project["id"],
                name="private-runner",
                credential_hash=hash_token("x"),
                last_heartbeat_at=stale,
                version="0.1.0",
            )
        )
        db.commit()
    assert scan_operational_alerts() == 1
    assert scan_operational_alerts() == 0
    with SessionLocal() as db:
        row = db.scalar(select(AlertRecord).where(AlertRecord.kind == "runner_offline"))
        assert row is not None
