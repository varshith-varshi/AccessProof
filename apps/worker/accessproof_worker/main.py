from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from apps.api.accessproof_api.config import settings
from apps.api.accessproof_api.db import (
    CleanupTask,
    EmailOutbox,
    RetentionPolicy,
    Runner,
    GuardPermissionEvent,
    SessionLocal,
    SourceConnection,
    TestRun,
    WebhookDelivery,
    WebhookEndpoint,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from connectors.factory import create_source_adapter
from integrations.webhooks.delivery import deliver
from integrations.email.delivery import EmailDeliveryConfig, deliver_email
from packages.crypto.secrets import build_secret_backend
from packages.domain.models import SourceResource
from apps.api.accessproof_api.retention import apply_retention
from apps.api.accessproof_api.alerts import queue_alert
from apps.api.accessproof_api.observability import (
    cleanup_attempts,
    webhook_attempts,
    email_attempts,
    operational_alerts,
    logger,
)
from packages.observability.tracing import configure_tracing

POLL_SECONDS = float(os.getenv("ACCESSPROOF_WORKER_POLL_SECONDS", "2"))
box = build_secret_backend(
    backend=settings.secret_backend,
    local_key=settings.secret_encryption_key,
    aws_kms_key_id=settings.aws_kms_key_id,
    aws_region=settings.aws_region,
)


def scan_operational_alerts() -> int:
    created = 0
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        runners = list(
            db.scalars(select(Runner).where(Runner.revoked.is_(False), Runner.disabled.is_(False)))
        )
        for runner in runners:
            heartbeat = runner.last_heartbeat_at
            if heartbeat and heartbeat.tzinfo is None:
                heartbeat = heartbeat.replace(tzinfo=timezone.utc)
            if heartbeat and (now - heartbeat).total_seconds() > settings.runner_offline_seconds:
                if queue_alert(
                    db,
                    organization_id=runner.organization_id,
                    project_id=runner.project_id,
                    kind="runner_offline",
                    severity="warning",
                    dedupe_key=f"runner_offline:{runner.id}:{heartbeat.isoformat()}",
                    subject=f"{settings.product_name}: runner offline",
                    detail=f"Runner {runner.name} has not heartbeated since {heartbeat.isoformat()}.",
                ):
                    created += 1
                    operational_alerts.labels("runner_offline", "warning").inc()
        for task in db.scalars(select(CleanupTask).where(CleanupTask.status == "failed")):
            if queue_alert(
                db,
                organization_id=task.organization_id,
                project_id=task.project_id,
                kind="cleanup_failure",
                severity="critical",
                dedupe_key=f"cleanup_failure:{task.id}",
                subject=f"{settings.product_name}: provider cleanup failed",
                detail=f"Cleanup task {task.id} exhausted retries for provider resource {task.provider_resource_id}. Manual reconciliation is required.",
            ):
                created += 1
                operational_alerts.labels("cleanup_failure", "critical").inc()
        for delivery in db.scalars(
            select(WebhookDelivery).where(WebhookDelivery.status == "failed")
        ):
            endpoint = db.get(WebhookEndpoint, delivery.endpoint_id)
            if endpoint and queue_alert(
                db,
                organization_id=delivery.organization_id,
                project_id=endpoint.project_id,
                kind="webhook_failure",
                severity="warning",
                dedupe_key=f"webhook_failure:{delivery.id}",
                subject=f"{settings.product_name}: webhook delivery exhausted retries",
                detail=f"Webhook delivery {delivery.id} for event {delivery.event_type} exhausted retries.",
            ):
                created += 1
                operational_alerts.labels("webhook_failure", "warning").inc()
        db.commit()
    return created


def process_all_retention() -> dict[str, dict[str, int]]:
    results: dict[str, dict[str, int]] = {}
    with SessionLocal() as db:
        org_ids = list(db.scalars(select(RetentionPolicy.organization_id)))
        for org_id in org_ids:
            results[org_id] = apply_retention(db, org_id)
        db.commit()
    return results


def claim_one_email() -> str | None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.scalar(
            select(EmailOutbox)
            .where(EmailOutbox.status.in_(["pending", "retry"]), EmailOutbox.next_attempt_at <= now)
            .order_by(EmailOutbox.created_at.asc())
            .limit(1)
        )
        if not row:
            return None
        row.status = "delivering"
        row.attempts += 1
        db.commit()
        return row.id


async def process_email(email_id: str) -> None:
    with SessionLocal() as db:
        row = db.get(EmailOutbox, email_id)
        if not row:
            return
        recipient = row.recipient
        subject = row.subject
        payload = json.loads(box.decrypt(row.encrypted_payload))
    config = EmailDeliveryConfig(
        mode=settings.email_delivery_mode,
        from_address=settings.email_from,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        smtp_starttls=settings.smtp_starttls,
    )
    try:
        await asyncio.to_thread(
            deliver_email,
            config=config,
            recipient=recipient,
            subject=subject,
            text_body=str(payload["text_body"]),
        )
    except Exception as exc:
        with SessionLocal() as db:
            row = db.get(EmailOutbox, email_id)
            if not row:
                return
            row.last_error = f"{type(exc).__name__}: {exc}"[:2000]
            if row.attempts >= 8:
                row.status = "failed"
                row.completed_at = datetime.now(timezone.utc)
            else:
                row.status = "retry"
                row.next_attempt_at = datetime.now(timezone.utc) + timedelta(
                    seconds=min(1800, 2 ** min(row.attempts, 10))
                )
            db.commit()
        email_attempts.labels("failed" if row.attempts >= 8 else "retry").inc()
        return
    email_attempts.labels("delivered").inc()
    with SessionLocal() as db:
        row = db.get(EmailOutbox, email_id)
        if row:
            row.status = "delivered"
            row.last_error = None
            row.completed_at = datetime.now(timezone.utc)
            db.commit()


def claim_one_webhook() -> str | None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.scalar(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.status.in_(["pending", "retry"]),
                WebhookDelivery.next_attempt_at <= now,
            )
            .order_by(WebhookDelivery.created_at.asc())
            .limit(1)
        )
        if not row:
            return None
        row.status = "delivering"
        db.commit()
        return row.id


async def process_delivery(delivery_id: str) -> None:
    with SessionLocal() as db:
        row = db.get(WebhookDelivery, delivery_id)
        if not row:
            return
        endpoint = db.get(WebhookEndpoint, row.endpoint_id)
        if not endpoint or not endpoint.enabled:
            row.status = "disabled"
            row.completed_at = datetime.now(timezone.utc)
            db.commit()
            return
        url = endpoint.url
        secret = box.decrypt(endpoint.encrypted_secret)
        payload = json.loads(row.payload_json)
    attempts = await deliver(url, secret, payload, max_attempts=3)
    success = bool(attempts and 200 <= attempts[-1].get("status_code", 0) < 300)
    with SessionLocal() as db:
        row = db.get(WebhookDelivery, delivery_id)
        if not row:
            return
        previous = json.loads(row.attempts_json)
        previous.extend(attempts)
        row.attempts_json = json.dumps(previous)
        if success:
            row.status = "delivered"
            row.completed_at = datetime.now(timezone.utc)
        elif len(previous) >= 9:
            row.status = "failed"
            row.completed_at = datetime.now(timezone.utc)
        else:
            row.status = "retry"
            row.next_attempt_at = datetime.now(timezone.utc) + timedelta(
                seconds=min(300, 2 ** min(len(previous), 8))
            )
        webhook_attempts.labels(row.status).inc()
        db.commit()


def claim_one_cleanup() -> str | None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.scalar(
            select(CleanupTask)
            .where(CleanupTask.status.in_(["pending", "retry"]), CleanupTask.next_attempt_at <= now)
            .order_by(CleanupTask.created_at.asc())
            .limit(1)
        )
        if not row:
            return None
        row.status = "running"
        row.attempts += 1
        db.commit()
        return row.id


async def process_cleanup_task(task_id: str) -> None:
    with SessionLocal() as db:
        task = db.get(CleanupTask, task_id)
        if not task:
            return
        run = db.get(TestRun, task.run_id)
        source = (
            db.get(SourceConnection, run.source_connection_id)
            if run and run.source_connection_id
            else None
        )
        if source is None:
            task.status = "failed"
            task.last_error = "Source connection no longer exists; manual reconciliation required"
            task.completed_at = datetime.now(timezone.utc)
            db.commit()
            return
        credentials = (
            json.loads(box.decrypt(source.encrypted_credentials))
            if source.encrypted_credentials
            else {}
        )
        provider = source.provider
        resource_payload = json.loads(task.resource_json)

    adapter = None
    try:
        adapter = create_source_adapter(provider, credentials)
        resource = SourceResource(
            provider_id=str(resource_payload["provider_id"]),
            name=str(resource_payload.get("name") or "AccessProof synthetic resource"),
            marker=str(resource_payload.get("marker") or ""),
            canary=str(resource_payload.get("canary") or "REDACTED"),
            metadata=dict(resource_payload.get("metadata") or {}),
        )
        await adapter.validate_connection()
        await adapter.adopt_tracked_resource(resource)
        if not resource.metadata.get("deleted_by_scenario"):
            await adapter.delete_resource(resource)
        await adapter.cleanup()
    except Exception as exc:
        with SessionLocal() as db:
            task = db.get(CleanupTask, task_id)
            if not task:
                return
            task.last_error = f"{type(exc).__name__}: {exc}"[:2000]
            if task.attempts >= 10:
                task.status = "failed"
                task.completed_at = datetime.now(timezone.utc)
            else:
                task.status = "retry"
                task.next_attempt_at = datetime.now(timezone.utc) + timedelta(
                    seconds=min(3600, 2 ** min(task.attempts, 10))
                )
            db.commit()
        cleanup_attempts.labels("failed" if task.attempts >= 10 else "retry", task.provider).inc()
        return
    finally:
        client = getattr(adapter, "_client", None) if adapter is not None else None
        if client is not None:
            try:
                await client.aclose()
            except Exception as exc:
                logger.warning(
                    "cleanup_provider_client_close_failed provider=%s error=%s",
                    adapter.provider if adapter is not None else "unknown",
                    type(exc).__name__,
                )

    with SessionLocal() as db:
        task = db.get(CleanupTask, task_id)
        if task:
            task.status = "completed"
            task.last_error = None
            task.completed_at = datetime.now(timezone.utc)
            cleanup_attempts.labels("completed", task.provider).inc()
            db.commit()


def claim_one_guard_event() -> str | None:
    # A worker can terminate after leasing an event and before it writes a
    # terminal result.  Reclaim only leases old enough to be abandoned so a
    # live worker is never raced by another worker.
    now = datetime.now(timezone.utc)
    retry_before = now - timedelta(minutes=5)
    with SessionLocal() as db:
        row = db.scalar(
            select(GuardPermissionEvent)
            .where(
                (GuardPermissionEvent.processing_status.in_(["received", "queued"]))
                | (
                    (GuardPermissionEvent.processing_status == "processing")
                    & (GuardPermissionEvent.processing_started_at < retry_before)
                )
            )
            .order_by(GuardPermissionEvent.received_at.asc())
            .limit(1)
        )
        if row is None:
            return None
        row.processing_status = "processing"
        row.processing_started_at = now
        db.commit()
        return row.id


def process_claimed_guard_event(event_id: str) -> None:
    with SessionLocal() as db:
        try:
            process_guard_event(db, event_id)
        except Exception as exc:
            event = db.get(GuardPermissionEvent, event_id)
            if event is not None:
                event.processing_status = "error"
                event.error_code = type(exc).__name__[:100]
                event.processing_started_at = None
                event.completed_at = datetime.now(timezone.utc)
                db.commit()
            logger.exception("guard_permission_event_processing_failed event_id=%s", event_id)


async def main() -> None:
    configure_tracing("accessproof-worker")
    last_retention = datetime.min.replace(tzinfo=timezone.utc)
    while True:
        did_work = False
        now = datetime.now(timezone.utc)
        if (now - last_retention).total_seconds() >= max(60, settings.retention_sweep_seconds):
            process_all_retention()
            scan_operational_alerts()
            last_retention = now
            did_work = True
        email_id = claim_one_email()
        if email_id:
            did_work = True
            await process_email(email_id)
        cleanup_id = claim_one_cleanup()
        if cleanup_id:
            did_work = True
            await process_cleanup_task(cleanup_id)
        delivery_id = claim_one_webhook()
        if delivery_id:
            did_work = True
            await process_delivery(delivery_id)
        guard_event_id = claim_one_guard_event()
        if guard_event_id:
            did_work = True
            await asyncio.to_thread(process_claimed_guard_event, guard_event_id)
        if not did_work:
            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
