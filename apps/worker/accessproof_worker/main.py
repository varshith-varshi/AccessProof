from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update, or_, and_
from sqlalchemy.orm import Session

from apps.api.accessproof_api.config import settings
from apps.api.accessproof_api.db import (
    CleanupTask,
    EmailOutbox,
    RetentionPolicy,
    Runner,
    GuardPermissionEvent,
    SessionLocal,
    SourceConnection,
    ProviderSyncCursor,
    ProviderEventJournal,
    ProviderEventSubscription,
    TestRun,
    WebhookDelivery,
    WebhookEndpoint,
)
from apps.worker.accessproof_worker.watch_lifecycle import ensure_google_watch, validate_callback_url
from apps.api.accessproof_api.guard_pipeline import process_guard_event_with_retry
from apps.api.accessproof_api.directory_sync import synchronize_directory
from connectors.directory import DirectorySyncError
from apps.api.accessproof_api.acl_sync import ACLSyncError, reconcile_known_acls, synchronize_acls
from packages.auth.oauth_refresh import OAuthCredentials, OAuthRefreshError, refresh_credentials
from packages.auth.microsoft_consent import graph_app_token, MicrosoftConsentError, tenant_uuid
from connectors.factory import create_source_adapter
from integrations.webhooks.delivery import deliver
from integrations.email.delivery import EmailDeliveryConfig, deliver_email
from packages.crypto.secrets import build_secret_backend
from packages.domain.models import SourceResource
from apps.api.accessproof_api.retention import apply_retention
from apps.api.accessproof_api.alerts import queue_alert
from apps.api.accessproof_api.verification_engine import run_worker_cycle
from apps.api.accessproof_api.observability import (
    cleanup_attempts,
    webhook_attempts,
    email_attempts,
    operational_alerts,
    logger,
)
from packages.observability.tracing import configure_tracing

POLL_SECONDS = float(os.getenv("ACCESSPROOF_WORKER_POLL_SECONDS", "2"))
DIRECTORY_SYNC_SECONDS = max(60, int(os.getenv("ACCESSPROOF_DIRECTORY_SYNC_SECONDS", "300")))
ACL_SYNC_SECONDS = max(60, int(os.getenv("ACCESSPROOF_ACL_SYNC_SECONDS", "300")))
# Poll for source-scoped queued bootstrap jobs without making every healthy
# Google source resynchronize more frequently than its configured cadence.
SOURCE_SYNC_CHECK_SECONDS = max(10, int(os.getenv("ACCESSPROOF_SOURCE_SYNC_CHECK_SECONDS", "30")))
SOURCE_SYNC_FAILURE_BACKOFF_SECONDS = max(60, int(os.getenv("ACCESSPROOF_SOURCE_SYNC_FAILURE_BACKOFF_SECONDS", "60")))
GOOGLE_WATCH_CALLBACK_URL = os.getenv("ACCESSPROOF_GOOGLE_WATCH_CALLBACK_URL", "").strip()
MICROSOFT_NOTIFICATION_URL = os.getenv("ACCESSPROOF_MICROSOFT_NOTIFICATION_URL", "").strip()
MICROSOFT_SUBSCRIPTION_CHECK_SECONDS = max(60, int(os.getenv("ACCESSPROOF_MICROSOFT_SUBSCRIPTION_CHECK_SECONDS", "900")))
GOOGLE_WATCH_CHECK_SECONDS = max(60, int(os.getenv("ACCESSPROOF_GOOGLE_WATCH_CHECK_SECONDS", "900")))
ACL_RECONCILE_SECONDS = max(
    300,
    int(
        os.getenv(
            "ACCESSPROOF_ACL_RECONCILE_SECONDS",
            os.getenv(
                "ACCESSPROOF_GOOGLE_ACL_RECONCILE_SECONDS",
                os.getenv("ACCESSPROOF_MICROSOFT_ACL_RECONCILE_SECONDS", "3600"),
            ),
        )
    ),
)
box = build_secret_backend(
    backend=settings.secret_backend,
    local_key=settings.secret_encryption_key,
    aws_kms_key_id=settings.aws_kms_key_id,
    aws_region=settings.aws_region,
)


async def refresh_source_credentials_if_needed(
    db: Session, source: SourceConnection, credentials: dict[str, Any]
) -> dict[str, Any]:
    """Refresh an expiring OAuth source credential and atomically re-encrypt it."""
    endpoint = credentials.get("token_endpoint") or credentials.get("oauth_token_url")
    if str(getattr(source, "provider", "")).lower() == "google-drive":
        # Source credentials are administrator-controlled input. Prevent the
        # OAuth refresh worker from POSTing credentials to an arbitrary URL.
        expected = "https://oauth2.googleapis.com/token"
        if endpoint and endpoint != expected:
            raise OAuthRefreshError("UNTRUSTED_GOOGLE_TOKEN_ENDPOINT")
        endpoint = expected
    if str(getattr(source, "provider", "")).lower() in {"microsoft365", "sharepoint", "onedrive"}:
        # Token endpoint is not a generic URL: source credentials are supplied
        # by tenant administrators and must never cause a credential POST to
        # a caller-controlled server.
        import re
        tenant_id = str(credentials.get("tenant_id") or credentials.get("tenant_hint") or "")
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", tenant_id):
            if credentials.get("refresh_token"):
                raise OAuthRefreshError("INVALID_MICROSOFT_TENANT")
        elif credentials.get("refresh_token"):
            expected = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            if endpoint and endpoint != expected:
                raise OAuthRefreshError("UNTRUSTED_MICROSOFT_TOKEN_ENDPOINT")
            endpoint = expected
    if (str(getattr(source, "provider", "")).lower() in {"microsoft365", "sharepoint", "onedrive"}
            and credentials.get("grant_type") == "client_credentials"):
        # Application permissions use the client-credentials grant; Microsoft
        # does not issue refresh tokens for this grant. Reacquire short-lived
        # Graph tokens from the *configured tenant only*, never an arbitrary URL.
        try:
            tenant = tenant_uuid(credentials.get("tenant_id") or credentials.get("tenant_hint"))
        except MicrosoftConsentError as exc:
            raise OAuthRefreshError("INVALID_MICROSOFT_TENANT") from exc
        expected = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        if endpoint and endpoint != expected:
            raise OAuthRefreshError("UNTRUSTED_MICROSOFT_TOKEN_ENDPOINT")
        expiry_raw = credentials.get("expires_at")
        try:
            expiry = datetime.fromisoformat(str(expiry_raw).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("Timezone missing")
        except (TypeError, ValueError) as exc:
            raise OAuthRefreshError("MICROSOFT_TOKEN_EXPIRY_INVALID") from exc
        if (credentials.get("access_token")
                and expiry > datetime.now(timezone.utc) + timedelta(minutes=5)):
            return credentials
        # Microsoft app credentials are control-plane operator secrets, not
        # tenant-source secrets. Older records may still contain them; use the
        # configured operator identity and scrub the legacy copies on the next
        # successful renewal.
        operator_client_id = os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "").strip()
        operator_client_secret = os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "").strip()
        stored_client_id = str(credentials.get("client_id") or "")
        # Retain a development-only compatibility path for encrypted legacy
        # records so an upgrade does not strand local/test sources before the
        # operator configures its app identity. Production never uses it.
        legacy_client_secret = str(credentials.get("client_secret") or "")
        if not operator_client_id or not operator_client_secret:
            if settings.env == "production" or not stored_client_id or not legacy_client_secret:
                raise OAuthRefreshError("MICROSOFT_OPERATOR_CREDENTIALS_NOT_CONFIGURED")
            operator_client_id, operator_client_secret = stored_client_id, legacy_client_secret
        if stored_client_id and stored_client_id != operator_client_id:
            raise OAuthRefreshError("MICROSOFT_OPERATOR_CLIENT_MISMATCH")
        try:
            access_token, new_expiry = await asyncio.to_thread(
                graph_app_token, tenant_id=tenant,
                client_id=operator_client_id, client_secret=operator_client_secret,
            )
        except MicrosoftConsentError as exc:
            raise OAuthRefreshError(str(exc)) from exc
        updated = dict(credentials)
        updated["access_token"] = access_token
        updated["expires_at"] = new_expiry.isoformat()
        updated["token_endpoint"] = expected
        updated["client_id"] = operator_client_id
        if os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "").strip():
            updated["oauth_credential_mode"] = "server_managed"
            updated.pop("client_secret", None)
            updated.pop("oauth_client_secret", None)
        source.encrypted_credentials = box.encrypt(json.dumps(updated, sort_keys=True))
        return updated
    original_source_credentials = credentials
    provider = str(getattr(source, "provider", "")).lower()
    client_id = credentials.get("client_id") or credentials.get("oauth_client_id")
    client_secret = credentials.get("client_secret") or credentials.get("oauth_client_secret")
    # Public production Google OAuth uses exactly the operator's registered
    # client. Never trust a customer-source record to specify the app secret
    # or client ID; legacy records are migrated/scrubbed opportunistically.
    operator_managed_google = provider == "google-drive" and (
        settings.env == "production" or credentials.get("oauth_credential_mode") == "server_managed"
    )
    if operator_managed_google:
        operator_client_id = os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID", "").strip()
        operator_secret = os.getenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
        if not operator_client_id or not operator_secret:
            raise OAuthRefreshError("GOOGLE_OPERATOR_OAUTH_NOT_CONFIGURED")
        if client_id and client_id != operator_client_id:
            raise OAuthRefreshError("GOOGLE_OPERATOR_OAUTH_CLIENT_MISMATCH")
        client_id, client_secret = operator_client_id, operator_secret
        credentials = dict(credentials)
        credentials.pop("client_secret", None)
        credentials.pop("oauth_client_secret", None)
        credentials.pop("oauth_client_id", None)
        credentials["client_id"] = operator_client_id
        credentials["oauth_credential_mode"] = "server_managed"
    refresh_token = credentials.get("refresh_token")
    expires_at_raw = credentials.get("expires_at")
    if not (endpoint and client_id and client_secret and refresh_token and expires_at_raw):
        return credentials
    try:
        expires_at = datetime.fromisoformat(str(expires_at_raw).replace("Z", "+00:00"))
    except ValueError:
        return credentials
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    current = OAuthCredentials(
        access_token=str(credentials.get("access_token") or ""),
        refresh_token=str(refresh_token),
        expires_at=expires_at,
        token_type=str(credentials.get("token_type") or "Bearer"),
        scopes=tuple(str(credentials.get("scope") or "").split()),
    )
    if not current.needs_refresh():
        if operator_managed_google and credentials != original_source_credentials:
            source.encrypted_credentials = box.encrypt(json.dumps(credentials, sort_keys=True))
        return credentials
    holder: dict[str, OAuthCredentials] = {}

    def save(refreshed: OAuthCredentials) -> None:
        holder["credentials"] = refreshed

    refreshed = await asyncio.to_thread(
        refresh_credentials,
        current,
        token_endpoint=str(endpoint),
        client_id=str(client_id),
        client_secret=str(client_secret),
        save=save,
    )
    updated = dict(credentials)
    updated["access_token"] = refreshed.access_token
    updated["refresh_token"] = refreshed.refresh_token
    updated["expires_at"] = refreshed.expires_at.isoformat() if refreshed.expires_at else None
    updated["token_type"] = refreshed.token_type
    if refreshed.scopes:
        updated["scope"] = " ".join(refreshed.scopes)
    source.encrypted_credentials = box.encrypt(json.dumps(updated, sort_keys=True))
    return updated


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


def claim_one_provider_event() -> str | None:
    """Lease one provider notification without conflating it with ACL truth."""
    now = datetime.now(timezone.utc)
    abandoned = now - timedelta(minutes=5)
    eligible = or_(
        and_(ProviderEventJournal.status.in_(["received", "retry"]),
             ProviderEventJournal.next_attempt_at <= now),
        and_(ProviderEventJournal.status == "processing",
             ProviderEventJournal.processing_started_at < abandoned),
    )
    with SessionLocal() as db:
        # A conditional UPDATE/RETURNING is a single atomic claim. Workers
        # cannot both lease the same row even if they select concurrently.
        # The nested ID query is intentionally deterministic for fair ordering.
        candidate = (select(ProviderEventJournal.id).where(eligible)
                     .order_by(ProviderEventJournal.received_at, ProviderEventJournal.id)
                     .limit(1).scalar_subquery())
        row_id = db.scalar(
            update(ProviderEventJournal)
            .where(ProviderEventJournal.id == candidate, eligible)
            .values(status="processing", processing_started_at=now,
                    attempts=ProviderEventJournal.attempts + 1)
            .returning(ProviderEventJournal.id)
        )
        db.commit()
        return row_id


async def process_provider_event(event_id: str) -> None:
    """Fetch the authoritative provider delta for a validated notification."""
    with SessionLocal() as db:
        event = db.get(ProviderEventJournal, event_id)
        if event is None or event.status != "processing":
            return
        source = db.get(SourceConnection, event.source_id)
        subscription = db.get(ProviderEventSubscription, event.subscription_id)
        if source is None or subscription is None or source.organization_id != event.organization_id:
            event.status, event.error_code, event.completed_at = "failed", "SOURCE_BINDING_MISMATCH", datetime.now(timezone.utc)
            db.commit()
            return
        credentials = json.loads(box.decrypt(source.encrypted_credentials)) if source.encrypted_credentials else {}
    event_type = str(event.event_type or "")
    subscription_row_id = str(event.subscription_id)
    received_at = event.received_at
    try:
        # The event is only a wake-up signal. The worker re-reads AUTHORITATIVE
        # provider state (ACL delta / directory) before any policy changes.
        if event_type.startswith("lifecycle:"):
            from apps.worker.accessproof_worker.graph_subscriptions import handle_lifecycle
            outcome = await handle_lifecycle(subscription_row_id, event_type.split(":", 1)[1], box=box,
                                             refresh_credentials=refresh_source_credentials_if_needed)
            logger.info("graph_lifecycle_processed outcome=%s", outcome)
        channel = (subscription.channel_type if subscription is not None else "acl") or "acl"
        with SessionLocal() as db:
            source = db.get(SourceConnection, event.source_id)
            if source is None:
                raise ACLSyncError("SOURCE_BINDING_MISMATCH")
            credentials = await refresh_source_credentials_if_needed(db, source, credentials)
            if channel == "directory":
                # Group membership / account state changed: authoritative
                # directory re-read; membership changes flow through the Guard
                # pipeline into effective access and a new revision.
                await synchronize_directory(db, source, credentials)
            else:
                await synchronize_acls(db, source, credentials, max_pages=50)
            db.commit()
        if received_at is not None:
            from apps.api.accessproof_api.observability import provider_event_reconcile_seconds
            seen = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - seen).total_seconds()
            provider_event_reconcile_seconds.labels(channel).observe(elapsed)
            logger.info("provider_event_reconciled channel=%s seconds_since_receipt=%.3f", channel, elapsed)
        with SessionLocal() as db:
            event = db.get(ProviderEventJournal, event_id)
            subscription = db.get(ProviderEventSubscription, event.subscription_id) if event else None
            if event:
                event.status, event.error_code, event.completed_at = "completed", None, datetime.now(timezone.utc)
            if subscription:
                subscription.last_successful_processing_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:
        code = getattr(exc, "code", type(exc).__name__)[:100]
        with SessionLocal() as db:
            event = db.get(ProviderEventJournal, event_id)
            if event:
                from apps.api.accessproof_api.observability import provider_event_failures
                if event.attempts >= 8:
                    event.status, event.completed_at = "failed", datetime.now(timezone.utc)
                    provider_event_failures.labels(str(event.event_type).split(":")[0], "dead_letter").inc()
                else:
                    provider_event_failures.labels(str(event.event_type).split(":")[0], "retry").inc()
                    event.status = "retry"
                    event.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=min(300, 2 ** min(event.attempts, 8)))
                event.error_code = code
                event.processing_started_at = None
                db.commit()
        logger.warning("provider_event_sync_failed event_id=%s code=%s", event_id, code)


def claim_one_guard_event() -> str | None:
    # A worker can terminate after leasing an event and before it writes a
    # terminal result.  Reclaim only leases old enough to be abandoned so a
    # live worker is never raced by another worker.
    now = datetime.now(timezone.utc)
    retry_before = now - timedelta(minutes=5)
    eligible = or_(
        GuardPermissionEvent.processing_status.in_(["received", "queued"]),
        and_(
            GuardPermissionEvent.processing_status == "processing",
            GuardPermissionEvent.processing_started_at < retry_before,
        ),
    )
    with SessionLocal() as db:
        # Row selection and lease acquisition must be one conditional UPDATE.
        # The old SELECT -> set -> COMMIT sequence allowed two workers to
        # claim the same event before either had committed its local change.
        candidate = (select(GuardPermissionEvent.id).where(eligible)
                     .order_by(GuardPermissionEvent.received_at, GuardPermissionEvent.id)
                     .limit(1).scalar_subquery())
        claimed = db.scalar(
            update(GuardPermissionEvent)
            .where(GuardPermissionEvent.id == candidate, eligible)
            .values(processing_status="processing", processing_started_at=now)
            .returning(GuardPermissionEvent.id)
        )
        db.commit()
        return claimed


def process_claimed_guard_event(event_id: str) -> None:
    try:
        process_guard_event_with_retry(SessionLocal, event_id)
    except Exception as exc:
        with SessionLocal() as db:
            event = db.get(GuardPermissionEvent, event_id)
            if event is not None:
                event.processing_status = "error"
                event.error_code = type(exc).__name__[:100]
                event.processing_started_at = None
                event.completed_at = datetime.now(timezone.utc)
                db.commit()
        logger.exception("guard_permission_event_processing_failed event_id=%s", event_id)


def _record_directory_failure(db: Session, source: SourceConnection, code: str) -> None:
    """Persist retry backoff and fail-closed directory freshness after rollback."""
    cursor = db.scalar(select(ProviderSyncCursor).where(
        ProviderSyncCursor.organization_id == source.organization_id,
        ProviderSyncCursor.source_id == source.id,
        ProviderSyncCursor.sync_kind == "directory",
    ))
    if cursor is None:
        cursor = ProviderSyncCursor(
            organization_id=source.organization_id, source_id=source.id,
            provider=source.provider, sync_kind="directory",
        )
        db.add(cursor)
    cursor.status = "reauthorization_required" if code == "REAUTHORIZATION_REQUIRED" else "degraded"
    cursor.last_error_code = code
    cursor.last_error_at = datetime.now(timezone.utc)
    source.status = cursor.status
    source.last_error = code


async def synchronize_due_directories() -> int:
    """Run one complete, source-scoped directory snapshot when it is due.

    The snapshot synchronizer only changes the graph after complete provider
    reads. Failures therefore retain the last trusted employee state.
    """
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        sources = list(
            db.scalars(
                select(SourceConnection).where(
                    SourceConnection.provider.in_(
                        ["google-drive", "microsoft365", "sharepoint", "onedrive"]
                    ),
                    SourceConnection.encrypted_credentials.is_not(None),
                )
            )
        )
        cursors = {
            row.source_id: row
            for row in db.scalars(select(ProviderSyncCursor).where(
                ProviderSyncCursor.sync_kind == "directory"
            ))
        }
        due: list[str] = []
        for source in sources:
            cursor = cursors.get(source.id)
            last_success = cursor.last_success_at if cursor else None
            if last_success is None:
                if cursor and cursor.last_error_at:
                    last_error = cursor.last_error_at.replace(tzinfo=cursor.last_error_at.tzinfo or timezone.utc)
                    if (now - last_error).total_seconds() < SOURCE_SYNC_FAILURE_BACKOFF_SECONDS:
                        continue
                due.append(source.id)
                continue
            checked_at = last_success.replace(tzinfo=last_success.tzinfo or timezone.utc)
            if (now - checked_at).total_seconds() >= DIRECTORY_SYNC_SECONDS:
                if cursor and cursor.last_error_at:
                    last_error = cursor.last_error_at.replace(tzinfo=cursor.last_error_at.tzinfo or timezone.utc)
                    if (now - last_error).total_seconds() < SOURCE_SYNC_FAILURE_BACKOFF_SECONDS:
                        continue
                due.append(source.id)
    completed = 0
    for source_id in due:
        with SessionLocal() as db:
            stored_source = db.get(SourceConnection, source_id)
            if stored_source is None or not stored_source.encrypted_credentials:
                continue
            try:
                credentials = json.loads(box.decrypt(stored_source.encrypted_credentials))
                credentials = await refresh_source_credentials_if_needed(db, stored_source, credentials)
                await synchronize_directory(db, stored_source, credentials)
                stored_source.status, stored_source.last_error, stored_source.last_validated_at = (
                    "connected",
                    None,
                    datetime.now(timezone.utc),
                )
                db.commit()
                completed += 1
            except (DirectorySyncError, OAuthRefreshError) as exc:
                # Provider/ORM failures cannot commit a partial employee graph.
                # Roll back even if a synchronizer mutated rows before raising.
                db.rollback()
                retry_source = db.get(SourceConnection, source_id)
                if retry_source is not None:
                    _record_directory_failure(db, retry_source, exc.code)
                    db.commit()
            except Exception as exc:
                db.rollback()
                retry_source = db.get(SourceConnection, source_id)
                if retry_source is not None:
                    _record_directory_failure(db, retry_source, "DIRECTORY_SYNC_INCOMPLETE")
                    db.commit()
                logger.warning(
                    "scheduled_directory_sync_failed source_id=%s error=%s",
                    source_id,
                    type(exc).__name__,
                )
    return completed


async def synchronize_due_acls() -> int:
    """Consume provider ACL deltas and enqueue normalized Guard events."""
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        sources = list(
            db.scalars(
                select(SourceConnection).where(
                    SourceConnection.provider.in_(
                        ["google-drive", "microsoft365", "sharepoint", "onedrive"]
                    ),
                    SourceConnection.encrypted_credentials.is_not(None),
                )
            )
        )
        cursors = {
            row.source_id: row
            for row in db.scalars(
                select(ProviderSyncCursor).where(ProviderSyncCursor.sync_kind == "acl")
            )
        }
        due: list[str] = []
        for candidate_source in sources:
            cursor = cursors.get(candidate_source.id)
            last_success = cursor.last_success_at if cursor else None
            if last_success is None:
                if cursor and cursor.last_error_at:
                    last_error = cursor.last_error_at.replace(tzinfo=cursor.last_error_at.tzinfo or timezone.utc)
                    if (now - last_error).total_seconds() < SOURCE_SYNC_FAILURE_BACKOFF_SECONDS:
                        continue
                due.append(candidate_source.id)
                continue
            normalized_success = last_success.replace(tzinfo=last_success.tzinfo or timezone.utc)
            if (now - normalized_success).total_seconds() >= ACL_SYNC_SECONDS:
                if cursor and cursor.last_error_at:
                    last_error = cursor.last_error_at.replace(tzinfo=cursor.last_error_at.tzinfo or timezone.utc)
                    if (now - last_error).total_seconds() < SOURCE_SYNC_FAILURE_BACKOFF_SECONDS:
                        continue
                due.append(candidate_source.id)
    completed = 0
    for source_id in due:
        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            if source is None or not source.encrypted_credentials:
                continue
            try:
                credentials = json.loads(box.decrypt(source.encrypted_credentials))
                credentials = await refresh_source_credentials_if_needed(db, source, credentials)
                await synchronize_acls(db, source, credentials)
                db.commit()
                completed += 1
            except ACLSyncError as exc:
                db.rollback()
                cursor = db.scalar(
                    select(ProviderSyncCursor).where(
                        ProviderSyncCursor.source_id == source_id,
                        ProviderSyncCursor.sync_kind == "acl",
                    )
                )
                if cursor is None:
                    cursor = ProviderSyncCursor(
                        organization_id=source.organization_id,
                        source_id=source.id,
                        provider=source.provider,
                        sync_kind="acl",
                    )
                    db.add(cursor)
                cursor.status = (
                    "reauthorization_required"
                    if exc.code == "REAUTHORIZATION_REQUIRED"
                    else "degraded"
                )
                cursor.last_error_code = exc.code
                cursor.last_error_at = datetime.now(timezone.utc)
                db.commit()
                # D-25: the code alone hid the real cause for hours. Log the
                # exception types only (no messages, URLs or tokens).
                logger.warning(
                    "scheduled_acl_sync_failed source_id=%s code=%s cause=%s",
                    source_id, exc.code, type(exc.__cause__).__name__ if exc.__cause__ else "-",
                )
            except OAuthRefreshError as exc:
                db.rollback()
                refreshed_source = db.get(SourceConnection, source_id)
                if refreshed_source:
                    refreshed_source.status, refreshed_source.last_error = (
                        (
                            "reauthorization_required"
                            if exc.code == "REAUTHORIZATION_REQUIRED"
                            else "degraded"
                        ),
                        exc.code,
                    )
                    db.commit()
            except Exception as exc:
                db.rollback()
                cursor = db.scalar(
                    select(ProviderSyncCursor).where(
                        ProviderSyncCursor.source_id == source_id,
                        ProviderSyncCursor.sync_kind == "acl",
                    )
                )
                if cursor is None:
                    cursor = ProviderSyncCursor(
                        organization_id=source.organization_id,
                        source_id=source.id,
                        provider=source.provider,
                        sync_kind="acl",
                    )
                    db.add(cursor)
                cursor.status = "degraded"
                cursor.last_error_code = "ACL_SYNC_INCOMPLETE"
                cursor.last_error_at = datetime.now(timezone.utc)
                db.commit()
                logger.warning(
                    "scheduled_acl_sync_failed source_id=%s error=%s", source_id, type(exc).__name__
                )
    return completed


async def reconcile_known_source_acls() -> int:
    """Re-read a bounded set of known resources to repair missed provider deltas."""
    with SessionLocal() as db:
        source_ids = list(
            db.scalars(
                select(SourceConnection.id).where(
                    SourceConnection.provider.in_(
                        ["google-drive", "microsoft365", "sharepoint", "onedrive"]
                    ),
                    SourceConnection.encrypted_credentials.is_not(None),
                )
            )
        )
    completed = 0
    for source_id in source_ids:
        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            if source is None or not source.encrypted_credentials:
                continue
            try:
                credentials = json.loads(box.decrypt(source.encrypted_credentials))
                credentials = await refresh_source_credentials_if_needed(db, source, credentials)
                await reconcile_known_acls(db, source, credentials)
                db.commit()
                completed += 1
            except (ACLSyncError, OAuthRefreshError) as exc:
                db.rollback()
                source = db.get(SourceConnection, source_id)
                if source:
                    source.status, source.last_error = (
                        (
                            "reauthorization_required"
                            if getattr(exc, "code", "") == "REAUTHORIZATION_REQUIRED"
                            else "degraded"
                        ),
                        getattr(exc, "code", "ACL_RECONCILIATION_INCOMPLETE"),
                    )
                    db.commit()
            except Exception:
                db.rollback()
    return completed


async def maintain_microsoft_subscriptions() -> int:
    """Opt-in Graph change notifications for connected Microsoft sources."""
    if not MICROSOFT_NOTIFICATION_URL:
        return 0
    from apps.worker.accessproof_worker.graph_subscriptions import (
        MICROSOFT_SOURCE_PROVIDERS, ensure_microsoft_subscriptions, validate_callback_url as valid_graph_url,
    )
    if not valid_graph_url(MICROSOFT_NOTIFICATION_URL):
        logger.error("microsoft_notification_invalid_callback_configuration")
        return 0
    with SessionLocal() as db:
        source_ids = [s.id for s in db.scalars(select(SourceConnection).where(SourceConnection.status == "connected"))
                      if s.provider.lower() in MICROSOFT_SOURCE_PROVIDERS]
    changed = 0
    for source_id in source_ids:
        try:
            stats = await ensure_microsoft_subscriptions(source_id, callback_url=MICROSOFT_NOTIFICATION_URL, box=box,
                                                         refresh_credentials=refresh_source_credentials_if_needed)
            changed += stats["created"] + stats["renewed"] + stats["retired"]
        except Exception as exc:
            logger.warning("microsoft_subscription_maintenance_failed source_id=%s error=%s", source_id, type(exc).__name__)
    return changed


async def maintain_google_watches() -> int:
    """Register/renew watch channels when an administrator opted in."""
    if not GOOGLE_WATCH_CALLBACK_URL:
        return 0
    if not validate_callback_url(GOOGLE_WATCH_CALLBACK_URL):
        logger.error("google_watch_invalid_callback_configuration")
        return 0
    with SessionLocal() as db:
        source_ids = list(db.scalars(select(SourceConnection.id).where(
            SourceConnection.provider == "google-drive",
            SourceConnection.encrypted_credentials.is_not(None),
        )))
    installed = 0
    for source_id in source_ids:
        try:
            if await ensure_google_watch(
                source_id, callback_url=GOOGLE_WATCH_CALLBACK_URL,
                box=box, refresh_credentials=refresh_source_credentials_if_needed,
            ):
                installed += 1
        except Exception as exc:
            logger.warning("google_watch_registration_failed source_id=%s error=%s",
                           source_id, type(exc).__name__)
    return installed


async def main() -> None:
    configure_tracing("accessproof-worker")
    last_retention = datetime.min.replace(tzinfo=timezone.utc)
    last_directory_sync = datetime.min.replace(tzinfo=timezone.utc)
    last_acl_sync = datetime.min.replace(tzinfo=timezone.utc)
    last_acl_reconcile = datetime.min.replace(tzinfo=timezone.utc)
    last_google_watch = datetime.min.replace(tzinfo=timezone.utc)
    last_microsoft_subscriptions = datetime.min.replace(tzinfo=timezone.utc)
    while True:
        did_work = False
        now = datetime.now(timezone.utc)
        if (now - last_retention).total_seconds() >= max(60, settings.retention_sweep_seconds):
            process_all_retention()
            scan_operational_alerts()
            last_retention = now
            did_work = True
        if (now - last_directory_sync).total_seconds() >= SOURCE_SYNC_CHECK_SECONDS:
            if await synchronize_due_directories():
                did_work = True
            last_directory_sync = now
        if (now - last_acl_sync).total_seconds() >= SOURCE_SYNC_CHECK_SECONDS:
            if await synchronize_due_acls():
                did_work = True
            last_acl_sync = now
        if (now - last_acl_reconcile).total_seconds() >= ACL_RECONCILE_SECONDS:
            if await reconcile_known_source_acls():
                did_work = True
            last_acl_reconcile = now
        if (now - last_microsoft_subscriptions).total_seconds() >= MICROSOFT_SUBSCRIPTION_CHECK_SECONDS:
            if await maintain_microsoft_subscriptions():
                did_work = True
            last_microsoft_subscriptions = now
        if (now - last_google_watch).total_seconds() >= GOOGLE_WATCH_CHECK_SECONDS:
            if await maintain_google_watches():
                did_work = True
            last_google_watch = now
        # Durable PostgreSQL outbox is authoritative; on failure jobs remain
        # eligible for worker restart recovery. Do not couple provider sync to
        # availability of this new optional verification engine.
        try:
            if await asyncio.to_thread(run_worker_cycle):
                did_work = True
        except Exception as exc:
            logger.warning("verification_worker_cycle_failed error=%s", type(exc).__name__)
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
        provider_event_id = claim_one_provider_event()
        if provider_event_id:
            did_work = True
            await process_provider_event(provider_event_id)
        guard_event_id = claim_one_guard_event()
        if guard_event_id:
            did_work = True
            await asyncio.to_thread(process_claimed_guard_event, guard_event_id)
        if not did_work:
            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
