"""Opt-in, durable Google Drive changes.watch registration and renewal.

A notification is only a wake-up; authoritative changes.list remains required.
When no HTTPS callback is configured the product uses periodic ACL sync only.
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import select

from apps.api.accessproof_api.db import (
    ProviderEventSubscription, ProviderSyncCursor, SessionLocal, SourceConnection,
)
from connectors.google_drive.adapter import GoogleDriveAdapter

logger = logging.getLogger(__name__)
CALLBACK_PATH = "/api/v1/provider-events/google-drive"
RENEWAL_MARGIN = timedelta(hours=6)
WATCH_LIFETIME = timedelta(days=3)


def validate_callback_url(callback_url: str) -> bool:
    parsed = urlsplit(callback_url)
    return bool(parsed.scheme == "https" and parsed.hostname
                and not parsed.username and not parsed.password and not parsed.fragment
                and not parsed.query and parsed.path == CALLBACK_PATH)


async def ensure_google_watch(source_id: str, *, callback_url: str, box: Any,
                              refresh_credentials: Any) -> bool:
    """Install or renew one source subscription; return True on new channel.

    Row locks serialize concurrent registrations on PostgreSQL. Expired or
    failed registration never changes an existing healthy subscription. The
    current ACL cursor must already be synchronized, because the watch is
    only a hint and is not a substitute for initial inventory.
    """
    if not validate_callback_url(callback_url):
        raise ValueError("UNSAFE_GOOGLE_WATCH_CALLBACK_URL")
    with SessionLocal() as db:
        source = db.scalar(select(SourceConnection).where(
            SourceConnection.id == source_id,
            SourceConnection.provider == "google-drive",
        ).with_for_update())
        if source is None or not source.encrypted_credentials:
            return False
        cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id,
            ProviderSyncCursor.organization_id == source.organization_id,
            ProviderSyncCursor.sync_kind == "acl",
        ))
        if cursor is None or cursor.status != "connected" or not cursor.cursor:
            return False
        now = datetime.now(timezone.utc)
        current = list(db.scalars(select(ProviderEventSubscription).where(
            ProviderEventSubscription.organization_id == source.organization_id,
            ProviderEventSubscription.source_id == source.id,
            ProviderEventSubscription.provider == "google-drive",
            ProviderEventSubscription.state.in_(["active", "replacing"]),
        )))
        if any((sub.expires_at.replace(tzinfo=sub.expires_at.tzinfo or timezone.utc)
                > now + RENEWAL_MARGIN) for sub in current):
            return False
        creds = json.loads(box.decrypt(source.encrypted_credentials))
        creds = await refresh_credentials(db, source, creds)
        if not creds.get("access_token") or not creds.get("test_root_folder_id"):
            raise ValueError("GOOGLE_WATCH_CREDENTIALS_INCOMPLETE")
        adapter = GoogleDriveAdapter(
            access_token=str(creds["access_token"]),
            test_root_folder_id=str(creds["test_root_folder_id"]),
        )
        channel_id, channel_token = str(uuid4()), secrets.token_urlsafe(32)
        response: dict[str, Any] | None = None
        try:
            response = await adapter.watch_changes(
                page_token=str(cursor.cursor), channel_id=channel_id,
                callback_url=callback_url, channel_token=channel_token,
                expiration_millis=int((now + WATCH_LIFETIME).timestamp() * 1000),
            )
            expires = datetime.fromtimestamp(int(response["expiration"]) / 1000, tz=timezone.utc)
            if expires <= datetime.now(timezone.utc) + timedelta(minutes=2):
                raise ValueError("GOOGLE_WATCH_EXPIRES_TOO_SOON")
            db.add(ProviderEventSubscription(
                organization_id=source.organization_id, source_id=source.id,
                provider="google-drive", channel_type="acl", channel_id=channel_id,
                provider_resource_id=str(response["resourceId"]),
                encrypted_channel_token=box.encrypt(channel_token),
                expires_at=expires, state="active",
            ))
            for prior in current:
                prior.state = "replacing"
            db.commit()
        except Exception:
            db.rollback()
            # The provider could have created the channel even if persistence
            # failed; clean up when its resource identifier is available.
            if response and response.get("resourceId"):
                try:
                    await adapter.stop_watch_channel(
                        channel_id=channel_id, resource_id=str(response["resourceId"]),
                    )
                except Exception:
                    logger.warning("google_watch_orphan_stop_failed source_id=%s", source_id)
            raise
        finally:
            # Cleanup old watches uses a separate client; do not retain a
            # secret-bearing provider client after a registration attempt.
            await adapter._client.aclose()

    if current:
        cleanup = GoogleDriveAdapter(
            access_token=str(creds["access_token"]),
            test_root_folder_id=str(creds["test_root_folder_id"]),
        )
        try:
            for prior in current:
                try:
                    await cleanup.stop_watch_channel(
                        channel_id=prior.channel_id,
                        resource_id=prior.provider_resource_id,
                    )
                    with SessionLocal() as db:
                        stored = db.get(ProviderEventSubscription, prior.id)
                        if stored and stored.state == "replacing":
                            stored.state = "stopped"
                            db.commit()
                except Exception:
                    # Keep the old channel accepted until it expires. Duplicate
                    # notifications are idempotently journaled per channel.
                    logger.warning("google_watch_previous_stop_failed source_id=%s", source_id)
        finally:
            await cleanup._client.aclose()
    return True
