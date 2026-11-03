"""Provider notification intake for event-triggered ACL synchronization.

Provider messages are hints only.  They are bound to a registered subscription,
durably journaled, then a worker fetches the authoritative provider delta.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Callable, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ProviderEventJournal, ProviderEventSubscription, SourceConnection, set_tenant_context


class NotificationRejected(ValueError):
    """An untrusted notification must not affect authorization state."""


def _header(headers: Mapping[str, str], name: str) -> str:
    return str(headers.get(name, "") or "").strip()


def accept_google_notification(
    db: Session, *, headers: Mapping[str, str], decrypt_token: Callable[[str], str],
) -> ProviderEventJournal | None:
    """Authenticate and journal one Google channel notification.

    ``None`` means a syntactically valid but unsupported state was ignored. It
    is deliberately not an authorization success and creates no policy change.
    """
    channel_id = _header(headers, "x-goog-channel-id")
    token = _header(headers, "x-goog-channel-token")
    resource_id = _header(headers, "x-goog-resource-id")
    state = _header(headers, "x-goog-resource-state").lower()
    message_number = _header(headers, "x-goog-message-number")
    if not channel_id or not token or not resource_id or not message_number:
        raise NotificationRejected("MISSING_NOTIFICATION_HEADERS")
    if len(channel_id) > 255 or len(resource_id) > 1024 or len(token) > 1024 or len(message_number) > 128:
        raise NotificationRejected("NOTIFICATION_HEADER_LIMIT")
    if not message_number.isdecimal() or int(message_number) < 1:
        raise NotificationRejected("INVALID_NOTIFICATION_SEQUENCE")
    subscription = db.scalar(select(ProviderEventSubscription).where(
        ProviderEventSubscription.provider == "google-drive",
        ProviderEventSubscription.channel_id == channel_id,
    ))
    if subscription is None or subscription.state not in {"active", "replacing"}:
        raise NotificationRejected("UNKNOWN_OR_INACTIVE_CHANNEL")
    expires_at = subscription.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise NotificationRejected("EXPIRED_CHANNEL")
    if not hmac.compare_digest(str(subscription.provider_resource_id), resource_id):
        raise NotificationRejected("RESOURCE_BINDING_MISMATCH")
    expected = decrypt_token(subscription.encrypted_channel_token)
    if not expected or not hmac.compare_digest(expected, token):
        raise NotificationRejected("CHANNEL_TOKEN_MISMATCH")
    # The channel secret authenticated this subscription; scope every further
    # tenant read/write to its organization (RLS), never to caller input.
    set_tenant_context(db, subscription.organization_id)
    subscription.last_notification_at = datetime.now(timezone.utc)
    if state not in {"sync", "change", "update", "add", "remove", "trash", "untrash"}:
        return None
    dedupe_key = hashlib.sha256(f"{subscription.id}:{message_number}".encode()).hexdigest()
    existing = db.scalar(select(ProviderEventJournal).where(
        ProviderEventJournal.organization_id == subscription.organization_id,
        ProviderEventJournal.dedupe_key == dedupe_key,
    ))
    if existing is not None:
        return existing
    source = db.get(SourceConnection, subscription.source_id)
    if source is None or source.organization_id != subscription.organization_id:
        raise NotificationRejected("SOURCE_BINDING_MISMATCH")
    event = ProviderEventJournal(
        organization_id=subscription.organization_id, source_id=subscription.source_id,
        subscription_id=subscription.id, provider="google-drive", event_type=state,
        provider_message_number=message_number, dedupe_key=dedupe_key, status="received",
    )
    db.add(event)
    db.flush()
    return event
