"""Provider notification intake for event-triggered ACL synchronization.

Provider messages are hints only.  They are bound to a registered subscription,
durably journaled, then a worker fetches the authoritative provider delta.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
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


# --------------------------------------------------------------------------
# Microsoft Graph change notifications (driveItem root, group members, users)
# --------------------------------------------------------------------------
MICROSOFT_PROVIDER = "microsoft365"
_GRAPH_LIFECYCLE = {"reauthorizationRequired", "subscriptionRemoved", "missed"}
_GUID_CHARS = set("0123456789abcdef-")


def microsoft_binding(tenant_id: str, resource: str) -> str:
    """Stored in provider_resource_id: the tenant and resource a subscription covers."""
    return f"{tenant_id.lower()}|{normalize_graph_resource(resource)}"


def normalize_graph_resource(resource: str) -> str:
    return str(resource or "").strip().strip("/").lower()


def _resource_in_scope(notified: str, subscribed: str) -> bool:
    """Graph reports e.g. ``Groups/{id}`` for a ``/groups/{id}/members``
    subscription and the drive root for ``/drives/{id}/root``. Accept only the
    same object or a parent/child path of it; never another drive or group."""
    n, s = normalize_graph_resource(notified), normalize_graph_resource(subscribed)
    if not n or not s:
        return False
    return n == s or n.startswith(s + "/") or s.startswith(n + "/")


def accept_microsoft_notifications(
    db: Session, payload: object, *, decrypt_token: Callable[[str], str],
    now: datetime | None = None,
) -> tuple[list[ProviderEventJournal], list[str]]:
    """Authenticate and journal a Microsoft Graph notification batch.

    Returns (journaled events, rejection codes). Each item is authenticated on
    its own: known active unexpired subscription, constant-time clientState
    match, tenant binding and resource scope. A notification is only a wake-up
    hint: the worker re-reads authoritative state from Microsoft; nothing in
    the payload is ever used as permission data.

    Graph drive notifications carry no unique id, so identical payloads are
    normal for distinct changes. Instead of content de-duplication (which
    would drop real changes), a new hint is coalesced into a still-pending
    event for the same subscription; an in-progress sync gets a follow-up.
    """
    now = now or datetime.now(timezone.utc)
    if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
        raise NotificationRejected("INVALID_NOTIFICATION_BATCH")
    items = payload["value"]
    if not 1 <= len(items) <= 1000:
        raise NotificationRejected("INVALID_NOTIFICATION_BATCH")
    events: list[ProviderEventJournal] = []
    rejected: list[str] = []
    for item in items:
        try:
            events.append(_accept_one_microsoft(db, item, decrypt_token=decrypt_token, now=now))
        except NotificationRejected as exc:
            rejected.append(str(exc))
    return events, rejected


def _accept_one_microsoft(db: Session, item: object, *, decrypt_token: Callable[[str], str],
                          now: datetime) -> ProviderEventJournal:
    if not isinstance(item, dict):
        raise NotificationRejected("INVALID_NOTIFICATION")
    subscription_id, client_state, tenant_id = (str(item.get(k) or "") for k in ("subscriptionId", "clientState", "tenantId"))
    if (not subscription_id or len(subscription_id) > 255 or not client_state or len(client_state) > 128
            or not tenant_id or len(tenant_id) > 64 or set(tenant_id.lower()) - _GUID_CHARS):
        raise NotificationRejected("MISSING_NOTIFICATION_FIELDS")
    lifecycle = item.get("lifecycleEvent")
    if lifecycle is not None and lifecycle not in _GRAPH_LIFECYCLE:
        raise NotificationRejected("UNKNOWN_LIFECYCLE_EVENT")
    subscription = db.scalar(select(ProviderEventSubscription).where(
        ProviderEventSubscription.provider == MICROSOFT_PROVIDER,
        ProviderEventSubscription.channel_id == subscription_id,
    ))
    if subscription is None or subscription.state not in {"active", "replacing"}:
        raise NotificationRejected("UNKNOWN_OR_INACTIVE_SUBSCRIPTION")
    expires_at = subscription.expires_at if subscription.expires_at.tzinfo else subscription.expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise NotificationRejected("EXPIRED_SUBSCRIPTION")
    expected = decrypt_token(subscription.encrypted_channel_token)
    if not expected or not hmac.compare_digest(expected.encode(), client_state.encode()):
        raise NotificationRejected("CLIENT_STATE_MISMATCH")
    bound_tenant, _, bound_resource = str(subscription.provider_resource_id).partition("|")
    if not hmac.compare_digest(bound_tenant, tenant_id.lower()):
        raise NotificationRejected("TENANT_BINDING_MISMATCH")
    if lifecycle is None:
        if str(item.get("changeType") or "") not in {"updated", "deleted", "created"}:
            raise NotificationRejected("UNSUPPORTED_CHANGE_TYPE")
        if not _resource_in_scope(str(item.get("resource") or ""), bound_resource):
            raise NotificationRejected("RESOURCE_BINDING_MISMATCH")
    # Authenticated by the subscription secret: scope every further read/write
    # to its organization (RLS), never to caller-supplied identifiers.
    set_tenant_context(db, subscription.organization_id)
    source = db.get(SourceConnection, subscription.source_id)
    if source is None or source.organization_id != subscription.organization_id:
        raise NotificationRejected("SOURCE_BINDING_MISMATCH")
    subscription.last_notification_at = now
    event_type = f"lifecycle:{lifecycle}" if lifecycle else f"{subscription.channel_type}:{item.get('changeType')}"
    pending = db.scalar(select(ProviderEventJournal).where(
        ProviderEventJournal.organization_id == subscription.organization_id,
        ProviderEventJournal.subscription_id == subscription.id,
        ProviderEventJournal.event_type == event_type,
        ProviderEventJournal.status.in_(["received", "retry"]),
    ).limit(1))
    if pending is not None:
        return pending
    digest = hashlib.sha256(repr(sorted(item.items())).encode()).hexdigest()
    event = ProviderEventJournal(
        organization_id=subscription.organization_id, source_id=subscription.source_id,
        subscription_id=subscription.id, provider=MICROSOFT_PROVIDER, event_type=event_type,
        provider_message_number=digest[:64],
        dedupe_key=hashlib.sha256(f"{subscription.id}:{now.isoformat()}:{secrets.token_hex(8)}".encode()).hexdigest(),
        status="received", received_at=now, next_attempt_at=now,
    )
    db.add(event)
    db.flush()
    return event
