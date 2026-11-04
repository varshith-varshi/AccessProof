"""Microsoft Graph change-notification subscriptions (opt-in) for Microsoft sources.

A notification is only a wake-up: the worker always re-reads authoritative
state from Microsoft (drive delta + permissions, directory sync). Periodic
synchronization stays the safety net, because Microsoft documents a maximum
driveItem notification latency of 6 hours, "unknown" latency for group and
user notifications, and NO `missed`/`subscriptionRemoved` lifecycle events for
these resources (only `reauthorizationRequired`).

Subscriptions per Microsoft source (bounded; Graph quota is 100 directory
subscriptions per app and tenant):
  * acl:       /drives/{drive}/root            changeType=updated
               with `Prefer: includesecuritywebhooks` (security events where
               Microsoft honours it; not assumed to cover every permission change)
  * directory: /groups/{id}/members for groups that carry grants (<= MAX_GROUPS)
  * directory: /users                           (disable / delete / create)

When ACCESSPROOF_MICROSOFT_NOTIFICATION_URL is unset the product stays on
periodic synchronization only. Failures are recorded on the subscription row
and never affect authorization state.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from apps.api.accessproof_api.db import (
    GuardGroup, GuardPermissionGrant, ProviderEventSubscription, SessionLocal, SourceConnection,
)
from apps.api.accessproof_api.event_sync import MICROSOFT_PROVIDER, microsoft_binding
from apps.api.accessproof_api.observability import graph_subscription_operations

logger = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"
CALLBACK_PATH = "/api/v1/provider-events/microsoft"
# Documented maxima: driveItem 42,300 min; user/group 41,760 min. Stay below.
LIFETIME = {"acl": timedelta(minutes=42_000), "directory": timedelta(minutes=41_400)}
RENEWAL_MARGIN = timedelta(days=2)
MAX_GROUPS = 40
MICROSOFT_SOURCE_PROVIDERS = {"microsoft365", "sharepoint", "onedrive"}


def validate_callback_url(url: str) -> bool:
    parsed = urlsplit(url)
    return bool(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                and not parsed.fragment and not parsed.query and parsed.path == CALLBACK_PATH)


@dataclass(frozen=True)
class Desired:
    channel_type: str      # "acl" | "directory"
    resource: str          # Graph resource path without the base URL
    change_type: str
    security_webhooks: bool = False


def desired_subscriptions(drive_id: str, group_ids: list[str]) -> list[Desired]:
    wanted = [Desired("acl", f"drives/{drive_id}/root", "updated", security_webhooks=True),
              Desired("directory", "users", "updated,deleted")]
    wanted += [Desired("directory", f"groups/{gid}/members", "updated,deleted") for gid in sorted(set(group_ids))[:MAX_GROUPS]]
    return wanted


def granted_group_ids(db: Any, source: SourceConnection) -> list[str]:
    rows = db.execute(select(GuardGroup.provider_group_id).join(
        GuardPermissionGrant, GuardPermissionGrant.principal_id == GuardGroup.id,
    ).where(
        GuardPermissionGrant.organization_id == source.organization_id,
        GuardPermissionGrant.source_id == source.id,
        GuardPermissionGrant.principal_type == "group",
        GuardPermissionGrant.active.is_(True),
    ).distinct()).all()
    return [str(r[0]) for r in rows if r[0]]


class GraphSubscriptionClient:
    def __init__(self, access_token: str, client: httpx.AsyncClient | None = None):
        self._token = access_token
        self._client = client or httpx.AsyncClient(timeout=20, follow_redirects=False, trust_env=False)

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json", **(extra or {})}

    async def create(self, want: Desired, *, callback_url: str, client_state: str, expires: datetime) -> dict:
        body = {"changeType": want.change_type, "notificationUrl": callback_url,
                "lifecycleNotificationUrl": callback_url, "resource": want.resource,
                "expirationDateTime": expires.strftime("%Y-%m-%dT%H:%M:%S.0000000Z"),
                "clientState": client_state, "latestSupportedTlsVersion": "v1_2"}
        headers = self._headers({"Prefer": "includesecuritywebhooks"} if want.security_webhooks else None)
        response = await self._client.post(f"{GRAPH}/subscriptions", json=body, headers=headers)
        response.raise_for_status()
        data = response.json()
        data["_preference_applied"] = response.headers.get("Preference-Applied", "")
        return data

    async def renew(self, subscription_id: str, expires: datetime) -> dict:
        # PATCH both renews and reauthorizes (never combine with /reauthorize
        # within 10 minutes, per Microsoft guidance).
        response = await self._client.patch(
            f"{GRAPH}/subscriptions/{subscription_id}", headers=self._headers(),
            json={"expirationDateTime": expires.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")})
        response.raise_for_status()
        return response.json()

    async def delete(self, subscription_id: str) -> None:
        response = await self._client.delete(f"{GRAPH}/subscriptions/{subscription_id}", headers=self._headers())
        if response.status_code not in (204, 404):
            response.raise_for_status()

    async def aclose(self) -> None:
        await self._client.aclose()


async def ensure_microsoft_subscriptions(
    source_id: str, *, callback_url: str, box: Any,
    refresh_credentials: Callable[[Any, SourceConnection, dict], Awaitable[dict]],
    client_factory: Callable[[str], GraphSubscriptionClient] = GraphSubscriptionClient,
    now: datetime | None = None,
) -> dict[str, int]:
    """Create missing, renew expiring and retire unwanted subscriptions for one source."""
    if not validate_callback_url(callback_url):
        raise ValueError("UNSAFE_MICROSOFT_NOTIFICATION_URL")
    now = now or datetime.now(timezone.utc)
    stats = {"created": 0, "renewed": 0, "retired": 0, "failed": 0}
    import json
    with SessionLocal() as db:
        source = db.get(SourceConnection, source_id)
        if (source is None or source.provider.lower() not in MICROSOFT_SOURCE_PROVIDERS
                or not source.encrypted_credentials or source.status != "connected"):
            return stats
        credentials = await refresh_credentials(db, source, json.loads(box.decrypt(source.encrypted_credentials)))
        tenant_id, drive_id = str(credentials.get("tenant_id") or ""), str(credentials.get("drive_id") or "")
        token = str(credentials.get("access_token") or "")
        if not tenant_id or not drive_id or not token:
            return stats
        wanted = {(w.channel_type, microsoft_binding(tenant_id, w.resource)): w
                  for w in desired_subscriptions(drive_id, granted_group_ids(db, source))}
        existing = list(db.scalars(select(ProviderEventSubscription).where(
            ProviderEventSubscription.organization_id == source.organization_id,
            ProviderEventSubscription.source_id == source.id,
            ProviderEventSubscription.provider == MICROSOFT_PROVIDER,
        )))
        graph = client_factory(token)
        try:
            have: set[tuple[str, str]] = set()
            for row in existing:
                key = (row.channel_type, row.provider_resource_id)
                expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
                if key not in wanted or row.state not in {"active", "replacing"} or expires <= now:
                    if row.state != "retired":
                        try:
                            await graph.delete(row.channel_id)
                        except httpx.HTTPError:
                            pass  # best effort; an unknown subscription is rejected at intake anyway
                        row.state = "retired"
                        stats["retired"] += 1
                    continue
                if row.state == "replacing" or expires - now < RENEWAL_MARGIN:
                    try:
                        await graph.renew(row.channel_id, now + LIFETIME[row.channel_type])
                        row.expires_at, row.state = now + LIFETIME[row.channel_type], "active"
                        stats["renewed"] += 1
                    except httpx.HTTPError:
                        # Could not renew/reauthorize: retire and recreate below.
                        row.state = "retired"
                        stats["retired"] += 1
                        continue
                have.add(key)
            for key, want in wanted.items():
                if key in have:
                    continue
                client_state = secrets.token_urlsafe(48)[:96]
                expires = now + LIFETIME[want.channel_type]
                try:
                    created = await graph.create(want, callback_url=callback_url, client_state=client_state, expires=expires)
                except httpx.HTTPStatusError as exc:
                    stats["failed"] += 1
                    logger.warning("graph_subscription_create_failed source_id=%s channel=%s status=%s",
                                   source.id, want.channel_type, exc.response.status_code)
                    continue
                except httpx.HTTPError as exc:
                    stats["failed"] += 1
                    logger.warning("graph_subscription_create_failed source_id=%s channel=%s error=%s",
                                   source.id, want.channel_type, type(exc).__name__)
                    continue
                if want.security_webhooks and "includesecuritywebhooks" not in created.get("_preference_applied", "").lower():
                    logger.warning("graph_security_webhooks_not_applied source_id=%s", source.id)
                db.add(ProviderEventSubscription(
                    organization_id=source.organization_id, source_id=source.id, provider=MICROSOFT_PROVIDER,
                    channel_type=want.channel_type, channel_id=str(created["id"]),
                    provider_resource_id=key[1], encrypted_channel_token=box.encrypt(client_state),
                    state="active", expires_at=expires,
                ))
                stats["created"] += 1
            db.commit()
        finally:
            await graph.aclose()
    for operation, count in stats.items():
        if count:
            graph_subscription_operations.labels("all", operation).inc(count)
    return stats


async def handle_lifecycle(subscription_id: str, lifecycle: str, *, box: Any,
                           refresh_credentials: Callable[[Any, SourceConnection, dict], Awaitable[dict]],
                           client_factory: Callable[[str], GraphSubscriptionClient] = GraphSubscriptionClient,
                           now: datetime | None = None) -> str:
    """reauthorizationRequired -> PATCH (renews + reauthorizes);
    subscriptionRemoved/missed -> mark for replacement. The caller always
    follows with an authoritative resync of the subscription's channel."""
    import json
    now = now or datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.get(ProviderEventSubscription, subscription_id)
        if row is None:
            return "UNKNOWN_SUBSCRIPTION"
        if lifecycle != "reauthorizationRequired":
            row.state = "replacing"
            db.commit()
            return "MARKED_FOR_REPLACEMENT"
        source = db.get(SourceConnection, row.source_id)
        credentials = await refresh_credentials(db, source, json.loads(box.decrypt(source.encrypted_credentials)))
        graph = client_factory(str(credentials.get("access_token") or ""))
        try:
            await graph.renew(row.channel_id, now + LIFETIME.get(row.channel_type, LIFETIME["directory"]))
            row.expires_at, row.state = now + LIFETIME.get(row.channel_type, LIFETIME["directory"]), "active"
            outcome = "REAUTHORIZED"
        except httpx.HTTPError:
            row.state = "replacing"
            outcome = "REAUTHORIZATION_FAILED_REPLACING"
        finally:
            await graph.aclose()
        db.commit()
        return outcome
