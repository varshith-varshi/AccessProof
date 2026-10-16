"""Provider ACL change ingestion into the durable Guard permission graph.

Provider deltas are treated as notifications.  The authoritative permission
state is re-read for each changed item, then translated into idempotent Guard
permission events.  A provider outage never removes the last trusted grant.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import (
    GuardGroup,
    GuardGroupMembership,
    GuardPermissionEvent,
    GuardPermissionGrant,
    GuardResource,
    GuardSubject,
    ProviderSyncCursor,
    SourceConnection,
)
from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import AuthenticationError, AuthorizationError, ProviderUnavailableError, RateLimitError


class ACLSyncError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _provider_error_code(exc: Exception) -> str:
    if isinstance(exc, AuthenticationError):
        return "REAUTHORIZATION_REQUIRED"
    if isinstance(exc, AuthorizationError):
        return "INSUFFICIENT_PERMISSION"
    if isinstance(exc, (RateLimitError, ProviderUnavailableError)):
        return "DEGRADED"
    return "ACL_SYNC_INCOMPLETE"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _provider(source: SourceConnection) -> str:
    return "microsoft365" if source.provider.lower() in {"microsoft365", "sharepoint", "onedrive"} else source.provider.lower()


def _principal(permission: dict[str, Any], provider: str) -> tuple[str, str, str | None]:
    """Return principal type, provider identifier, and optional email."""
    if provider == "google-drive":
        ptype = str(permission.get("type") or "user")
        if ptype == "group":
            return "group", str(permission.get("emailAddress") or permission.get("id") or ""), permission.get("emailAddress")
        if ptype in {"domain", "anyone"}:
            return "organization", str(permission.get("domain") or ptype), None
        return "subject", str(permission.get("id") or permission.get("emailAddress") or ""), permission.get("emailAddress")
    granted = permission.get("grantedToV2") or {}
    identities = permission.get("grantedToIdentitiesV2") or []
    if identities and not granted:
        granted = identities[0]
    if granted.get("group"):
        group = granted["group"]
        return "group", str(group.get("id") or group.get("email") or ""), group.get("email")
    if granted.get("siteUser"):
        user = granted["siteUser"]
        return "subject", str(user.get("userId") or user.get("id") or user.get("email") or ""), user.get("email")
    user = granted.get("user") or {}
    return "subject", str(user.get("id") or user.get("email") or user.get("displayName") or ""), user.get("email")


def _subjects_for_principal(db: Session, source: SourceConnection, provider: str, ptype: str, pid: str, email: str | None) -> list[tuple[str, str | None]]:
    if ptype == "subject":
        direct = db.get(GuardSubject, pid)
        if direct is not None and direct.organization_id == source.organization_id:
            return [(direct.id, None)]
        candidates = list(db.scalars(select(GuardSubject).where(
            GuardSubject.organization_id == source.organization_id,
            GuardSubject.provider == provider,
        )))
        email_l = (email or "").lower()
        return [(row.id, None) for row in candidates if row.provider_subject_id == pid or (email_l and (row.primary_email or "").lower() == email_l)]
    if ptype == "group":
        group = db.get(GuardGroup, pid)
        if group is None:
            group = db.scalar(select(GuardGroup).where(
            GuardGroup.organization_id == source.organization_id,
            GuardGroup.provider == provider,
            GuardGroup.provider_group_id == pid,
            ))
        if group is None and email:
            group = db.scalar(select(GuardGroup).where(
                GuardGroup.organization_id == source.organization_id,
                GuardGroup.provider == provider,
                GuardGroup.provider_email == email,
            ))
        if group is None:
            return []
        return [(membership.subject_id, group.id) for membership in db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == source.organization_id,
            GuardGroupMembership.group_id == group.id,
            GuardGroupMembership.active.is_(True),
        ))]
    return [(subject.id, None) for subject in db.scalars(select(GuardSubject).where(
        GuardSubject.organization_id == source.organization_id,
        GuardSubject.provider == provider,
        GuardSubject.status == "active",
    ))]


def _resource(db: Session, source: SourceConnection, file_id: str, item: dict[str, Any] | None, now: datetime) -> GuardResource:
    row = db.scalar(select(GuardResource).where(
        GuardResource.organization_id == source.organization_id,
        GuardResource.source_id == source.id,
        GuardResource.provider_resource_id == file_id,
    ))
    if row is None:
        row = GuardResource(organization_id=source.organization_id, source_id=source.id, provider_resource_id=file_id)
        db.add(row)
    metadata = dict(json.loads(row.metadata_json or "{}"))
    if item:
        metadata.update({key: item.get(key) for key in ("name", "mimeType", "parentReference", "webUrl") if item.get(key) is not None})
        metadata["deleted"] = False
        row.resource_type = "folder" if item.get("folder") else "document"
    row.metadata_json = json.dumps(metadata, sort_keys=True)
    row.last_synced_at = now
    db.flush()
    return row


def _event(db: Session, *, source: SourceConnection, provider: str, resource: GuardResource, subject_id: str, change_type: str, revision: int, mutation: dict[str, Any], stable: str) -> bool:
    dedupe = hashlib.sha256(stable.encode()).hexdigest()[:120]
    if db.scalar(select(GuardPermissionEvent.id).where(
        GuardPermissionEvent.organization_id == source.organization_id,
        GuardPermissionEvent.dedupe_key == dedupe,
    )):
        return False
    db.add(GuardPermissionEvent(
        organization_id=source.organization_id, source_id=source.id, provider=provider,
        provider_revision=revision, subject_id=subject_id, resource_id=resource.id,
        change_type=change_type, dedupe_key=dedupe, processing_status="queued",
        mutation_json=json.dumps(mutation, sort_keys=True), observed_at=_now(), received_at=_now(),
    ))
    return True


def _queue_snapshot(db: Session, source: SourceConnection, provider: str, resource: GuardResource, permissions: list[dict[str, Any]], revision: int, stable_prefix: str) -> int:
    queued = 0
    for permission in permissions:
        permission_id = str(permission.get("id") or "")
        if not permission_id:
            continue
        grant_key = f"{provider}:{permission_id}"
        ptype, pid, email = _principal(permission, provider)
        for subject_id, group_id in _subjects_for_principal(db, source, provider, ptype, pid, email):
            principal_id = group_id if ptype == "group" and group_id else (subject_id if ptype == "subject" else source.organization_id)
            existing = db.scalar(select(GuardPermissionGrant).where(
                GuardPermissionGrant.organization_id == source.organization_id,
                GuardPermissionGrant.source_id == source.id,
                GuardPermissionGrant.resource_id == resource.id,
                GuardPermissionGrant.grant_key == grant_key,
                GuardPermissionGrant.principal_type == ptype,
                GuardPermissionGrant.principal_id == principal_id,
                GuardPermissionGrant.active.is_(True),
            ))
            pending_marker = f'"grant_key": "{grant_key}"'
            pending = db.scalar(select(GuardPermissionEvent.id).where(
                GuardPermissionEvent.organization_id == source.organization_id,
                GuardPermissionEvent.resource_id == resource.id,
                GuardPermissionEvent.subject_id == subject_id,
                GuardPermissionEvent.change_type == "grant_upsert",
                GuardPermissionEvent.processing_status.in_(["queued", "processing"]),
                GuardPermissionEvent.mutation_json.contains(pending_marker),
            ))
            if existing is not None or pending is not None:
                continue
            mutation = {"grant_key": grant_key, "principal_type": ptype, "principal_id": pid, "group_id": pid, "scope": "read", "grant_effect": "allow", "snapshot_complete": True}
            if _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_upsert", revision=revision, mutation=mutation, stable=f"{stable_prefix}:{grant_key}:{subject_id}:{revision}:upsert"):
                queued += 1
    return queued


async def synchronize_acls(db: Session, source: SourceConnection, credentials: dict[str, Any], *, max_pages: int = 50) -> dict[str, int]:
    provider = _provider(source)
    if not credentials.get("access_token"):
        raise ACLSyncError("REAUTHORIZATION_REQUIRED")
    cursor = db.scalar(select(ProviderSyncCursor).where(
        ProviderSyncCursor.organization_id == source.organization_id,
        ProviderSyncCursor.source_id == source.id,
        ProviderSyncCursor.sync_kind == "acl",
    ))
    if cursor is None:
        cursor = ProviderSyncCursor(organization_id=source.organization_id, source_id=source.id, provider=provider, sync_kind="acl")
        db.add(cursor)
    cursor.status, cursor.last_started_at, cursor.last_error_code = "syncing", _now(), None
    db.flush()
    if provider == "google-drive":
        adapter: Any = GoogleDriveAdapter(access_token=credentials["access_token"], test_root_folder_id=credentials["test_root_folder_id"])
        token = cursor.cursor
        if token is None:
            page = await adapter.acl_change_page(None)
            token = page.get("startPageToken")
            cursor.cursor = str(token) if token else None
            resource = _resource(db, source, str(credentials["test_root_folder_id"]), {"id": str(credentials["test_root_folder_id"]), "name": "configured test boundary"}, _now())
            seed_events = _queue_snapshot(db, source, provider, resource, await adapter.permissions_snapshot(str(credentials["test_root_folder_id"])), 1, f"{source.id}:seed")
            cursor.last_provider_revision = "1"
            cursor.status = "connected"
            cursor.last_success_at = _now()
            await adapter._client.aclose()
            return {"pages": 0, "changes": 1, "events": seed_events}
    elif provider == "microsoft365":
        adapter = Microsoft365Adapter(access_token=credentials["access_token"], drive_id=credentials["drive_id"], test_root_item_id=credentials["test_root_item_id"])
        token = cursor.cursor
    else:
        raise ACLSyncError("ACL_SYNC_UNSUPPORTED")
    pages = changes = events = 0
    try:
        base_revision = int(cursor.last_provider_revision or "0")
    except ValueError:
        base_revision = 0
    try:
        if provider == "microsoft365" and token is None:
            boundary = str(credentials["test_root_item_id"])
            resource = _resource(db, source, boundary, {"id": boundary, "name": "configured test boundary"}, _now())
            events += _queue_snapshot(db, source, provider, resource, await adapter.permissions_snapshot(boundary), 1, f"{source.id}:seed")
            cursor.last_provider_revision = "1"
        while pages < max_pages and (pages == 0 or token):
            page = await (adapter.acl_change_page(token) if provider == "google-drive" else adapter.acl_delta_page(token))
            pages += 1
            revision = base_revision + pages + 1
            entries = page.get("changes", []) if provider == "google-drive" else page.get("value", [])
            for change in entries:
                file_id = str(change.get("fileId") or change.get("id") or "")
                if not file_id:
                    continue
                changes += 1
                removed = bool(change.get("removed") or change.get("deleted"))
                resource = _resource(db, source, file_id, change.get("file") if provider == "google-drive" else change, _now())
                if removed:
                    resource.metadata_json = json.dumps({**json.loads(resource.metadata_json or "{}"), "deleted": True}, sort_keys=True)
                    existing = list(db.scalars(select(GuardPermissionGrant).where(
                        GuardPermissionGrant.organization_id == source.organization_id,
                        GuardPermissionGrant.source_id == source.id,
                        GuardPermissionGrant.resource_id == resource.id,
                        GuardPermissionGrant.active.is_(True),
                    )))
                    for grant in existing:
                        subject_ids = [grant.principal_id] if grant.principal_type == "subject" else [s for s, _ in _subjects_for_principal(db, source, provider, "group" if grant.principal_type == "group" else "organization", grant.principal_id, None)]
                        for subject_id in subject_ids:
                            pending = db.scalar(select(GuardPermissionEvent.id).where(
                                GuardPermissionEvent.organization_id == source.organization_id,
                                GuardPermissionEvent.resource_id == resource.id,
                                GuardPermissionEvent.subject_id == subject_id,
                                GuardPermissionEvent.change_type == "grant_revoke",
                                GuardPermissionEvent.processing_status.in_(["queued", "processing"]),
                                GuardPermissionEvent.mutation_json.contains(f'"grant_key": "{grant.grant_key}"'),
                            ))
                            if pending is not None:
                                continue
                            if _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_revoke", revision=revision, mutation={"grant_key": grant.grant_key, "scope": grant.scope, "snapshot_complete": True}, stable=f"{source.id}:{file_id}:{grant.grant_key}:{revision}:revoke"):
                                events += 1
                    continue
                permissions = await adapter.permissions_snapshot(file_id)
                current_keys: set[str] = set()
                for permission in permissions:
                    permission_id = str(permission.get("id") or "")
                    if not permission_id:
                        continue
                    grant_key = f"{provider}:{permission_id}"
                    current_keys.add(grant_key)
                    ptype, pid, email = _principal(permission, provider)
                    subjects = _subjects_for_principal(db, source, provider, ptype, pid, email)
                    for subject_id, group_id in subjects:
                        mutation = {"grant_key": grant_key, "principal_type": ptype, "principal_id": pid, "group_id": pid, "scope": "read", "grant_effect": "allow", "snapshot_complete": True}
                        if _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_upsert", revision=revision, mutation=mutation, stable=f"{source.id}:{file_id}:{grant_key}:{subject_id}:{revision}:upsert"):
                            events += 1
                for grant in db.scalars(select(GuardPermissionGrant).where(
                    GuardPermissionGrant.organization_id == source.organization_id,
                    GuardPermissionGrant.source_id == source.id,
                    GuardPermissionGrant.resource_id == resource.id,
                    GuardPermissionGrant.active.is_(True),
                )):
                    if grant.grant_key not in current_keys:
                        for subject_id, _ in _subjects_for_principal(db, source, provider, grant.principal_type, grant.principal_id, None):
                            if _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_revoke", revision=revision, mutation={"grant_key": grant.grant_key, "scope": grant.scope, "snapshot_complete": True}, stable=f"{source.id}:{file_id}:{grant.grant_key}:{subject_id}:{revision}:revoke"):
                                events += 1
            next_token = page.get("nextPageToken") or page.get("@odata.nextLink")
            if next_token:
                token = str(next_token)
                cursor.cursor = token
                continue
            token = page.get("newStartPageToken") or page.get("@odata.deltaLink") or token
            cursor.cursor = str(token)
            break
        cursor.status, cursor.last_success_at, cursor.last_provider_revision = "connected", _now(), str(base_revision + pages)
        return {"pages": pages, "changes": changes, "events": events}
    except Exception as exc:
        code = _provider_error_code(exc)
        cursor.status, cursor.last_error_at, cursor.last_error_code = "degraded", _now(), code
        raise ACLSyncError(code) from exc
    finally:
        await adapter._client.aclose()


async def reconcile_known_acls(db: Session, source: SourceConnection, credentials: dict[str, Any], *, limit: int = 100) -> dict[str, int]:
    """Bounded authoritative reconciliation for resources already in the graph."""
    provider = _provider(source)
    if not credentials.get("access_token"):
        raise ACLSyncError("REAUTHORIZATION_REQUIRED")
    if provider == "google-drive":
        adapter: Any = GoogleDriveAdapter(access_token=credentials["access_token"], test_root_folder_id=credentials["test_root_folder_id"])
    elif provider == "microsoft365":
        adapter = Microsoft365Adapter(access_token=credentials["access_token"], drive_id=credentials["drive_id"], test_root_item_id=credentials["test_root_item_id"])
    else:
        raise ACLSyncError("ACL_SYNC_UNSUPPORTED")
    resources = list(db.scalars(select(GuardResource).where(
        GuardResource.organization_id == source.organization_id,
        GuardResource.source_id == source.id,
    ).order_by(GuardResource.last_synced_at.asc()).limit(max(1, min(limit, 500)))))
    queued = 0
    revision = int(datetime.now(timezone.utc).timestamp())
    try:
        for resource in resources:
            metadata = json.loads(resource.metadata_json or "{}")
            if metadata.get("deleted"):
                continue
            permissions = await adapter.permissions_snapshot(resource.provider_resource_id)
            current_keys = {f"{provider}:{str(permission.get('id'))}" for permission in permissions if permission.get("id")}
            queued += _queue_snapshot(db, source, provider, resource, permissions, revision, f"{source.id}:reconcile:{resource.provider_resource_id}")
            for grant in db.scalars(select(GuardPermissionGrant).where(
                GuardPermissionGrant.organization_id == source.organization_id,
                GuardPermissionGrant.source_id == source.id,
                GuardPermissionGrant.resource_id == resource.id,
                GuardPermissionGrant.active.is_(True),
            )):
                if grant.grant_key in current_keys:
                    continue
                subject_ids = [grant.principal_id] if grant.principal_type == "subject" else [subject_id for subject_id, _ in _subjects_for_principal(db, source, provider, grant.principal_type, grant.principal_id, None)]
                for subject_id in subject_ids:
                    marker = f'"grant_key": "{grant.grant_key}"'
                    pending = db.scalar(select(GuardPermissionEvent.id).where(
                        GuardPermissionEvent.organization_id == source.organization_id,
                        GuardPermissionEvent.resource_id == resource.id,
                        GuardPermissionEvent.subject_id == subject_id,
                        GuardPermissionEvent.change_type == "grant_revoke",
                        GuardPermissionEvent.processing_status.in_(["queued", "processing"]),
                        GuardPermissionEvent.mutation_json.contains(marker),
                    ))
                    if pending is None and _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_revoke", revision=revision, mutation={"grant_key": grant.grant_key, "scope": grant.scope, "snapshot_complete": True}, stable=f"{source.id}:reconcile:{resource.provider_resource_id}:{grant.grant_key}:{subject_id}:{revision}:revoke"):
                        queued += 1
        return {"resources": len(resources), "events": queued}
    except Exception as exc:
        raise ACLSyncError(_provider_error_code(exc)) from exc
    finally:
        await adapter._client.aclose()
