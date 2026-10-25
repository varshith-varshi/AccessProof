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
    if isinstance(exc, ACLSyncError):
        return exc.code
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


_GOOGLE_READ_ROLES = {"owner", "organizer", "fileOrganizer", "writer", "commenter", "reader"}
_GOOGLE_SHORTCUT_MIME = "application/vnd.google-apps.shortcut"


def _google_permission_authorizes_read(permission: dict[str, Any], now: datetime) -> bool:
    """Return whether a Drive permission is currently a usable read grant.

    Expired, deleted, broad-link, and non-reader roles must remove any older
    allow path.  Treat malformed expiry metadata as non-authorizing: keeping a
    stale ALLOW is less safe than a temporary false denial while the provider
    data is corrected.
    """
    if permission.get("deleted") or str(permission.get("type") or "") in {"domain", "anyone"}:
        return False
    if str(permission.get("role") or "") not in _GOOGLE_READ_ROLES:
        return False
    expiry = permission.get("expirationTime")
    if expiry is None:
        return True
    if not isinstance(expiry, str):
        return False
    try:
        expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except ValueError:
        return False
    if expires_at.tzinfo is None:
        return False
    return expires_at > now


def _permission_authorizes_read(permission: dict[str, Any], provider: str, now: datetime) -> bool:
    return _google_permission_authorizes_read(permission, now) if provider == "google-drive" else True


def _principal(permission: dict[str, Any], provider: str) -> tuple[str, str, str | None]:
    """Return principal type, provider identifier, and optional email."""
    if provider == "google-drive":
        ptype = str(permission.get("type") or "user")
        if ptype == "group":
            return "group", str(permission.get("emailAddress") or permission.get("id") or ""), permission.get("emailAddress")
        if ptype in {"domain", "anyone"}:
            # Broad and link grants are not equivalent to all employees in this
            # AccessProof tenant. Fail closed until Google effective-access and
            # link possession are correctly modeled and provider-validated.
            return "unsupported", str(permission.get("domain") or ptype), None
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
    if ptype == "unsupported":
        return []
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


def _group_for_principal(
    db: Session, source: SourceConnection, provider: str, provider_group_id: str, email: str | None,
) -> GuardGroup:
    """Find or create the durable group principal behind a Drive ACL.

    An empty Google Group is still an authorization principal.  Persisting its
    grant before a member exists lets a later directory membership sync create
    the correct effective access instead of silently dropping the ACL.
    """
    group = db.scalar(select(GuardGroup).where(
        GuardGroup.organization_id == source.organization_id,
        GuardGroup.provider == provider,
        GuardGroup.provider_group_id == provider_group_id,
    ))
    if group is None and email:
        group = db.scalar(select(GuardGroup).where(
            GuardGroup.organization_id == source.organization_id,
            GuardGroup.provider == provider,
            GuardGroup.provider_email == email,
        ))
    if group is None:
        group = GuardGroup(
            organization_id=source.organization_id,
            provider=provider,
            provider_group_id=provider_group_id,
            provider_email=email,
            status="unknown",
        )
        db.add(group)
        db.flush()
    elif email and not group.provider_email:
        group.provider_email = email
    return group


def _ensure_group_grant(
    db: Session, *, source: SourceConnection, provider: str, resource: GuardResource,
    grant_key: str, provider_group_id: str, email: str | None, revision: int,
) -> tuple[GuardGroup, bool]:
    """Persist a group ACL even when it has no active members.

    Events remain responsible for recalculating each member's effective policy;
    this durable grant is what allows a future membership event to find the
    group's existing authorization path.
    """
    group = _group_for_principal(db, source, provider, provider_group_id, email)
    grant = db.scalar(select(GuardPermissionGrant).where(
        GuardPermissionGrant.organization_id == source.organization_id,
        GuardPermissionGrant.source_id == source.id,
        GuardPermissionGrant.grant_key == grant_key,
    ).with_for_update())
    changed = grant is None or not grant.active or grant.resource_id != resource.id or grant.principal_id != group.id
    if grant is None:
        db.add(GuardPermissionGrant(
            organization_id=source.organization_id, source_id=source.id,
            resource_id=resource.id, grant_key=grant_key,
            principal_type="group", principal_id=group.id, effect="allow",
            scope="read", active=True, provider_revision=revision, observed_at=_now(),
        ))
    else:
        grant.resource_id = resource.id
        grant.principal_type = "group"
        grant.principal_id = group.id
        grant.effect = "allow"
        grant.scope = "read"
        grant.active = True
        grant.provider_revision = max(grant.provider_revision, revision)
        grant.observed_at = _now()
    db.flush()
    return group, changed


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
        metadata.update({key: item.get(key) for key in ("name", "mimeType", "parents", "parentReference", "webUrl") if item.get(key) is not None})
        metadata["deleted"] = False
        row.resource_type = "folder" if item.get("folder") or item.get("mimeType") == "application/vnd.google-apps.folder" else "document"
        parents = item.get("parents") or []
        if parents:
            parent = db.scalar(select(GuardResource).where(
                GuardResource.organization_id == source.organization_id,
                GuardResource.source_id == source.id,
                GuardResource.provider_resource_id == str(parents[0]),
            ))
            row.parent_resource_id = parent.id if parent else None
    row.metadata_json = json.dumps(metadata, sort_keys=True)
    row.last_synced_at = now
    db.flush()
    return row


def _known_descendants(db: Session, source: SourceConnection, ancestor: GuardResource, *, limit: int = 20000) -> list[GuardResource]:
    """Known descendants need ACL re-evaluation when a parent changes.

    Drive change feeds do not guarantee a separate notification for every
    child whose inherited access changed.
    """
    seen = {ancestor.id}
    pending = [ancestor.id]
    descendants: list[GuardResource] = []
    while pending:
        rows = list(db.scalars(select(GuardResource).where(
            GuardResource.organization_id == source.organization_id,
            GuardResource.source_id == source.id,
            GuardResource.parent_resource_id.in_(pending),
        )))
        pending = []
        for row in rows:
            if row.id in seen:
                continue
            seen.add(row.id)
            descendants.append(row)
            pending.append(row.id)
            if len(descendants) > limit:
                raise ACLSyncError("DRIVE_DESCENDANT_RECONCILIATION_LIMIT")
    return descendants


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
    observed_at = _now()
    for permission in permissions:
        if not _permission_authorizes_read(permission, provider, observed_at):
            continue
        permission_id = str(permission.get("id") or "")
        if not permission_id:
            continue
        grant_key = f"{provider}:{resource.provider_resource_id}:{permission_id}"
        ptype, pid, email = _principal(permission, provider)
        if ptype == "unsupported":
            continue
        group_changed = False
        if ptype == "group":
            _, group_changed = _ensure_group_grant(
                db, source=source, provider=provider, resource=resource,
                grant_key=grant_key, provider_group_id=pid, email=email, revision=revision,
            )
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
            # A new/reactivated group grant needs one event for every current
            # member, even though the durable group row was inserted above.
            if (existing is not None and not group_changed) or pending is not None:
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
            # Capture change cursor BEFORE inventory so changes during the
            # scan are subsequently replayed. Do not mark connected or commit
            # any partial progress when listing/permissions fail.
            try:
                page = await adapter.acl_change_page(None)
                start_token = page.get("startPageToken")
                if not isinstance(start_token, str) or not start_token:
                    raise ACLSyncError("DRIVE_START_CURSOR_MISSING")
                boundary = str(credentials["test_root_folder_id"])
                resources = [{"id": boundary, "name": "configured test boundary",
                              "mimeType": "application/vnd.google-apps.folder"}]
                resources.extend(await adapter.list_boundary_resources())
                seed_events = 0
                for item in resources:
                    resource = _resource(db, source, str(item["id"]), item, _now())
                    permissions = await adapter.permissions_snapshot(resource.provider_resource_id)
                    seed_events += _queue_snapshot(
                        db, source, provider, resource, permissions, 1,
                        f"{source.id}:seed:{resource.provider_resource_id}"
                    )
                cursor.cursor = start_token
                cursor.last_provider_revision = "1"
                cursor.status = "connected"
                cursor.last_success_at = _now()
                return {"pages": 0, "changes": len(resources), "events": seed_events}
            except Exception as exc:
                cursor.status, cursor.last_error_at = "degraded", _now()
                cursor.last_error_code = _provider_error_code(exc)
                raise ACLSyncError(cursor.last_error_code) from exc
            finally:
                await adapter._client.aclose()
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
            if provider == "google-drive":
                # Refresh known descendants on folder ACL/move/delete events.
                # Also discover nested files when a new folder is moved into
                # the protected root; don't depend on individual child deltas.
                expanded = list(entries)
                present_ids = {str(c.get("fileId") or "") for c in expanded}
                for changed in list(entries):
                    changed_id = str(changed.get("fileId") or "")
                    if not changed_id:
                        continue
                    folder_row = db.scalar(select(GuardResource).where(
                        GuardResource.organization_id == source.organization_id,
                        GuardResource.source_id == source.id,
                        GuardResource.provider_resource_id == changed_id,
                        GuardResource.resource_type == "folder",
                    ))
                    if folder_row:
                        for child in _known_descendants(db, source, folder_row):
                            if child.provider_resource_id not in present_ids:
                                expanded.append({
                                    "fileId": child.provider_resource_id,
                                    "removed": bool(changed.get("removed")),
                                })
                                present_ids.add(child.provider_resource_id)
                    elif (not changed.get("removed") and
                          (changed.get("file") or {}).get("mimeType") == "application/vnd.google-apps.folder" and
                          await adapter.is_inside_boundary(changed_id)):
                        for child in await adapter.list_boundary_resources(root_id=changed_id):
                            cid = str(child["id"])
                            if cid not in present_ids:
                                expanded.append({"fileId": cid, "file": child})
                                present_ids.add(cid)
                entries = expanded
            for change in entries:
                file_id = str(change.get("fileId") or change.get("id") or "")
                if not file_id:
                    continue
                changes += 1
                removed = bool(change.get("removed") or change.get("deleted"))
                if provider == "google-drive":
                    changed_file = change.get("file") if isinstance(change.get("file"), dict) else {}
                    existing_resource = db.scalar(select(GuardResource).where(
                        GuardResource.organization_id == source.organization_id,
                        GuardResource.source_id == source.id,
                        GuardResource.provider_resource_id == file_id,
                    ))
                    # Shortcuts can point to content outside the approved
                    # boundary. Ignore new ones and revoke any historical
                    # shortcut state from a pre-V1 policy graph.
                    if changed_file.get("mimeType") == _GOOGLE_SHORTCUT_MIME:
                        if existing_resource is None:
                            continue
                        removed = True
                    # The Drive changes feed is user-scoped, not root-scoped.
                    # Ignore new objects outside this customer's boundary;
                    # previously known objects moved outside must be revoked.
                    if not removed:
                        in_boundary = await adapter.is_inside_boundary(file_id)
                        if not in_boundary and existing_resource is None:
                            continue
                        if not in_boundary:
                            removed = True
                    elif existing_resource is None:
                        continue
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
                        if not subject_ids and grant.principal_type == "group":
                            # No effective user policy exists to recompute, but
                            # retain no dormant allow path after the provider
                            # has removed the group's permission.
                            grant.active = False
                            grant.provider_revision = max(grant.provider_revision, revision)
                            grant.observed_at = _now()
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
                    if not _permission_authorizes_read(permission, provider, _now()):
                        continue
                    permission_id = str(permission.get("id") or "")
                    if not permission_id:
                        continue
                    grant_key = f"{provider}:{resource.provider_resource_id}:{permission_id}"
                    ptype, pid, email = _principal(permission, provider)
                    if ptype == "unsupported":
                        continue
                    current_keys.add(grant_key)
                    group_changed = False
                    if ptype == "group":
                        _, group_changed = _ensure_group_grant(
                            db, source=source, provider=provider, resource=resource,
                            grant_key=grant_key, provider_group_id=pid, email=email, revision=revision,
                        )
                    subjects = _subjects_for_principal(db, source, provider, ptype, pid, email)
                    for subject_id, group_id in subjects:
                        mutation = {"grant_key": grant_key, "principal_type": ptype, "principal_id": pid, "group_id": pid, "scope": "read", "grant_effect": "allow", "snapshot_complete": True}
                        existing = db.scalar(select(GuardPermissionGrant).where(
                            GuardPermissionGrant.organization_id == source.organization_id,
                            GuardPermissionGrant.source_id == source.id,
                            GuardPermissionGrant.grant_key == grant_key,
                            GuardPermissionGrant.active.is_(True),
                        ))
                        if (existing is None or group_changed) and _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_upsert", revision=revision, mutation=mutation, stable=f"{source.id}:{file_id}:{grant_key}:{subject_id}:{revision}:upsert"):
                            events += 1
                for grant in db.scalars(select(GuardPermissionGrant).where(
                    GuardPermissionGrant.organization_id == source.organization_id,
                    GuardPermissionGrant.source_id == source.id,
                    GuardPermissionGrant.resource_id == resource.id,
                    GuardPermissionGrant.active.is_(True),
                )):
                    if grant.grant_key not in current_keys:
                        subject_ids = [subject_id for subject_id, _ in _subjects_for_principal(
                            db, source, provider, grant.principal_type, grant.principal_id, None,
                        )]
                        if not subject_ids and grant.principal_type == "group":
                            grant.active = False
                            grant.provider_revision = max(grant.provider_revision, revision)
                            grant.observed_at = _now()
                        for subject_id in subject_ids:
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
        if token and pages >= max_pages:
            # Keep the durable continuation token, but do not report a stale
            # partial ACL sweep as fresh enough for Protect mode.
            cursor.status = "catching_up"
            cursor.last_error_at = _now()
            cursor.last_error_code = "ACL_SYNC_BACKLOG"
            raise ACLSyncError("ACL_SYNC_BACKLOG")
        cursor.status, cursor.last_success_at, cursor.last_provider_revision = "connected", _now(), str(base_revision + pages)
        return {"pages": pages, "changes": changes, "events": events}
    except Exception as exc:
        code = _provider_error_code(exc)
        # A durable continuation token remains available after a bounded
        # sweep. Keep that operational state distinguishable from a provider
        # failure so Guard can fail closed for staleness without reporting a
        # misleading connector outage.
        if code == "ACL_SYNC_BACKLOG":
            cursor.status = "catching_up"
        else:
            cursor.status = "degraded"
        cursor.last_error_at, cursor.last_error_code = _now(), code
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
            current_keys = {
                f"{provider}:{resource.provider_resource_id}:{str(permission.get('id'))}"
                for permission in permissions
                if permission.get("id")
                and _principal(permission, provider)[0] != "unsupported"
                and _permission_authorizes_read(permission, provider, _now())
            }
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
