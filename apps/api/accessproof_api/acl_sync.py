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

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.config import settings
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
from connectors.microsoft365.adapter import DeltaResyncRequired, Microsoft365Adapter
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
    """Return whether a Drive permission authorizes RAG source content, not metadata.

    Expired, deleted, broad-link, and non-reader roles must remove any older
    allow path.  Treat malformed expiry metadata as non-authorizing: keeping a
    stale ALLOW is less safe than a temporary false denial while the provider
    data is corrected.
    """
    if permission.get("deleted") or str(permission.get("type") or "") in {"domain", "anyone"}:
        return False
    role = str(permission.get("role") or "")
    if role not in _GOOGLE_READ_ROLES:
        return False
    # Drive can report role=reader for a *metadata-only* view of a
    # limited-access folder. That is not permission to read folder children
    # or their contents. Published views are likewise not source-content
    # access. Any non-null/unknown view is deliberately non-authorizing.
    if permission.get("view") is not None:
        return False
    limited = permission.get("inheritedPermissionsDisabled")
    if limited is not None and not isinstance(limited, bool):
        return False
    if limited and role not in {"owner", "organizer"}:
        details = permission.get("permissionDetails")
        if details is not None:
            if (not isinstance(details, list) or any(
                not isinstance(detail, dict) or not isinstance(detail.get("inherited"), bool)
                for detail in details
            )):
                return False
            # A permission inherited solely from a limited folder's parent
            # does not grant content access. Directly re-added permissions
            # include an inherited=false detail on shared drives. My Drive
            # may omit permissionDetails; there, Drive's view field is the
            # documented discriminator between metadata-only and full access.
            if details and all(detail["inherited"] for detail in details):
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


_MICROSOFT_READ_ROLES = {"read", "write", "owner"}


def _microsoft_permission_authorizes_read(permission: dict[str, Any], now: datetime) -> bool:
    """Accept only an unexpired, explicit Microsoft Graph read grant.

    A link is not equivalent to a named employee's effective permission;
    SharePoint inheritance/link semantics need separate provider validation.
    Unknown permissions must not silently become ALLOW.
    """
    if permission.get("deleted") or permission.get("link") is not None:
        return False
    roles = permission.get("roles")
    if not isinstance(roles, list) or not roles or not all(
        isinstance(role, str) and role in _MICROSOFT_READ_ROLES for role in roles
    ):
        return False
    if _principal(permission, "microsoft365")[0] == "unsupported":
        return False
    expiry = permission.get("expirationDateTime")
    if expiry is None:
        return True
    if not isinstance(expiry, str):
        return False
    try:
        expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except ValueError:
        return False
    return expires_at.tzinfo is not None and expires_at > now


def _permission_authorizes_read(permission: dict[str, Any], provider: str, now: datetime) -> bool:
    if provider == "google-drive":
        return _google_permission_authorizes_read(permission, now)
    if provider == "microsoft365":
        return _microsoft_permission_authorizes_read(permission, now)
    return False


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
    if provider != "microsoft365" or permission.get("link") is not None:
        return "unsupported", "", None
    granted = permission.get("grantedToV2") or permission.get("grantedTo") or {}
    if not isinstance(granted, dict):
        return "unsupported", "", None
    identities = permission.get("grantedToIdentitiesV2")
    if not granted:
        if not isinstance(identities, list) or len(identities) != 1 or not isinstance(identities[0], dict):
            return "unsupported", "", None
        granted = identities[0]
    # Prefer tenant-wide Entra identities; siteUser.id is a SharePoint-local
    # site-user key and MUST NOT be mistaken for the Entra directory object ID.
    group = granted.get("group")
    user = granted.get("user")
    if isinstance(group, dict) and not user:
        identifier = group.get("id")
        if isinstance(identifier, str) and identifier:
            return "group", identifier, group.get("email")
    if isinstance(user, dict) and not group:
        identifier = user.get("id")
        if isinstance(identifier, str) and identifier:
            return "subject", identifier, user.get("email")
    # Site-only, email-only, ambiguous, or sharing-link principals are
    # unsupported until resolved against an authoritative directory.
    return "unsupported", "", None


def _grant_key(provider: str, resource_id: str, permission: dict[str, Any]) -> str:
    """Bind a provider permission ID to its *actual* immutable grant identity.

    Provider IDs can be reassigned to a different principal or permission
    scope. Reusing an old grant key in that case silently preserves access.
    Including the source resource and a compact canonical fingerprint makes
    the obsolete grant separately revocable by ordinary snapshot diffs.
    """
    principal_type, principal_id, _ = _principal(permission, provider)
    identity = {
        "ptype": principal_type,
        "principal": principal_id,
        "role": permission.get("role") if provider == "google-drive" else permission.get("roles"),
        "expires": permission.get("expirationTime") if provider == "google-drive" else permission.get("expirationDateTime"),
        "inherited": permission.get("inheritedFrom"),
        "access_path": permission.get("accessPath"),
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()[:24]
    # Resource IDs can be long; store a deterministic bounded key while
    # preventing collisions between files with equal permission IDs.
    prefix = hashlib.sha256(f"{provider}\0{resource_id}\0{permission['id']}".encode()).hexdigest()[:24]
    return f"{provider}:{prefix}:{digest}"


def _subjects_for_principal(
    db: Session, source: SourceConnection, provider: str, ptype: str, pid: str,
    email: str | None, *, trusted_grant_id: bool = False,
) -> list[tuple[str, str | None]]:
    if ptype == "unsupported":
        return []
    if ptype == "subject":
        # Provider ACL identifiers are not database primary keys. Only a
        # previously persisted grant may refer to an internal principal ID.
        # Otherwise an externally supplied GUID matching a database row could
        # be interpreted as an unrelated authorized subject.
        if trusted_grant_id:
            direct = db.get(GuardSubject, pid)
            if (direct is not None and direct.organization_id == source.organization_id
                    and direct.provider == provider):
                return [(direct.id, None)]
            return []
        candidates = list(db.scalars(select(GuardSubject).where(
            GuardSubject.organization_id == source.organization_id,
            GuardSubject.provider == provider,
        )))
        email_l = (email or "").lower()
        # Drive permission IDs and Workspace Directory subject IDs are
        # separate opaque namespaces. Email may be recycled/renamed, so a
        # production V1 never uses a mutable email as authorization proof.
        # Development retains historical synthetic fixture compatibility;
        # the release requires a provider-verified Drive permission-ID map.
        allow_legacy_email_match = provider == "google-drive" and settings.env != "production"
        return [(row.id, None) for row in candidates if (row.status == "active" or settings.env != "production") and (
            (provider == "google-drive" and settings.env == "production"
             and row.drive_permission_id is not None and row.drive_permission_id == pid)
            or (not (provider == "google-drive" and settings.env == "production") and (
                row.provider_subject_id == pid or (
                    allow_legacy_email_match and email_l and (row.primary_email or "").lower() == email_l
                )
            ))
        )]
    if ptype == "group":
        group = db.get(GuardGroup, pid) if trusted_grant_id else None
        if group is None and not trusted_grant_id:
            # In V1 production, pid is the Google Drive ACL permissionId,
            # NOT a Workspace Directory group ID. Only a verified match to
            # the independently resolved Drive ID can authorize members.
            key_field = (GuardGroup.drive_permission_id if
                         provider == "google-drive" and settings.env == "production"
                         else GuardGroup.provider_group_id)
            group = db.scalar(select(GuardGroup).where(
                GuardGroup.organization_id == source.organization_id,
                GuardGroup.provider == provider,
                key_field == pid,
            ))
        if (group is None and email and provider == "google-drive"
                and not trusted_grant_id and settings.env != "production"):
            group = db.scalar(select(GuardGroup).where(
                GuardGroup.organization_id == source.organization_id,
                GuardGroup.provider == provider,
                GuardGroup.provider_email == email,
            ))
        if (group is None or group.status != "active"
                or group.organization_id != source.organization_id
                or group.provider != provider):
            return []
        return [(membership.subject_id, group.id) for membership in db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == source.organization_id,
            GuardGroupMembership.group_id == group.id,
            GuardGroupMembership.active.is_(True),
        )) if (subject := db.get(GuardSubject, membership.subject_id)) is not None and subject.status == "active"]
    if ptype != "organization" or not trusted_grant_id:
        return []
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
    production_drive = provider == "google-drive" and settings.env == "production"
    group = db.scalar(select(GuardGroup).where(
        GuardGroup.organization_id == source.organization_id,
        GuardGroup.provider == provider,
        (GuardGroup.drive_permission_id if production_drive else GuardGroup.provider_group_id) == provider_group_id,
    ))
    if group is None and email and provider == "google-drive" and settings.env != "production":
        group = db.scalar(select(GuardGroup).where(
            GuardGroup.organization_id == source.organization_id,
            GuardGroup.provider == provider,
            GuardGroup.provider_email == email,
        ))
    if group is None:
        group = GuardGroup(
            organization_id=source.organization_id,
            provider=provider,
            provider_group_id=(f"drive-unresolved:{provider_group_id}" if production_drive else provider_group_id),
            drive_permission_id=provider_group_id if production_drive else None,
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
        metadata.update({key: item.get(key) for key in ("name", "mimeType", "parents", "parentReference", "webUrl", "driveId", "eTag", "cTag") if item.get(key) is not None})
        metadata["deleted"] = False
        if "folder" in item or item.get("mimeType") == "application/vnd.google-apps.folder":
            row.resource_type = "folder"
        elif "file" in item or "mimeType" in item:
            row.resource_type = "document"
        # Sparse provider delta notifications often omit file/folder facets:
        # retain the authoritative previous type and child hierarchy.
        parents = item.get("parents") or []
        graph_parent = item.get("parentReference")
        parent_id = (str(parents[0]) if parents else
                     str(graph_parent.get("id")) if isinstance(graph_parent, dict) and graph_parent.get("id")
                     else None)
        if parent_id:
            parent = db.scalar(select(GuardResource).where(
                GuardResource.organization_id == source.organization_id,
                GuardResource.source_id == source.id,
                GuardResource.provider_resource_id == parent_id,
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
            # D-27: a descendant already recorded as deleted has no provider
            # item left to re-read (Graph 404s); its grants were revoked when
            # the deletion was processed. Re-reading it failed every later sync.
            if json.loads(row.metadata_json or "{}").get("deleted"):
                continue
            descendants.append(row)
            pending.append(row.id)
            if len(descendants) > limit:
                raise ACLSyncError("DRIVE_DESCENDANT_RECONCILIATION_LIMIT")
    return descendants


def _event(db: Session, *, source: SourceConnection, provider: str, resource: GuardResource, subject_id: str, change_type: str, revision: int, mutation: dict[str, Any], stable: str) -> bool:
    dedupe = hashlib.sha256(stable.encode()).hexdigest()[:120]
    # D-32: the session runs with autoflush=False, so an event queued earlier in
    # THIS sync is invisible to the query below unless flushed first. A new
    # organization's first full snapshot can produce the same event twice.
    db.flush()
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
        grant_key = _grant_key(provider, resource.provider_resource_id, permission)
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
        if token is None:
            # Capture changes before enumeration: otherwise a revoke between
            # folder inventory and final checkpoint would be missed.
            try:
                # The caller may persist a degraded cursor after an exception.
                # A nested transaction ensures partial resources, grants and
                # events from an incomplete inventory are rolled back first.
                with db.begin_nested():
                    checkpoint = await adapter.acl_latest_delta_link()
                    boundary = str(credentials["test_root_item_id"])
                    root = _resource(db, source, boundary, {
                        "id": boundary, "folder": {}, "name": "configured Microsoft boundary",
                    }, _now())
                    ms_resources = [root]
                    for item in await adapter.list_boundary_resources():
                        ms_resources.append(_resource(db, source, str(item["id"]), item, _now()))
                    # A *complete* snapshot is required before the ACL cursor is
                    # marked fresh; partial inventory cannot authorize.
                    count = 0
                    for resource in ms_resources:
                        permissions = await adapter.permissions_snapshot(resource.provider_resource_id)
                        count += _queue_snapshot(
                            db, source, provider, resource, permissions, 1,
                            f"{source.id}:seed:{resource.provider_resource_id}",
                        )
                cursor.cursor = checkpoint
                cursor.last_provider_revision = "1"
                cursor.status = "connected"
                cursor.last_success_at = _now()
                return {"pages": 0, "changes": len(ms_resources), "events": count}
            except Exception as exc:
                cursor.status, cursor.last_error_at = "degraded", _now()
                cursor.last_error_code = _provider_error_code(exc)
                raise ACLSyncError(cursor.last_error_code) from exc
            finally:
                await adapter._client.aclose()
    else:
        raise ACLSyncError("ACL_SYNC_UNSUPPORTED")
    pages = changes = events = 0
    # D-31: authorization-relevant grant mutations that are not events.
    grant_mutations = 0
    has_more_pages = False
    try:
        base_revision = int(cursor.last_provider_revision or "0")
    except ValueError:
        base_revision = 0
    try:
        while pages < max_pages and (pages == 0 or token):
            try:
                page = await (adapter.acl_change_page(token) if provider == "google-drive" else adapter.acl_delta_page(token))
            except DeltaResyncRequired:
                # D-24: an expired/incompatible delta token used to leave the
                # cursor degraded forever. Re-read the whole approved subtree as
                # one change set at the next revision: every permission set is
                # re-snapshotted and grants on vanished items are revoked.
                page = await adapter.resync_delta_page()
                listed = {str(item.get("id")) for item in page["value"] if isinstance(item, dict)}
                for known in db.scalars(select(GuardResource).where(
                    GuardResource.organization_id == source.organization_id,
                    GuardResource.source_id == source.id,
                )):
                    if known.provider_resource_id not in listed:
                        page["value"].append({"id": known.provider_resource_id, "removed": True})
            pages += 1
            # ``last_provider_revision`` is the high-water mark of the
            # *emitted* normalized events.  The initial inventory is version
            # 1, so the first delta must be version 2.  Previously we emitted
            # ``base + pages + 1`` but persisted ``base + pages`` below.  A
            # following reconciliation then reused the event's revision;
            # revoke-wins-on-ties correctly rejected the fresh re-grant as a
            # stale replay.  Keep the cursor and every emitted revision in
            # one monotonic domain.
            revision = base_revision + pages
            if provider == "microsoft365":
                if (not isinstance(page, dict) or not isinstance(page.get("value"), list)
                        or not (page.get("@odata.nextLink") or page.get("@odata.deltaLink"))):
                    raise ACLSyncError("MICROSOFT_DELTA_INCOMPLETE")
            entries = page.get("changes", []) if provider == "google-drive" else page.get("value", [])
            if provider == "microsoft365":
                # A folder permission change can affect all descendants even
                # without a separate Graph delta for each child.
                expanded_microsoft = list(entries)
                present_microsoft = {str(e.get("id") or "") for e in entries if isinstance(e, dict)}
                for change in list(entries):
                    if not isinstance(change, dict):
                        raise ACLSyncError("ACL_SYNC_INCOMPLETE")
                    parent_id = str(change.get("id") or "")
                    # A whole folder can move INTO the protected root. Its
                    # descendants need not each have a delta record, so scan
                    # that subtree before declaring the ACL sweep complete.
                    if (parent_id and isinstance(change.get("folder"), dict)
                            and not (change.get("@removed") or change.get("deleted") or change.get("removed"))
                            and await adapter.is_inside_boundary(parent_id)):
                        for new_child in await adapter.list_boundary_resources(root_id=parent_id):
                            child_id = str(new_child["id"])
                            if child_id not in present_microsoft:
                                expanded_microsoft.append(new_child)
                                present_microsoft.add(child_id)
                    ancestor = db.scalar(select(GuardResource).where(
                        GuardResource.organization_id == source.organization_id,
                        GuardResource.source_id == source.id,
                        GuardResource.provider_resource_id == parent_id,
                        GuardResource.resource_type == "folder",
                    ))
                    if ancestor is None:
                        continue
                    for child in _known_descendants(db, source, ancestor):
                        if child.provider_resource_id not in present_microsoft:
                            expanded_microsoft.append({
                                "id": child.provider_resource_id,
                                "removed": bool(change.get("deleted") or change.get("removed") or change.get("@removed")),
                            })
                            present_microsoft.add(child.provider_resource_id)
                entries = expanded_microsoft
            if provider == "google-drive":
                # Shared-drive membership/role events may have no fileId.
                # Re-check the existing source graph rather than treating a
                # legitimate provider page as malformed or silently retaining
                # previously authorized documents. Permission failures keep
                # the whole cursor degraded (fail closed). The bounded sweep
                # avoids claiming partial evidence for large sources.
                drive_events = [change for change in entries
                                if (change.get("changeType") or change.get("type")) == "drive"]
                if drive_events:
                    known = list(db.scalars(select(GuardResource).where(
                        GuardResource.organization_id == source.organization_id,
                        GuardResource.source_id == source.id,
                    ).limit(20_001)))
                    if len(known) > 20_000:
                        raise ACLSyncError("DRIVE_MEMBERSHIP_RESCAN_LIMIT")
                    affected_drives = {str(change["driveId"]) for change in drive_events}
                    known_drives = {str(json.loads(resource.metadata_json or "{}").get("driveId"))
                                    for resource in known}
                    # Older indexed resources lack driveId metadata: scan them
                    # conservatively rather than assuming they are unrelated.
                    for resource in known:
                        metadata = json.loads(resource.metadata_json or "{}")
                        drive_id = metadata.get("driveId")
                        if (drive_id is None or str(drive_id) in affected_drives
                                or not (known_drives & affected_drives)):
                            entries.append({"changeType": "file", "fileId": resource.provider_resource_id})
                    entries = [change for change in entries if (change.get("changeType") or change.get("type")) != "drive"]
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
                prefetched_permissions: list[dict[str, Any]] | None = None
                removed = bool(change.get("removed") or change.get("deleted") or (
                    provider == "microsoft365" and change.get("@removed")
                ))
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
                elif provider == "microsoft365":
                    existing_resource = db.scalar(select(GuardResource).where(
                        GuardResource.organization_id == source.organization_id,
                        GuardResource.source_id == source.id,
                        GuardResource.provider_resource_id == file_id,
                    ))
                    if "remoteItem" in change:
                        if existing_resource is None:
                            continue
                        removed = True
                    if removed and existing_resource is None:
                        continue
                    if not removed:
                        try:
                            in_boundary = await adapter.is_inside_boundary(file_id)
                            if in_boundary:
                                prefetched_permissions = await adapter.permissions_snapshot(file_id)
                        except httpx.HTTPStatusError as exc:
                            # D-27: Graph itemNotFound means the item is gone (deleted
                            # or no longer visible to the source): revoke, do not fail
                            # the whole sync. Any other provider error still fails closed.
                            if exc.response is None or exc.response.status_code != 404:
                                raise
                            if existing_resource is None:
                                continue
                            in_boundary, removed = True, True
                        if not in_boundary and existing_resource is None:
                            continue
                        if not in_boundary:
                            removed = True  # Existing item moved beyond approved root.
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
                        subject_ids = [grant.principal_id] if grant.principal_type == "subject" else [s for s, _ in _subjects_for_principal(db, source, provider, "group" if grant.principal_type == "group" else "organization", grant.principal_id, None, trusted_grant_id=True)]
                        if not subject_ids and grant.principal_type == "group":
                            # No effective user policy exists to recompute, but
                            # retain no dormant allow path after the provider
                            # has removed the group's permission.
                            grant.active = False
                            grant_mutations += 1
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
                            if _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_revoke", revision=revision, mutation={"grant_key": grant.grant_key, "scope": grant.scope, "snapshot_complete": True}, stable=f"{source.id}:{file_id}:{grant.grant_key}:{subject_id}:{revision}:revoke"):
                                events += 1
                    continue
                permissions = (prefetched_permissions if prefetched_permissions is not None
                               else await adapter.permissions_snapshot(file_id))
                current_keys: set[str] = set()
                for permission in permissions:
                    if not _permission_authorizes_read(permission, provider, _now()):
                        continue
                    permission_id = str(permission.get("id") or "")
                    if not permission_id:
                        continue
                    grant_key = _grant_key(provider, resource.provider_resource_id, permission)
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
                    grant_mutations += int(group_changed)
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
                            trusted_grant_id=True,
                        )]
                        if not subject_ids and grant.principal_type == "group":
                            grant.active = False
                            grant_mutations += 1
                            grant.provider_revision = max(grant.provider_revision, revision)
                            grant.observed_at = _now()
                        for subject_id in subject_ids:
                            if _event(db, source=source, provider=provider, resource=resource, subject_id=subject_id, change_type="grant_revoke", revision=revision, mutation={"grant_key": grant.grant_key, "scope": grant.scope, "snapshot_complete": True}, stable=f"{source.id}:{file_id}:{grant.grant_key}:{subject_id}:{revision}:revoke"):
                                events += 1
            next_token = page.get("nextPageToken") or page.get("@odata.nextLink")
            has_more_pages = bool(next_token)
            if next_token:
                token = str(next_token)
                cursor.cursor = token
                continue
            token = page.get("newStartPageToken") or page.get("@odata.deltaLink") or token
            cursor.cursor = str(token)
            break
        if has_more_pages and pages >= max_pages:
            # Keep the durable continuation token, but do not report a stale
            # partial ACL sweep as fresh enough for Protect mode.
            cursor.status = "catching_up"
            cursor.last_error_at = _now()
            cursor.last_error_code = "ACL_SYNC_BACKLOG"
            raise ACLSyncError("ACL_SYNC_BACKLOG")
        if provider == "microsoft365":
            # Cached-chunk freshness: resources synced before versions were
            # recorded get their current eTag/cTag from one bounded inventory
            # read (metadata only; ACLs are untouched here).
            from apps.api.accessproof_api.content_versions import needs_backfill
            if needs_backfill(db, source):
                for item in await adapter.list_boundary_resources():
                    _resource(db, source, str(item["id"]), item, _now())
                db.flush()
        cursor.status, cursor.last_success_at = "connected", _now()
        # D-31: this value feeds the signed authorization revision. Advancing it
        # on every no-op sync issued a new revision every few minutes and made
        # Layer 2 block in-flight answers with no authorization change. Persist
        # the high-water mark only when this sync emitted events or changed a
        # grant; unused revision numbers are never persisted, so emitted event
        # revisions stay monotonic.
        if events or grant_mutations:
            cursor.last_provider_revision = str(base_revision + pages)
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
    ).order_by(GuardResource.last_reconciled_at.asc().nullsfirst(), GuardResource.id.asc())
      .limit(max(1, min(limit, 500))).with_for_update(skip_locked=True)))
    queued = 0
    # Reconciliation and incremental change ingestion write the SAME grant
    # revision domain. A wall-clock timestamp here is not comparable with
    # the per-source revision used by synchronize_acls: after an auth grant is
    # discovered by reconciliation it could become effectively irrevocable.
    cursor = db.scalar(select(ProviderSyncCursor).where(
        ProviderSyncCursor.organization_id == source.organization_id,
        ProviderSyncCursor.source_id == source.id,
        ProviderSyncCursor.sync_kind == "acl",
    ).with_for_update())
    if cursor is None or cursor.last_success_at is None:
        raise ACLSyncError("ACL_SYNC_REQUIRED")
    try:
        revision = int(cursor.last_provider_revision or "0") + 1
    except ValueError as exc:
        raise ACLSyncError("INVALID_ACL_REVISION") from exc
    try:
        for resource in resources:
            # Advance even deleted resources so they cannot monopolize each
            # bounded batch; the change-feed sync clock is never overwritten.
            resource.last_reconciled_at = _now()
            metadata = json.loads(resource.metadata_json or "{}")
            if metadata.get("deleted"):
                continue
            # A file moved OUT of an approved folder can retain legitimate
            # permissions in Graph. Reconciliation cannot treat those as an
            # AccessProof grant: the resource is no longer in this source.
            if not await adapter.is_inside_boundary(resource.provider_resource_id):
                resource.metadata_json = json.dumps({**metadata, "deleted": True}, sort_keys=True)
                for grant in db.scalars(select(GuardPermissionGrant).where(
                    GuardPermissionGrant.organization_id == source.organization_id,
                    GuardPermissionGrant.source_id == source.id,
                    GuardPermissionGrant.resource_id == resource.id,
                    GuardPermissionGrant.active.is_(True),
                )):
                    subjects = ([grant.principal_id] if grant.principal_type == "subject" else
                                [sid for sid, _ in _subjects_for_principal(
                                    db, source, provider, grant.principal_type,
                                    grant.principal_id, None, trusted_grant_id=True,
                                )])
                    if not subjects:
                        grant.active = False
                        grant.provider_revision = max(grant.provider_revision, revision)
                        grant.observed_at = _now()
                    for subject_id in subjects:
                        if _event(
                            db, source=source, provider=provider, resource=resource,
                            subject_id=subject_id, change_type="grant_revoke", revision=revision,
                            mutation={"grant_key": grant.grant_key, "scope": grant.scope,
                                      "snapshot_complete": True},
                            stable=(f"{source.id}:reconcile:moved-out:{resource.provider_resource_id}:"
                                    f"{grant.grant_key}:{subject_id}:{revision}:revoke"),
                        ):
                            queued += 1
                continue
            permissions = await adapter.permissions_snapshot(resource.provider_resource_id)
            current_keys = {
                _grant_key(provider, resource.provider_resource_id, permission)
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
                subject_ids = [grant.principal_id] if grant.principal_type == "subject" else [subject_id for subject_id, _ in _subjects_for_principal(db, source, provider, grant.principal_type, grant.principal_id, None, trusted_grant_id=True)]
                if not subject_ids:
                    # Revoked groups without active members must not retain
                    # dormant grants which could revive after an employee join.
                    grant.active = False
                    grant.provider_revision = max(grant.provider_revision, revision)
                    grant.observed_at = _now()
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
        # This is a monotonic grant revision, not a Drive change token.
        # Advancing the same persisted sequence guarantees the next delta
        # has a larger revision and can revoke these reconciled grants.
        if queued:  # D-31: only an actual reconciled change advances the revision
            cursor.last_provider_revision = str(revision)
        return {"resources": len(resources), "events": queued}
    except Exception as exc:
        raise ACLSyncError(_provider_error_code(exc)) from exc
    finally:
        await adapter._client.aclose()
