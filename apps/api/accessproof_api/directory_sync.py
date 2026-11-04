"""Normalize provider directory data into the Guard identity graph."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.config import settings
from apps.api.accessproof_api.identity_resolution import is_guid, reconcile_microsoft_bindings
from apps.api.accessproof_api.db import (
    GuardEffectiveAccess,
    GuardGroup,
    GuardGroupMembership,
    GuardPermissionEvent,
    GuardPermissionGrant,
    GuardSubject,
    ProviderSyncCursor,
    SourceConnection,
)
from connectors.directory import (
    DirectorySyncError,
    GoogleWorkspaceDirectoryAdapter,
    MicrosoftEntraDirectoryAdapter,
)
from packages.connector_sdk.base import AuthenticationError, AuthorizationError, ProviderUnavailableError, RateLimitError


def _microsoft_tenant(credentials: dict[str, Any]) -> str | None:
    """The tenant these source credentials are bound to, or None."""
    value = str(credentials.get("tenant_id") or credentials.get("tenant_hint") or "").strip().lower()
    return value if is_guid(value) else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _provider(source: SourceConnection) -> str:
    return "microsoft365" if source.provider.lower() in {"microsoft365", "sharepoint", "onedrive"} else source.provider.lower()


def _directory_fingerprint(users: Any, groups: Any, members: dict[str, Any]) -> str:
    import hashlib
    import json as _json
    content = {
        "users": sorted([u.provider_id, u.status, getattr(u, "account_kind", ""), (u.email or "").lower()] for u in users),
        "groups": sorted([g.provider_id, (g.email or "").lower()] for g in groups),
        "members": sorted([gid, sorted(str(m) for m in ids)] for gid, ids in members.items()),
    }
    return "fp:" + hashlib.sha256(_json.dumps(content, separators=(",", ":")).encode()).hexdigest()[:48]


async def synchronize_directory(db: Session, source: SourceConnection, credentials: dict[str, Any]) -> dict[str, int]:
    """Synchronize complete provider directory state, preserving prior data on error."""
    provider = _provider(source)
    cursor = db.scalar(select(ProviderSyncCursor).where(
        ProviderSyncCursor.organization_id == source.organization_id,
        ProviderSyncCursor.source_id == source.id,
        ProviderSyncCursor.sync_kind == "directory",
    ))
    if cursor is None:
        cursor = ProviderSyncCursor(
            organization_id=source.organization_id,
            source_id=source.id,
            provider=provider,
            sync_kind="directory",
        )
        db.add(cursor)
    cursor.status, cursor.last_started_at, cursor.last_error_code = "syncing", _now(), None
    db.flush()
    token = str(credentials.get("access_token") or "")
    if not token:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "reauthorization_required", _now(), "REAUTHORIZATION_REQUIRED"
        raise DirectorySyncError("REAUTHORIZATION_REQUIRED")
    adapter: GoogleWorkspaceDirectoryAdapter | MicrosoftEntraDirectoryAdapter
    if provider == "google-drive":
        adapter = GoogleWorkspaceDirectoryAdapter(token)
    elif provider == "microsoft365":
        adapter = MicrosoftEntraDirectoryAdapter(token)
    else:
        raise DirectorySyncError("DIRECTORY_SYNC_UNSUPPORTED")
    verified_user_permission_ids: dict[str, str] = {}
    verified_group_permission_ids: dict[str, str] = {}
    try:
        users = await adapter.users()
        groups = await adapter.groups()
        members = {group.provider_id: await adapter.members(group.provider_id) for group in groups}
        if provider == "google-drive" and settings.env == "production":
            # The Admin Directory user/group ID is NOT a Google Drive ACL
            # permission ID. Resolve the latter with Google's authenticated
            # permissions.getIdForEmail endpoint, never by matching emails in
            # our own database. Cache immutable IDs while the email is stable.
            prior_users = {
                row.provider_subject_id: row for row in db.scalars(select(GuardSubject).where(
                    GuardSubject.organization_id == source.organization_id,
                    GuardSubject.provider == "google-drive",
                ))
            }
            prior_groups = {
                row.provider_group_id: row for row in db.scalars(select(GuardGroup).where(
                    GuardGroup.organization_id == source.organization_id,
                    GuardGroup.provider == "google-drive",
                ))
            }
            seen_user_ids: set[str] = set()
            seen_group_ids: set[str] = set()
            google_adapter = cast(GoogleWorkspaceDirectoryAdapter, adapter)
            for user in users:
                if user.status != "active":
                    continue
                if not isinstance(user.email, str) or not user.email:
                    raise DirectorySyncError("GOOGLE_DRIVE_USER_EMAIL_MISSING")
                prior_user = prior_users.get(user.provider_id)
                if (prior_user and prior_user.drive_permission_id and prior_user.primary_email
                        and prior_user.primary_email.casefold() == user.email.casefold()):
                    permission_id = prior_user.drive_permission_id
                else:
                    permission_id = await google_adapter.drive_permission_id(user.email)
                    if (prior_user and prior_user.drive_permission_id
                            and prior_user.drive_permission_id != permission_id):
                        raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_CHANGED")
                if permission_id in seen_user_ids:
                    raise DirectorySyncError("DUPLICATE_GOOGLE_DRIVE_PERMISSION_ID")
                seen_user_ids.add(permission_id)
                verified_user_permission_ids[user.provider_id] = permission_id
            for directory_group in groups:
                if not isinstance(directory_group.email, str) or not directory_group.email:
                    raise DirectorySyncError("GOOGLE_DRIVE_GROUP_EMAIL_MISSING")
                prior_group = prior_groups.get(directory_group.provider_id)
                if (prior_group and prior_group.drive_permission_id and prior_group.provider_email
                        and prior_group.provider_email.casefold() == directory_group.email.casefold()):
                    permission_id = prior_group.drive_permission_id
                else:
                    permission_id = await google_adapter.drive_permission_id(directory_group.email)
                    if (prior_group and prior_group.drive_permission_id
                            and prior_group.drive_permission_id != permission_id):
                        raise DirectorySyncError("GOOGLE_DRIVE_GROUP_PERMISSION_ID_CHANGED")
                if permission_id in seen_group_ids or permission_id in seen_user_ids:
                    raise DirectorySyncError("DUPLICATE_GOOGLE_DRIVE_GROUP_PERMISSION_ID")
                seen_group_ids.add(permission_id)
                verified_group_permission_ids[directory_group.provider_id] = permission_id
    except DirectorySyncError as exc:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "degraded", _now(), exc.code
        raise
    except AuthenticationError as exc:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "reauthorization_required", _now(), "REAUTHORIZATION_REQUIRED"
        raise DirectorySyncError("REAUTHORIZATION_REQUIRED") from exc
    except AuthorizationError as exc:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "degraded", _now(), "INSUFFICIENT_PERMISSION"
        raise DirectorySyncError("INSUFFICIENT_PERMISSION") from exc
    except (RateLimitError, ProviderUnavailableError) as exc:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "degraded", _now(), "DEGRADED"
        raise DirectorySyncError("DEGRADED") from exc
    except Exception:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "degraded", _now(), "DIRECTORY_SYNC_INCOMPLETE"
        raise
    finally:
        await adapter.close()
    now = _now()
    identity_map_changed = False
    subjects: dict[str, GuardSubject] = {}
    changed_subjects: dict[str, GuardSubject] = {}
    # One query for the whole directory (was one query per user).
    known_subjects = {
        row.provider_subject_id: row for row in db.scalars(select(GuardSubject).where(
            GuardSubject.organization_id == source.organization_id,
            GuardSubject.provider == provider,
        ))
    }
    microsoft_tenant = _microsoft_tenant(credentials) if provider == "microsoft365" else None
    for user in users:
        subject = known_subjects.get(user.provider_id)
        if subject is None:
            subject = GuardSubject(organization_id=source.organization_id, provider=provider, provider_subject_id=user.provider_id)
            db.add(subject)
            known_subjects[user.provider_id] = subject
        if subject.id is not None and subject.status != user.status:
            changed_subjects[subject.id] = subject
        subject.display_name, subject.primary_email, subject.status, subject.last_synced_at = user.display_name, user.email, user.status, now
        if provider == "microsoft365":
            # Directory provenance for automatic identity binding: the tenant
            # these source credentials read the account from, member vs guest.
            if (subject.provider_tenant_id and microsoft_tenant
                    and subject.provider_tenant_id != microsoft_tenant):
                raise DirectorySyncError("DIRECTORY_TENANT_CONFLICT")
            subject.provider_tenant_id = microsoft_tenant
            subject.account_kind = user.account_kind
        if provider == "google-drive" and settings.env == "production":
            resolved_id = verified_user_permission_ids.get(user.provider_id)
            identity_map_changed |= subject.drive_permission_id != resolved_id
            subject.drive_permission_id = resolved_id
        subjects[user.provider_id] = subject
    # This is a full, paginated provider snapshot. A previously known account
    # absent from a completed snapshot must not keep authorization indefinitely.
    for prior_subject in list(known_subjects.values()):
        if prior_subject.provider_subject_id not in subjects:
            if prior_subject.status != "removed":
                changed_subjects[prior_subject.id] = prior_subject
            prior_subject.status = "removed"
            prior_subject.drive_permission_id = None
            prior_subject.last_synced_at = now
    db.flush()
    for changed_subject in changed_subjects.values():
        _queue_subject_status_refresh(db, source, provider, changed_subject, now)
    group_rows: dict[str, GuardGroup] = {}
    known_groups = {
        row.provider_group_id: row for row in db.scalars(select(GuardGroup).where(
            GuardGroup.organization_id == source.organization_id,
            GuardGroup.provider == provider,
        ))
    }
    for directory_group in groups:
        group_row = known_groups.get(directory_group.provider_id)
        if group_row is None and provider == "google-drive" and settings.env == "production":
            # The ACL may have arrived before Workspace group enumeration.
            # Adopt only a pending entry bound to the *provider-confirmed*
            # opaque Drive ID, never an email or an unrelated group.
            permission_id = verified_group_permission_ids[directory_group.provider_id]
            provisional = db.scalar(select(GuardGroup).where(
                GuardGroup.organization_id == source.organization_id,
                GuardGroup.provider == provider,
                GuardGroup.drive_permission_id == permission_id,
            ))
            if provisional is not None:
                if provisional.provider_group_id != f"drive-unresolved:{permission_id}":
                    raise DirectorySyncError("GOOGLE_DRIVE_GROUP_IDENTITY_CONFLICT")
                provisional.provider_group_id = directory_group.provider_id
                group_row = provisional
        # An ACL can be observed before the directory job resolves the stable
        # provider group id.  Reuse that provisional email-keyed row only for
        # legacy development fixtures; production uses Drive permission IDs.
        if group_row is None and provider == "google-drive" and settings.env == "production":
            # ACL ingestion can predate a complete directory snapshot. Such an
            # ACL is stored against an *unknown* provisional Drive permission
            # principal and must grant no access. Promote only that placeholder
            # after Google's getIdForEmail resolves the exact opaque ID; never
            # merge an unrelated known group by email.
            resolved_id = verified_group_permission_ids[directory_group.provider_id]
            provisional = db.scalar(select(GuardGroup).where(
                GuardGroup.organization_id == source.organization_id,
                GuardGroup.provider == provider,
                GuardGroup.drive_permission_id == resolved_id,
            ))
            if provisional is not None:
                if (provisional.status != "unknown"
                        or provisional.provider_group_id != f"drive-unresolved:{resolved_id}"):
                    raise DirectorySyncError("GOOGLE_DRIVE_GROUP_IDENTITY_COLLISION")
                provisional.provider_group_id = directory_group.provider_id
                group_row = provisional
        if (group_row is None and directory_group.email and provider == "google-drive"
                and settings.env != "production"):
            group_row = db.scalar(select(GuardGroup).where(
                GuardGroup.organization_id == source.organization_id,
                GuardGroup.provider == provider,
                GuardGroup.provider_email == directory_group.email,
            ))
            if group_row is not None:
                group_row.provider_group_id = directory_group.provider_id
        if group_row is None:
            group_row = GuardGroup(organization_id=source.organization_id, provider=provider, provider_group_id=directory_group.provider_id)
            db.add(group_row)
        group_row.display_name, group_row.provider_email, group_row.status, group_row.last_synced_at = directory_group.display_name, directory_group.email, "active", now
        if provider == "google-drive" and settings.env == "production":
            resolved_id = verified_group_permission_ids[directory_group.provider_id]
            identity_map_changed |= group_row.drive_permission_id != resolved_id
            group_row.drive_permission_id = resolved_id
        group_rows[directory_group.provider_id] = group_row
    db.flush()
    # Groups can be deleted while their old document ACL/grant remains cached.
    # Retire the old membership paths after a complete directory snapshot.
    for prior_group in db.scalars(select(GuardGroup).where(
        GuardGroup.organization_id == source.organization_id,
        GuardGroup.provider == provider,
    )):
        if prior_group.provider_group_id in group_rows:
            continue
        prior_group.status = "removed"
        prior_group.drive_permission_id = None
        for membership_row in db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == source.organization_id,
            GuardGroupMembership.group_id == prior_group.id,
            GuardGroupMembership.active.is_(True),
        )):
            subject = db.get(GuardSubject, membership_row.subject_id)
            if subject is not None:
                _queue_membership_events(db, source, provider, prior_group, subject, "membership_revoke", now)
            membership_row.active = False
            membership_row.updated_at = now
    subjects_by_id = {row.id: row for row in known_subjects.values()}
    memberships = 0
    for group_id, member_ids in members.items():
        active_group = group_rows[group_id]
        present = set(member_ids)
        existing = list(db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == source.organization_id,
            GuardGroupMembership.group_id == active_group.id,
        )))
        by_subject = {membership_row.subject_id: membership_row for membership_row in existing}
        for member_id in present:
            subject = subjects.get(member_id)
            if subject is None:
                # A user omitted from a paged/privileged response is unknown,
                # not an identity to manufacture from an email address.
                continue
            existing_membership = by_subject.get(subject.id)
            was_active = bool(existing_membership and existing_membership.active)
            if existing_membership is None:
                created_membership = GuardGroupMembership(organization_id=source.organization_id, group_id=active_group.id, subject_id=subject.id, active=True)
                db.add(created_membership)
            else:
                existing_membership.active = True
                existing_membership.updated_at = now
            if not was_active:
                _queue_membership_events(db, source, provider, active_group, subject, "membership_upsert", now)
            memberships += 1
        for membership_row in existing:
            subject = subjects_by_id.get(membership_row.subject_id) or db.get(GuardSubject, membership_row.subject_id)
            if subject and subject.provider_subject_id not in present:
                if membership_row.active:
                    _queue_membership_events(db, source, provider, active_group, subject, "membership_revoke", now)
                membership_row.active = False
                membership_row.updated_at = now
    if identity_map_changed and provider == "google-drive" and settings.env == "production":
        # A legacy directory or Drive ACL ingestion could have produced
        # effective ALLOW before the provider-backed identity bridge existed.
        # Invalidate all cached grant paths for this one approved source, then
        # queue independent effective-access recalculations (DENY until the
        # subsequent authoritative ACL inventory re-establishes a grant).
        # This is control-plane cache maintenance, never a Google permission
        # mutation. The source ACL cursor remains queued until rebuilt.
        affected_subjects = set(db.scalars(select(GuardEffectiveAccess.subject_id).where(
            GuardEffectiveAccess.organization_id == source.organization_id,
            GuardEffectiveAccess.source_id == source.id,
        )).all())
        for grant in db.scalars(select(GuardPermissionGrant).where(
            GuardPermissionGrant.organization_id == source.organization_id,
            GuardPermissionGrant.source_id == source.id,
            GuardPermissionGrant.active.is_(True),
        )):
            grant.active = False
            grant.provider_revision = 0  # new trusted cursor starts at revision 1
        db.flush()
        for subject_id in affected_subjects:
            subject = db.get(GuardSubject, subject_id)
            if subject is not None:
                _queue_subject_status_refresh(db, source, provider, subject, now)
        # A newly resolved identity may already have direct ACL grants on
        # indexed files. Queue a complete scoped inventory, including prior
        # changes, before Protect can trust any policy derived from the map.
        acl_cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.organization_id == source.organization_id,
            ProviderSyncCursor.source_id == source.id,
            ProviderSyncCursor.sync_kind == "acl",
        ))
        if acl_cursor is None:
            acl_cursor = ProviderSyncCursor(
                organization_id=source.organization_id, source_id=source.id,
                provider=provider, sync_kind="acl",
            )
            db.add(acl_cursor)
        acl_cursor.status = "queued"
        acl_cursor.last_success_at = None
        acl_cursor.cursor = None
        acl_cursor.last_provider_revision = None
    cursor.status = "connected"
    cursor.last_success_at = now
    cursor.last_error_code = None
    # D-31: this value feeds the signed authorization revision. It used to be
    # the sync timestamp, which issued a new revision every directory sync and
    # made Layer 2 block in-flight answers with no authorization change. It is
    # now a fingerprint of the authorization-relevant directory CONTENT (users
    # and their status/kind/email, groups, memberships): any real change still
    # changes it; an unchanged directory keeps it. last_success_at records time.
    cursor.last_provider_revision = _directory_fingerprint(users, groups, members)
    result: dict[str, Any] = {"users": len(users), "groups": len(groups), "memberships": memberships}
    if provider == "microsoft365":
        if microsoft_tenant is None:
            # No authoritative tenant: no automatic binding (fail closed).
            result["automatic_identity_resolution"] = "TENANT_UNKNOWN"
        else:
            result["automatic_identity_resolution"] = reconcile_microsoft_bindings(
                db, source, microsoft_tenant, now=now).as_dict()
    return result


def _queue_subject_status_refresh(
    db: Session, source: SourceConnection, provider: str,
    subject: GuardSubject, observed_at: datetime,
) -> None:
    """Reissue decisions for all existing resources when employee status flips.

    A suspended/removed employee may have several direct grants or group
    grants, across multiple sources. Refresh policy rows rather than merely
    changing their directory status.
    """
    accesses = list(db.scalars(select(GuardEffectiveAccess).where(
        GuardEffectiveAccess.organization_id == source.organization_id,
        GuardEffectiveAccess.subject_id == subject.id,
    )))
    revision = int(observed_at.timestamp() * 1000)
    for access in accesses:
        bound_source = db.get(SourceConnection, access.source_id)
        if bound_source is None or _provider(bound_source) != provider:
            continue
        stable = f"{access.source_id}:{subject.id}:{access.id}:{revision}:{subject.status}:status"
        dedupe = hashlib.sha256(stable.encode()).hexdigest()
        if db.scalar(select(GuardPermissionEvent.id).where(
            GuardPermissionEvent.organization_id == source.organization_id,
            GuardPermissionEvent.dedupe_key == dedupe,
        )):
            continue
        db.add(GuardPermissionEvent(
            organization_id=source.organization_id,
            source_id=access.source_id,
            provider=provider,
            provider_revision=max(revision, access.source_revision),
            subject_id=subject.id,
            resource_id=access.resource_id,
            change_type="subject_status_refresh",
            dedupe_key=dedupe,
            processing_status="queued",
            mutation_json=json.dumps({"scope": access.scope, "snapshot_complete": True}, sort_keys=True),
            observed_at=observed_at,
            received_at=observed_at,
        ))


def _queue_membership_events(db: Session, source: SourceConnection, provider: str, group: GuardGroup, subject: GuardSubject, change_type: str, observed_at: datetime) -> None:
    revision = int(observed_at.timestamp() * 1000)
    grants = db.scalars(select(GuardPermissionGrant).where(
        GuardPermissionGrant.organization_id == source.organization_id,
        GuardPermissionGrant.source_id == source.id,
        GuardPermissionGrant.principal_type == "group",
        GuardPermissionGrant.principal_id == group.id,
        GuardPermissionGrant.active.is_(True),
    ))
    for grant in grants:
        stable = f"{source.id}:{group.provider_group_id}:{subject.id}:{grant.grant_key}:{revision}:{change_type}"
        dedupe = hashlib.sha256(stable.encode()).hexdigest()[:120]
        if db.scalar(select(GuardPermissionEvent.id).where(
            GuardPermissionEvent.organization_id == source.organization_id,
            GuardPermissionEvent.dedupe_key == dedupe,
        )):
            continue
        db.add(GuardPermissionEvent(
            organization_id=source.organization_id,
            source_id=source.id,
            provider=provider,
            provider_revision=revision,
            subject_id=subject.id,
            resource_id=grant.resource_id,
            change_type=change_type,
            dedupe_key=dedupe,
            processing_status="queued",
            mutation_json=json.dumps({"group_id": group.provider_group_id, "scope": grant.scope, "snapshot_complete": True}, sort_keys=True),
            observed_at=observed_at,
            received_at=observed_at,
        ))
