"""Normalize provider directory data into the Guard identity graph."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _provider(source: SourceConnection) -> str:
    return "microsoft365" if source.provider.lower() in {"microsoft365", "sharepoint", "onedrive"} else source.provider.lower()


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
    try:
        users = await adapter.users()
        groups = await adapter.groups()
        members = {group.provider_id: await adapter.members(group.provider_id) for group in groups}
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
    subjects: dict[str, GuardSubject] = {}
    changed_subjects: dict[str, GuardSubject] = {}
    for user in users:
        subject = db.scalar(select(GuardSubject).where(
            GuardSubject.organization_id == source.organization_id,
            GuardSubject.provider == provider,
            GuardSubject.provider_subject_id == user.provider_id,
        ))
        if subject is None:
            subject = GuardSubject(organization_id=source.organization_id, provider=provider, provider_subject_id=user.provider_id)
            db.add(subject)
        if subject.id is not None and subject.status != user.status:
            changed_subjects[subject.id] = subject
        subject.display_name, subject.primary_email, subject.status, subject.last_synced_at = user.display_name, user.email, user.status, now
        subjects[user.provider_id] = subject
    # This is a full, paginated provider snapshot. A previously known account
    # absent from a completed snapshot must not keep authorization indefinitely.
    for prior_subject in db.scalars(select(GuardSubject).where(
        GuardSubject.organization_id == source.organization_id,
        GuardSubject.provider == provider,
    )):
        if prior_subject.provider_subject_id not in subjects:
            if prior_subject.status != "removed":
                changed_subjects[prior_subject.id] = prior_subject
            prior_subject.status = "removed"
            prior_subject.last_synced_at = now
    db.flush()
    for changed_subject in changed_subjects.values():
        _queue_subject_status_refresh(db, source, provider, changed_subject, now)
    group_rows: dict[str, GuardGroup] = {}
    for directory_group in groups:
        group_row = db.scalar(select(GuardGroup).where(
            GuardGroup.organization_id == source.organization_id,
            GuardGroup.provider == provider,
            GuardGroup.provider_group_id == directory_group.provider_id,
        ))
        # An ACL can be observed before the directory job resolves the stable
        # provider group id.  Reuse that provisional email-keyed row rather
        # than creating a second group and losing the already-ingested ACL.
        if group_row is None and directory_group.email and provider == "google-drive":
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
    memberships = 0
    for group_id, member_ids in members.items():
        group = group_rows[group_id]
        present = set(member_ids)
        existing = list(db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == source.organization_id,
            GuardGroupMembership.group_id == group.id,
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
                created_membership = GuardGroupMembership(organization_id=source.organization_id, group_id=group.id, subject_id=subject.id, active=True)
                db.add(created_membership)
            else:
                existing_membership.active = True
                existing_membership.updated_at = now
            if not was_active:
                _queue_membership_events(db, source, provider, group, subject, "membership_upsert", now)
            memberships += 1
        for membership_row in existing:
            subject = db.get(GuardSubject, membership_row.subject_id)
            if subject and subject.provider_subject_id not in present:
                if membership_row.active:
                    _queue_membership_events(db, source, provider, group, subject, "membership_revoke", now)
                membership_row.active = False
                membership_row.updated_at = now
    cursor.status = "connected"
    cursor.last_success_at = now
    cursor.last_error_code = None
    # Full-snapshot readers do not have an incremental cursor.  Persist a
    # monotonic successful revision so restarts and operator diagnostics have
    # durable evidence without pretending a provider delta token exists.
    cursor.last_provider_revision = now.isoformat()
    return {"users": len(users), "groups": len(groups), "memberships": memberships}


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
