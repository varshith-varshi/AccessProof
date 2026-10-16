"""Normalize provider directory data into the Guard identity graph."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import (
    GuardGroup,
    GuardGroupMembership,
    GuardSubject,
    ProviderSyncCursor,
    SourceConnection,
)
from connectors.directory import (
    DirectorySyncError,
    GoogleWorkspaceDirectoryAdapter,
    MicrosoftEntraDirectoryAdapter,
)


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
    except Exception:
        cursor.status, cursor.last_error_at, cursor.last_error_code = "degraded", _now(), "DIRECTORY_SYNC_INCOMPLETE"
        raise
    finally:
        await adapter.close()
    now = _now()
    subjects: dict[str, GuardSubject] = {}
    for user in users:
        subject = db.scalar(select(GuardSubject).where(
            GuardSubject.organization_id == source.organization_id,
            GuardSubject.provider == provider,
            GuardSubject.provider_subject_id == user.provider_id,
        ))
        if subject is None:
            subject = GuardSubject(organization_id=source.organization_id, provider=provider, provider_subject_id=user.provider_id)
            db.add(subject)
        subject.display_name, subject.primary_email, subject.status, subject.last_synced_at = user.display_name, user.email, user.status, now
        subjects[user.provider_id] = subject
    db.flush()
    group_rows: dict[str, GuardGroup] = {}
    for group in groups:
        row = db.scalar(select(GuardGroup).where(
            GuardGroup.organization_id == source.organization_id,
            GuardGroup.provider == provider,
            GuardGroup.provider_group_id == group.provider_id,
        ))
        if row is None:
            row = GuardGroup(organization_id=source.organization_id, provider=provider, provider_group_id=group.provider_id)
            db.add(row)
        row.display_name, row.status, row.last_synced_at = group.display_name, "active", now
        group_rows[group.provider_id] = row
    db.flush()
    memberships = 0
    for group_id, member_ids in members.items():
        group = group_rows[group_id]
        present = set(member_ids)
        existing = list(db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == source.organization_id,
            GuardGroupMembership.group_id == group.id,
        )))
        by_subject = {row.subject_id: row for row in existing}
        for member_id in present:
            subject = subjects.get(member_id)
            if subject is None:
                # A user omitted from a paged/privileged response is unknown,
                # not an identity to manufacture from an email address.
                continue
            row = by_subject.get(subject.id)
            if row is None:
                row = GuardGroupMembership(organization_id=source.organization_id, group_id=group.id, subject_id=subject.id, active=True)
                db.add(row)
            else:
                row.active = True
                row.updated_at = now
            memberships += 1
        for row in existing:
            subject = db.get(GuardSubject, row.subject_id)
            if subject and subject.provider_subject_id not in present:
                row.active = False
                row.updated_at = now
    cursor.status = "connected"
    cursor.last_success_at = now
    cursor.last_error_code = None
    # Full-snapshot readers do not have an incremental cursor.  Persist a
    # monotonic successful revision so restarts and operator diagnostics have
    # durable evidence without pretending a provider delta token exists.
    cursor.last_provider_revision = now.isoformat()
    return {"users": len(users), "groups": len(groups), "memberships": memberships}
