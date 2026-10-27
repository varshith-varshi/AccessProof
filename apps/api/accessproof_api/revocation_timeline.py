"""Privacy-safe six-timestamp revocation timeline from retained evidence.

The timeline never guesses a missing timestamp. Each field is either directly
observed and sourced, or explicitly NOT_OBSERVED. Employee, resource and file
identifiers are used only for matching and are never returned.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from apps.api.accessproof_api.db import (
    AIApplication,
    AuthorizationRevision,
    GuardAuditEvent,
    GuardPermissionEvent,
    GuardResource,
    GuardSubject,
)

REVOCATION_TIMELINE_SCHEMA = "accessproof.revocation_timeline/v1"
_REVOKE_TYPES = ("grant_revoke", "membership_revoke", "user_disable", "revoke")
_TIMESTAMP_SOURCES = {
    "provider_permission_mutation_at": "Provider-supplied mutation timestamp in the permission event payload.",
    "provider_change_observed_at": "AccessProof observation time of the provider permission event.",
    "acl_state_committed_at": "Time the normalized ACL state transaction completed.",
    "authorization_revision_created_at": "First signed revision generated for this application at or after the ACL commit.",
    "guard_revision_applied_at": "First machine-authenticated Guard audit event evaluated under that exact revision. This is first observed use, not a heartbeat acknowledgement.",
    "first_verified_denial_at": "First blocking Layer 1 Guard audit after the ACL commit whose subject or resource matches the revocation event.",
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _utc(parsed)


def _timestamp(value: datetime | None, source: str, **extra: Any) -> dict[str, Any]:
    observed = _utc(value)
    return {
        "value": observed.isoformat() if observed else None,
        "status": "OBSERVED" if observed else "NOT_OBSERVED",
        "source": source,
        **extra,
    }


def _seconds(start: datetime | None, end: datetime | None) -> float | None:
    start_utc, end_utc = _utc(start), _utc(end)
    if start_utc is None or end_utc is None:
        return None
    return round(max(0.0, (end_utc - start_utc).total_seconds()), 3)


def _mutation_time(event: GuardPermissionEvent) -> datetime | None:
    try:
        mutation = json.loads(event.mutation_json or "{}")
    except ValueError:
        return None
    if not isinstance(mutation, dict):
        return None
    for key in ("provider_mutated_at", "provider_mutation_at", "mutation_at"):
        parsed = _parse_time(mutation.get(key))
        if parsed is not None:
            return parsed
    return None


def _event_resources(event: GuardPermissionEvent) -> set[str]:
    try:
        values = json.loads(event.mutation_json or "{}")
    except ValueError:
        return set()
    resources: set[str] = set()
    if isinstance(values, dict) and isinstance(values.get("resource_ids"), list):
        resources.update(item for item in values["resource_ids"] if isinstance(item, str))
    return resources


def _audit_resources(event: GuardAuditEvent) -> set[str]:
    try:
        values = json.loads(event.resources_json or "[]")
    except ValueError:
        return set()
    return {item for item in values if isinstance(item, str)} if isinstance(values, list) else set()


def _matches_revocation(
    audit: GuardAuditEvent, *, resource_ids: set[str], subject_id: str | None,
) -> bool:
    if subject_id is not None and audit.subject_id == subject_id:
        return True
    return bool(resource_ids.intersection(_audit_resources(audit)))


def _entry(
    db: OrmSession, application: AIApplication, event: GuardPermissionEvent,
) -> dict[str, Any]:
    observed = _utc(event.observed_at)
    committed = _utc(event.completed_at)
    mutation = _mutation_time(event)

    revision = None
    if committed is not None:
        revision = db.scalar(select(AuthorizationRevision).where(
            AuthorizationRevision.organization_id == application.organization_id,
            AuthorizationRevision.application_row_id == application.id,
            AuthorizationRevision.application_id == application.application_id,
            AuthorizationRevision.generated_at >= committed,
        ).order_by(AuthorizationRevision.generated_at.asc()).limit(1))
    revision_generated = _utc(revision.generated_at) if revision else None

    guard_first_use: datetime | None = None
    if revision is not None:
        candidate = db.scalar(select(GuardAuditEvent).where(
            GuardAuditEvent.organization_id == application.organization_id,
            GuardAuditEvent.application_id == application.application_id,
            GuardAuditEvent.layer == "layer1",
            GuardAuditEvent.result.in_(("allow", "would_allow")),
            GuardAuditEvent.authorization_revision == revision.revision,
            GuardAuditEvent.authorization_revision_hash == revision.revision_hash,
        ).order_by(GuardAuditEvent.occurred_at.asc(), GuardAuditEvent.created_at.asc()).limit(1))
        if candidate is not None:
            guard_first_use = _utc(candidate.occurred_at or candidate.created_at)

    resource_ids: set[str] = set()
    if event.resource_id:
        resource = db.get(GuardResource, event.resource_id)
        if resource is not None and resource.organization_id == application.organization_id:
            resource_ids.add(resource.provider_resource_id)
    resource_ids.update(_event_resources(event))
    subject = db.get(GuardSubject, event.subject_id) if event.subject_id else None
    subject_id = (
        subject.provider_subject_id
        if subject is not None and subject.organization_id == application.organization_id
        else None
    )

    denial: datetime | None = None
    if committed is not None and (resource_ids or subject_id):
        candidates = db.scalars(select(GuardAuditEvent).where(
            GuardAuditEvent.organization_id == application.organization_id,
            GuardAuditEvent.application_id == application.application_id,
            GuardAuditEvent.layer == "layer1",
            GuardAuditEvent.result.in_(("block", "would_block")),
            GuardAuditEvent.occurred_at.is_not(None),
            GuardAuditEvent.occurred_at >= committed,
        ).order_by(GuardAuditEvent.occurred_at.asc()).limit(500)).all()
        for candidate in candidates:
            if _matches_revocation(candidate, resource_ids=resource_ids, subject_id=subject_id):
                denial = _utc(candidate.occurred_at)
                break

    timestamps = {
        "provider_permission_mutation_at": _timestamp(
            mutation, _TIMESTAMP_SOURCES["provider_permission_mutation_at"],
            evidence_level="PROVIDER_REPORTED" if mutation else "NOT_OBSERVED",
        ),
        "provider_change_observed_at": _timestamp(
            observed, _TIMESTAMP_SOURCES["provider_change_observed_at"],
            evidence_level="PRODUCTION_OBSERVED" if observed else "NOT_OBSERVED",
        ),
        "acl_state_committed_at": _timestamp(
            committed, _TIMESTAMP_SOURCES["acl_state_committed_at"],
            evidence_level="PRODUCTION_OBSERVED" if committed else "NOT_OBSERVED",
        ),
        "authorization_revision_created_at": _timestamp(
            revision_generated, _TIMESTAMP_SOURCES["authorization_revision_created_at"],
            evidence_level="PRODUCTION_OBSERVED" if revision_generated else "NOT_OBSERVED",
            revision=revision.revision if revision else None,
        ),
        "guard_revision_applied_at": _timestamp(
            guard_first_use, _TIMESTAMP_SOURCES["guard_revision_applied_at"],
            evidence_level="PRODUCTION_OBSERVED" if guard_first_use else "NOT_OBSERVED",
        ),
        "first_verified_denial_at": _timestamp(
            denial, _TIMESTAMP_SOURCES["first_verified_denial_at"],
            evidence_level="PRODUCTION_OBSERVED" if denial else "NOT_OBSERVED",
        ),
    }
    durations = {
        "provider_mutation_to_denial_seconds": _seconds(mutation, denial),
        "provider_observation_to_acl_commit_seconds": _seconds(observed, committed),
        "acl_commit_to_revision_created_seconds": _seconds(committed, revision_generated),
        "revision_created_to_guard_first_use_seconds": _seconds(
            revision_generated, guard_first_use
        ),
        "provider_observation_to_first_denial_seconds": _seconds(observed, denial),
    }
    return {
        "sequence": None,
        "provider": event.provider,
        "change_type": event.change_type,
        "processing_status": event.processing_status,
        "timestamps": timestamps,
        "durations": durations,
        "complete": all(
            timestamps[key]["status"] == "OBSERVED" for key in (
                "provider_change_observed_at", "acl_state_committed_at",
                "authorization_revision_created_at", "guard_revision_applied_at",
                "first_verified_denial_at",
            )
        ),
    }


def build_timeline(
    db: OrmSession, *, organization_id: str, application_id: str, limit: int = 20,
) -> dict[str, Any]:
    application = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == organization_id,
        AIApplication.application_id == application_id,
    ))
    if application is None:
        raise LookupError("AI application not found")
    bounded = max(1, min(limit, 50))
    base: dict[str, Any] = {
        "schema": REVOCATION_TIMELINE_SCHEMA,
        "application_id": application.application_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": [],
        "limitations": [
            "A missing timestamp is NOT_OBSERVED, never inferred from unrelated events.",
            "Provider mutation time is available only when the provider event carries it.",
            "Guard revision applied is the first authenticated audit under that exact revision, not a heartbeat acknowledgement.",
            "First denial requires a matching provider subject or resource; an unrelated denial is not counted.",
            "Only retained permission events and Guard audit records are represented.",
        ],
    }
    if application.source_id is None:
        base["reason"] = "APPLICATION_HAS_NO_PERMISSION_SOURCE"
        return base
    events = db.scalars(select(GuardPermissionEvent).where(
        GuardPermissionEvent.organization_id == organization_id,
        GuardPermissionEvent.source_id == application.source_id,
        GuardPermissionEvent.change_type.in_(_REVOKE_TYPES),
    ).order_by(
        GuardPermissionEvent.observed_at.desc(), GuardPermissionEvent.received_at.desc(),
    ).limit(bounded)).all()
    entries = [_entry(db, application, event) for event in events]
    for index, entry in enumerate(reversed(entries), start=1):
        entry["sequence"] = index
    base["events"] = entries
    base["counts"] = {
        "revocations": len(entries),
        "complete_timelines": sum(1 for entry in entries if entry["complete"]),
        "end_to_end_observed": sum(
            1 for entry in entries
            if entry["durations"]["provider_observation_to_first_denial_seconds"] is not None
        ),
    }
    base["reason"] = "NO_RETAINED_REVOCATION_EVENTS" if not entries else "RETAINED_EVIDENCE"
    return base


__all__ = ["REVOCATION_TIMELINE_SCHEMA", "build_timeline"]
