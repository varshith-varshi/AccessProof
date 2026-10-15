"""Durable, provider-neutral Guard permission-event resolver.

The API only queues normalized changes.  This module runs in the worker and
turns the complete persisted permission state into an effective authorization
decision.  A revocation deactivates one grant path; it is never itself treated
as a denial.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import (
    AuditEvent,
    GuardEffectiveAccess,
    GuardGroup,
    GuardGroupMembership,
    GuardPermissionEvent,
    GuardPermissionGrant,
    GuardPermissionSnapshot,
    GuardPolicy,
    GuardPolicyDistribution,
    GuardPolicySequence,
    GuardRegistration,
    GuardResource,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _event_mutation(event: GuardPermissionEvent) -> dict[str, object]:
    try:
        raw = json.loads(event.mutation_json or "{}")
    except json.JSONDecodeError:
        raw = {}
    return raw if isinstance(raw, dict) else {}


def _group(db: Session, event: GuardPermissionEvent, provider_group_id: str) -> GuardGroup:
    row = db.scalar(select(GuardGroup).where(
        GuardGroup.organization_id == event.organization_id,
        GuardGroup.provider == event.provider,
        GuardGroup.provider_group_id == provider_group_id,
    ))
    if row is None:
        row = GuardGroup(
            organization_id=event.organization_id,
            provider=event.provider,
            provider_group_id=provider_group_id,
            last_synced_at=_now(),
        )
        db.add(row)
        db.flush()
    return row


def _apply_mutation(db: Session, event: GuardPermissionEvent, mutation: dict[str, object]) -> str | None:
    """Apply a normalized change.  Return an UNKNOWN reason when inputs are incomplete."""
    if not bool(mutation.get("snapshot_complete", True)) or event.change_type == "sync_incomplete":
        return "SOURCE_SYNC_INCOMPLETE"

    if event.change_type in {"membership_upsert", "membership_revoke"}:
        provider_group_id = str(mutation.get("group_id") or "")
        if not provider_group_id:
            return "GROUP_MEMBERSHIP_UNAVAILABLE"
        group = _group(db, event, provider_group_id)
        membership = db.scalar(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == event.organization_id,
            GuardGroupMembership.group_id == group.id,
            GuardGroupMembership.subject_id == event.subject_id,
        ))
        if membership is not None and membership.provider_revision > event.provider_revision:
            return "STALE"
        if membership is None:
            membership = GuardGroupMembership(
                organization_id=event.organization_id,
                group_id=group.id,
                subject_id=event.subject_id,
                active=event.change_type == "membership_upsert",
                provider_revision=event.provider_revision,
            )
            db.add(membership)
        else:
            membership.active = event.change_type == "membership_upsert"
            membership.provider_revision = event.provider_revision
            membership.updated_at = _now()
        return None

    if event.change_type not in {"grant_upsert", "grant_revoke"}:
        return "SOURCE_SYNC_INCOMPLETE"
    grant_key = str(mutation.get("grant_key") or "")
    if not grant_key:
        # An event without a stable provider permission identifier cannot safely
        # mutate state.  Record UNKNOWN instead of guessing which path changed.
        return "PERMISSION_DATA_STALE"
    grant = db.scalar(select(GuardPermissionGrant).where(
        GuardPermissionGrant.organization_id == event.organization_id,
        GuardPermissionGrant.source_id == event.source_id,
        GuardPermissionGrant.grant_key == grant_key,
    ))
    if grant is not None and grant.provider_revision > event.provider_revision:
        return "STALE"
    if event.change_type == "grant_revoke":
        if grant is not None:
            grant.active = False
            grant.provider_revision = event.provider_revision
            grant.observed_at = _now()
        return None

    principal_type = str(mutation.get("principal_type") or "subject")
    principal_id = str(mutation.get("principal_id") or "")
    if principal_type == "subject":
        principal_id = event.subject_id
    elif principal_type == "group":
        provider_group_id = str(mutation.get("group_id") or principal_id)
        if not provider_group_id:
            return "GROUP_MEMBERSHIP_UNAVAILABLE"
        principal_id = _group(db, event, provider_group_id).id
    elif principal_type == "organization":
        principal_id = event.organization_id
    else:
        return "IDENTITY_UNRESOLVED"
    resource = db.get(GuardResource, event.resource_id)
    if resource is None or resource.organization_id != event.organization_id:
        return "IDENTITY_UNRESOLVED"
    values = dict(
        organization_id=event.organization_id,
        source_id=event.source_id,
        resource_id=event.resource_id,
        grant_key=grant_key,
        principal_type=principal_type,
        principal_id=principal_id,
        effect=str(mutation.get("grant_effect") or "allow"),
        scope=str(mutation.get("scope") or resource.scope or "read"),
        access_path=str(mutation.get("access_path") or "") or None,
        active=True,
        provider_revision=event.provider_revision,
        observed_at=_now(),
    )
    if grant is None:
        db.add(GuardPermissionGrant(**values))
    else:
        for key, value in values.items():
            if key not in {"organization_id", "source_id", "grant_key"}:
                setattr(grant, key, value)
    return None


def _effective_grants(db: Session, event: GuardPermissionEvent, scope: str) -> list[GuardPermissionGrant]:
    group_ids = list(db.scalars(select(GuardGroupMembership.group_id).where(
        GuardGroupMembership.organization_id == event.organization_id,
        GuardGroupMembership.subject_id == event.subject_id,
        GuardGroupMembership.active.is_(True),
    )))
    grants = list(db.scalars(select(GuardPermissionGrant).where(
        GuardPermissionGrant.organization_id == event.organization_id,
        GuardPermissionGrant.source_id == event.source_id,
        GuardPermissionGrant.resource_id == event.resource_id,
        GuardPermissionGrant.scope == scope,
        GuardPermissionGrant.active.is_(True),
    )))
    return [
        grant for grant in grants
        if (grant.principal_type == "subject" and grant.principal_id == event.subject_id)
        or (grant.principal_type == "group" and grant.principal_id in group_ids)
        or (grant.principal_type == "organization" and grant.principal_id == event.organization_id)
    ]


def _decision(grants: list[GuardPermissionGrant], unknown_reason: str | None) -> tuple[str, str]:
    if unknown_reason and unknown_reason != "STALE":
        return "unknown", unknown_reason
    if any(grant.effect.lower() == "deny" for grant in grants):
        return "deny", "EXPLICIT_DENY"
    if any(grant.effect.lower() == "allow" for grant in grants):
        return "allow", "ACTIVE_GRANT_PATH"
    return "deny", "NO_ACTIVE_GRANT_PATH"


def _next_policy_version(db: Session, organization_id: str) -> int:
    """Allocate one strictly increasing version in the same transaction.

    PostgreSQL locks the per-tenant sequence row.  SQLite serializes writers;
    its test behaviour therefore exercises the same persisted allocator.
    """
    sequence = db.scalar(
        select(GuardPolicySequence)
        .where(GuardPolicySequence.organization_id == organization_id)
        .with_for_update()
    )
    if sequence is None:
        sequence = GuardPolicySequence(organization_id=organization_id, next_version=2)
        db.add(sequence)
        db.flush()
        return 1
    version = sequence.next_version
    sequence.next_version += 1
    sequence.updated_at = _now()
    return version


def process_guard_event(db: Session, event_id: str) -> dict[str, str]:
    """Resolve a claimed event transactionally and idempotently."""
    event = db.get(GuardPermissionEvent, event_id)
    if event is None:
        return {"status": "missing"}
    if event.processing_status in {"resolved", "stale", "error"}:
        return {"status": event.processing_status, "policy_id": event.policy_id or ""}
    event.processing_status = "processing"
    db.flush()
    mutation = _event_mutation(event)
    unknown_reason = _apply_mutation(db, event, mutation)
    # SessionLocal deliberately disables autoflush, so make the just-applied
    # grant or membership visible to the resolver in this transaction.
    db.flush()
    resource = db.get(GuardResource, event.resource_id)
    scope = str(mutation.get("scope") or (resource.scope if resource else "read") or "read")
    prior = db.scalar(select(GuardEffectiveAccess).where(
        GuardEffectiveAccess.organization_id == event.organization_id,
        GuardEffectiveAccess.source_id == event.source_id,
        GuardEffectiveAccess.subject_id == event.subject_id,
        GuardEffectiveAccess.resource_id == event.resource_id,
        GuardEffectiveAccess.scope == scope,
    ))
    if prior is not None and event.provider_revision < prior.source_revision:
        event.processing_status = "stale"
        event.error_code = "STALE"
        event.completed_at = _now()
        db.commit()
        return {"status": "stale"}
    grants = _effective_grants(db, event, scope)
    decision, reason = _decision(grants, unknown_reason)
    changed = prior is None or prior.decision != decision
    state_version = (prior.state_version if prior else 0) + 1
    if prior is None:
        prior = GuardEffectiveAccess(
            organization_id=event.organization_id,
            source_id=event.source_id,
            subject_id=event.subject_id,
            resource_id=event.resource_id,
            scope=scope,
            decision=decision,
            source_revision=event.provider_revision,
            state_version=state_version,
            reason=reason,
            resolved_at=_now(),
        )
        db.add(prior)
        db.flush()
    else:
        prior.decision = decision
        prior.reason = reason
        prior.source_revision = max(prior.source_revision, event.provider_revision)
        prior.state_version = state_version
        prior.resolved_at = _now()
    db.add(GuardPermissionSnapshot(
        organization_id=event.organization_id,
        effective_access_id=prior.id,
        permission_event_id=event.id,
        state_version=state_version,
        source_revision=event.provider_revision,
        decision=decision,
        reason=reason,
        grant_keys_json=json.dumps(sorted(grant.grant_key for grant in grants)),
    ))
    if changed:
        next_version = _next_policy_version(db, event.organization_id)
        previous_policy = db.scalar(select(GuardPolicy).where(
            GuardPolicy.organization_id == event.organization_id,
            GuardPolicy.policy_key == f"{event.source_id}:{event.subject_id}:{event.resource_id}:{scope}",
        ).order_by(GuardPolicy.version.desc()).limit(1))
        policy = GuardPolicy(
            organization_id=event.organization_id,
            policy_key=f"{event.source_id}:{event.subject_id}:{event.resource_id}:{scope}",
            version=next_version,
            decision=decision,
            subject_id=event.subject_id,
            resource_id=event.resource_id,
            source_id=event.source_id,
            scope=scope,
            source_revision=event.provider_revision,
            effective_state_version=state_version,
            reason=reason,
            supersedes_policy_id=previous_policy.id if previous_policy else None,
        )
        db.add(policy)
        db.flush()
        event.policy_id = policy.id
        guards = list(db.scalars(select(GuardRegistration).where(
            GuardRegistration.organization_id == event.organization_id,
            GuardRegistration.revoked_at.is_(None),
        )))
        if guards:
            for guard in guards:
                db.add(GuardPolicyDistribution(
                    organization_id=event.organization_id,
                    policy_id=policy.id,
                    guard_id=guard.id,
                    status="pending",
                ))
        else:
            db.add(GuardPolicyDistribution(
                organization_id=event.organization_id,
                policy_id=policy.id,
                guard_id=None,
                status="pending",
            ))
        db.add(AuditEvent(
            organization_id=event.organization_id,
            action="guard.policy_committed",
            target_type="guard_policy",
            target_id=policy.id,
            metadata_json=json.dumps({"event_id": event.id, "decision": decision, "version": next_version}),
        ))
    event.processing_status = "resolved"
    event.error_code = None
    event.completed_at = _now()
    db.commit()
    return {"status": "resolved", "policy_id": event.policy_id or "", "decision": decision}
