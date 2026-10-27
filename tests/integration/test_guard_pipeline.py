import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from apps.api.accessproof_api.db import (
    Base,
    GuardEffectiveAccess,
    GuardPermissionEvent,
    GuardPolicy,
    GuardSubject,
    GuardResource,
    Organization,
    SessionLocal,
    engine,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from apps.worker.accessproof_worker.main import claim_one_guard_event


def _event(db, org, subject, resource, revision, key, change_type, **mutation):
    row = GuardPermissionEvent(
        organization_id=org.id,
        source_id="drive-source",
        provider="google-drive",
        provider_revision=revision,
        subject_id=subject.id,
        resource_id=resource.id,
        change_type=change_type,
        dedupe_key=key,
        processing_status="queued",
        mutation_json=json.dumps({"scope": "read", "snapshot_complete": True, **mutation}),
    )
    db.add(row)
    db.commit()
    return row.id


def _setup():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    org = Organization(name="Guard pipeline")
    db.add(org)
    db.flush()
    subject = GuardSubject(organization_id=org.id, provider="google-drive", provider_subject_id="alice")
    resource = GuardResource(
        organization_id=org.id,
        source_id="drive-source",
        provider_resource_id="finance-folder",
    )
    db.add_all([subject, resource])
    db.commit()
    return db, org, subject, resource


def test_removing_one_of_two_group_paths_keeps_effective_access_allowed():
    db, org, subject, resource = _setup()
    try:
        for revision, group, action in [
            (1, "finance-readers", "membership_upsert"),
            (2, "finance-managers", "membership_upsert"),
        ]:
            event_id = _event(db, org, subject, resource, revision, f"member-{revision}", action, group_id=group)
            assert process_guard_event(db, event_id)["status"] == "resolved"
        for revision, group in [(3, "finance-readers"), (4, "finance-managers")]:
            event_id = _event(
                db, org, subject, resource, revision, f"grant-{revision}", "grant_upsert",
                grant_key=f"grant-{group}", principal_type="group", group_id=group, grant_effect="allow",
            )
            assert process_guard_event(db, event_id)["decision"] == "allow"
        before_revoke_policies = len(list(db.scalars(select(GuardPolicy))))
        event_id = _event(db, org, subject, resource, 5, "revoke-readers", "grant_revoke", grant_key="grant-finance-readers")
        result = process_guard_event(db, event_id)
        assert result["decision"] == "allow"
        effective = db.scalar(select(GuardEffectiveAccess))
        assert effective.decision == "allow"
        assert len(list(db.scalars(select(GuardPolicy)))) == before_revoke_policies
        event_id = _event(db, org, subject, resource, 6, "revoke-managers", "grant_revoke", grant_key="grant-finance-managers")
        assert process_guard_event(db, event_id)["decision"] == "deny"
        assert db.scalar(select(GuardEffectiveAccess)).decision == "deny"
        assert len(list(db.scalars(select(GuardPolicy)))) == before_revoke_policies + 1
        assert [p.version for p in db.scalars(select(GuardPolicy).order_by(GuardPolicy.version))] == list(
            range(1, before_revoke_policies + 2)
        )
    finally:
        db.close()


def test_stale_event_does_not_regress_state_or_create_policy():
    db, org, subject, resource = _setup()
    try:
        current = _event(
            db, org, subject, resource, 20, "allow-20", "grant_upsert",
            grant_key="direct-grant", principal_type="subject", grant_effect="allow",
        )
        assert process_guard_event(db, current)["decision"] == "allow"
        policies = len(list(db.scalars(select(GuardPolicy))))
        stale = _event(db, org, subject, resource, 19, "revoke-19", "grant_revoke", grant_key="direct-grant")
        assert process_guard_event(db, stale)["status"] == "stale"
        assert db.scalar(select(GuardEffectiveAccess)).decision == "allow"
        assert len(list(db.scalars(select(GuardPolicy)))) == policies
        assert db.get(GuardPermissionEvent, stale).processing_status == "stale"
    finally:
        db.close()


def test_incomplete_sync_becomes_unknown_instead_of_a_false_deny():
    db, org, subject, resource = _setup()
    try:
        event_id = _event(
            db, org, subject, resource, 1, "sync-incomplete", "sync_incomplete", snapshot_complete=False
        )
        assert process_guard_event(db, event_id)["decision"] == "unknown"
        effective = db.scalar(select(GuardEffectiveAccess))
        assert effective.decision == "unknown"
        assert effective.reason == "SOURCE_SYNC_INCOMPLETE"
    finally:
        db.close()


def test_retry_of_a_resolved_event_reuses_its_existing_policy():
    db, org, subject, resource = _setup()
    try:
        event_id = _event(
            db, org, subject, resource, 1, "grant-1", "grant_upsert",
            grant_key="direct", principal_type="subject", grant_effect="allow",
        )
        first = process_guard_event(db, event_id)
        retry = process_guard_event(db, event_id)
        assert retry["policy_id"] == first["policy_id"]
        assert len(list(db.scalars(select(GuardPolicy)))) == 1
    finally:
        db.close()


def test_abandoned_processing_event_is_reclaimed_and_completed():
    db, org, subject, resource = _setup()
    try:
        event_id = _event(
            db, org, subject, resource, 1, "reclaim-1", "grant_upsert",
            grant_key="direct", principal_type="subject", grant_effect="allow",
        )
        event = db.get(GuardPermissionEvent, event_id)
        event.processing_status = "processing"
        event.processing_started_at = datetime.now(timezone.utc) - timedelta(minutes=6)
        db.commit()
        assert claim_one_guard_event() == event_id
        assert process_guard_event(db, event_id)["status"] == "resolved"
        event = db.get(GuardPermissionEvent, event_id)
        assert event.processing_status == "resolved"
        assert event.processing_started_at is None
    finally:
        db.close()
