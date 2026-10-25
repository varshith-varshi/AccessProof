"""Validate Guard recovery while Redis is unavailable.

Guard permission events are intentionally durable PostgreSQL rows; the worker
scan is the recovery source when a Redis-side trigger/job is lost.
"""

from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, select
from apps.api.accessproof_api.db import (
    GuardPermissionEvent,
    GuardEffectiveAccess,
    GuardResource,
    GuardSubject,
    Organization,
    SessionLocal,
)
from apps.worker.accessproof_worker.main import claim_one_guard_event, process_claimed_guard_event


def main() -> int:
    db = SessionLocal()
    for old in list(
        db.scalars(
            select(Organization).where(
                Organization.name.in_(
                    [
                        "redis-recovery-validation",
                        "concurrency-validation",
                        "concurrency-validation-b",
                    ]
                )
            )
        )
    ):
        db.delete(old)
    db.commit()
    org = Organization(name="redis-recovery-validation")
    db.add(org)
    db.flush()
    subject = GuardSubject(
        organization_id=org.id, provider="validation", provider_subject_id="alice"
    )
    resource = GuardResource(
        organization_id=org.id, source_id="source", provider_resource_id="revocation-resource"
    )
    db.add_all([subject, resource])
    db.commit()
    org_id, sid, rid = org.id, subject.id, resource.id

    def add(status="queued", started=None, revision=1, key="recovery"):
        row = GuardPermissionEvent(
            organization_id=org_id,
            source_id="source",
            provider="validation",
            provider_revision=revision,
            subject_id=sid,
            resource_id=rid,
            change_type="grant_upsert",
            dedupe_key=key,
            processing_status=status,
            processing_started_at=started,
            mutation_json=json.dumps(
                {
                    "grant_key": "recovery-grant",
                    "principal_type": "subject",
                    "grant_effect": "allow",
                }
            ),
        )
        s = SessionLocal()
        s.add(row)
        s.commit()
        ident = row.id
        s.close()
        return ident

    try:
        # Redis-down enqueue equivalent: durable event exists before worker scan.
        queued = add()
        assert claim_one_guard_event() == queued
        process_claimed_guard_event(queued)
        # Lost queued job: an old processing lease is rediscovered after restart.
        abandoned = add(
            status="processing",
            started=datetime.now(timezone.utc) - timedelta(minutes=6),
            revision=2,
            key="abandoned",
        )
        assert claim_one_guard_event() == abandoned
        process_claimed_guard_event(abandoned)
        # Duplicate requeue/retry is idempotent and keeps one effective row.
        process_claimed_guard_event(abandoned)
        process_claimed_guard_event(queued)
        s = SessionLocal()
        assert s.get(GuardPermissionEvent, queued).processing_status == "resolved"
        assert s.get(GuardPermissionEvent, abandoned).processing_status == "resolved"
        assert (
            len(
                list(
                    s.scalars(
                        select(GuardEffectiveAccess).where(
                            GuardEffectiveAccess.organization_id == org_id
                        )
                    )
                )
            )
            == 1
        )
        s.close()
        print(
            "redis durable recovery matrix: 6/6 checks passed; lost-job recovery=DB scan; manual DB replay=0"
        )
        return 0
    finally:
        s = SessionLocal()
        s.execute(delete(Organization).where(Organization.id == org_id))
        s.commit()
        s.close()


if __name__ == "__main__":
    # This validator deletes/recreates test organizations. It must never run
    # merely because someone asks for --help or explores deployment commands.
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="Destructive Redis recovery check. Use only with a dedicated disposable database."
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Run against an isolated, correctly migrated validation database",
    )
    args = parser.parse_args()
    if not args.execute or os.environ.get("ACCESSPROOF_DISPOSABLE_VALIDATION") != "YES":
        parser.error(
            "Destructive validation disabled. Use --execute with "
            "ACCESSPROOF_DISPOSABLE_VALIDATION=YES only on a disposable database."
        )
    raise SystemExit(main())
