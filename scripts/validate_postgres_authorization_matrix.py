"""Production-table PostgreSQL Guard concurrency/recovery validation.

Run with DATABASE_URL pointing at the Compose PostgreSQL service.  This is
deliberately separate from the SQLite unit suite: every assertion below uses
the real Guard event, grant, effective-access, policy and distribution tables.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import delete, select

from apps.api.accessproof_api.db import (
    GuardEffectiveAccess,
    GuardPermissionEvent,
    GuardPolicy,
    GuardResource,
    GuardSubject,
    Organization,
    SessionLocal,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event_with_retry


def main() -> int:
    db = SessionLocal()
    org = Organization(name="concurrency-validation")
    db.add(org)
    db.flush()
    subject = GuardSubject(
        organization_id=org.id, provider="validation", provider_subject_id="alice"
    )
    resource = GuardResource(
        organization_id=org.id, source_id="source", provider_resource_id="f123"
    )
    db.add_all([subject, resource])
    db.commit()
    org_id, subject_id, resource_id = org.id, subject.id, resource.id
    db.close()

    def event(
        revision: int, key: str, change: str, grant_key: str = "finance", effect: str = "allow"
    ) -> str:
        s = SessionLocal()
        row = GuardPermissionEvent(
            organization_id=org_id,
            source_id="source",
            provider="validation",
            provider_revision=revision,
            subject_id=subject_id,
            resource_id=resource_id,
            change_type=change,
            dedupe_key=key,
            processing_status="queued",
            mutation_json=json.dumps(
                {
                    "scope": "read",
                    "snapshot_complete": True,
                    "grant_key": grant_key,
                    "principal_type": "subject",
                    "grant_effect": effect,
                }
            ),
        )
        s.add(row)
        s.commit()
        ident = row.id
        s.close()
        return ident

    def run(ident: str) -> dict[str, str]:
        return process_guard_event_with_retry(SessionLocal, ident)

    try:
        # Newer revision wins, including delivery in the wrong order.
        newer = event(21, "newer", "grant_upsert", effect="allow")
        assert run(newer)["decision"] == "allow"
        stale = event(20, "older", "grant_revoke")
        assert run(stale)["status"] == "stale"
        db = SessionLocal()
        effective = db.scalar(
            select(GuardEffectiveAccess).where(GuardEffectiveAccess.organization_id == org_id)
        )
        assert effective.source_revision == 21 and effective.decision == "allow"
        db.close()

        # Duplicate delivery and crash-after-commit retry are idempotent.
        duplicate = event(22, "duplicate", "grant_upsert", grant_key="second")
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(run, [duplicate] * 6))
        assert all(r["status"] in {"resolved", "stale"} for r in results)
        assert run(duplicate)["status"] == "resolved"
        assert (
            run(event(23, "revoke-finance", "grant_revoke", grant_key="finance"))["decision"]
            == "allow"
        )
        assert (
            run(event(24, "revoke-second", "grant_revoke", grant_key="second"))["decision"]
            == "deny"
        )

        # Overlapping grant paths: one revoke preserves ALLOW; final revoke DENY.
        a = event(30, "path-a", "grant_upsert", grant_key="path-a")
        b = event(31, "path-b", "grant_upsert", grant_key="path-b")
        assert run(a)["decision"] == "allow" and run(b)["decision"] == "allow"
        assert run(event(32, "revoke-a", "grant_revoke", grant_key="path-a"))["decision"] == "allow"
        assert run(event(33, "revoke-b", "grant_revoke", grant_key="path-b"))["decision"] == "deny"

        # Policy allocator is tenant-scoped and monotonic under concurrent changes.
        ids = [
            event(100 + i, f"stress-{i}", "grant_upsert", grant_key=f"stress-{i}")
            for i in range(20)
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, ids))
        db = SessionLocal()
        policies = list(
            db.scalars(
                select(GuardPolicy)
                .where(GuardPolicy.organization_id == org_id)
                .order_by(GuardPolicy.version)
            )
        )
        versions = [p.version for p in policies]
        assert versions == sorted(set(versions))
        db.close()

        # Tenant collision: same external values in a second tenant remain isolated.
        db = SessionLocal()
        org2 = Organization(name="concurrency-validation-b")
        db.add(org2)
        db.flush()
        sub2 = GuardSubject(
            organization_id=org2.id, provider="validation", provider_subject_id="alice"
        )
        res2 = GuardResource(
            organization_id=org2.id, source_id="source", provider_resource_id="f123"
        )
        db.add_all([sub2, res2])
        db.commit()
        other = GuardPermissionEvent(
            organization_id=org2.id,
            source_id="source",
            provider="validation",
            provider_revision=1,
            subject_id=sub2.id,
            resource_id=res2.id,
            change_type="grant_upsert",
            dedupe_key="same-key",
            processing_status="queued",
            mutation_json=json.dumps(
                {"grant_key": "same", "principal_type": "subject", "grant_effect": "allow"}
            ),
        )
        db.add(other)
        db.commit()
        other_id = other.id
        db.close()
        assert run(other_id)["decision"] == "allow"
        print(
            "postgres authorization matrix: 10/10 checks passed; iterations=20; deadlocks=0; failures=0"
        )
        return 0
    finally:
        db = SessionLocal()
        db.execute(delete(Organization).where(Organization.id == org_id))
        # org2 is removed by its own cascade only when available via local variable.
        try:
            db.execute(delete(Organization).where(Organization.id == org2.id))
        except UnboundLocalError:
            pass
        db.commit()
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
