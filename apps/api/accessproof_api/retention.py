from __future__ import annotations
from typing import Any, cast
from sqlalchemy.engine import CursorResult

from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import AuditEvent, EvidenceItem, Report, RetentionPolicy, TestRun


def get_or_create_policy(db: Session, organization_id: str) -> RetentionPolicy:
    row = db.get(RetentionPolicy, organization_id)
    if row is None:
        row = RetentionPolicy(organization_id=organization_id)
        db.add(row)
        db.flush()
    return row


def apply_retention(
    db: Session, organization_id: str, *, now: datetime | None = None
) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    policy = get_or_create_policy(db, organization_id)

    evidence_cutoff = now - timedelta(days=policy.detailed_evidence_days)
    report_cutoff = now - timedelta(days=policy.report_days)
    audit_cutoff = now - timedelta(days=policy.audit_days)

    old_run_ids = list(
        db.scalars(
            select(TestRun.id).where(
                TestRun.organization_id == organization_id,
                TestRun.created_at < evidence_cutoff,
            )
        )
    )
    evidence_deleted = 0
    results_redacted = 0
    if old_run_ids:
        result = db.execute(
            delete(EvidenceItem).where(
                EvidenceItem.organization_id == organization_id,
                EvidenceItem.run_id.in_(old_run_ids),
            )
        )
        evidence_deleted = int(cast(CursorResult[Any], result).rowcount or 0)
        runs = list(
            db.scalars(
                select(TestRun).where(
                    TestRun.id.in_(old_run_ids), TestRun.organization_id == organization_id
                )
            )
        )
        for run in runs:
            if run.result_json is not None:
                run.result_json = None
                results_redacted += 1

    result = db.execute(
        delete(Report).where(
            Report.organization_id == organization_id, Report.generated_at < report_cutoff
        )
    )
    reports_deleted = int(cast(CursorResult[Any], result).rowcount or 0)
    result = db.execute(
        delete(AuditEvent).where(
            AuditEvent.organization_id == organization_id, AuditEvent.created_at < audit_cutoff
        )
    )
    audit_deleted = int(cast(CursorResult[Any], result).rowcount or 0)

    return {
        "evidence_deleted": evidence_deleted,
        "run_results_redacted": results_redacted,
        "reports_deleted": reports_deleted,
        "audit_events_deleted": audit_deleted,
    }
