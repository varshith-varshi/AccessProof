import pytest
from sqlalchemy import delete

from apps.api.accessproof_api.db import AuditEvent, Base, SessionLocal, engine


def test_audit_event_orm_update_and_delete_are_rejected_but_explicit_bulk_policy_purge_works():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        row = AuditEvent(organization_id="org-1", action="created", target_type="test")
        db.add(row)
        db.commit()
        audit_id = row.id

    with SessionLocal() as db:
        row = db.get(AuditEvent, audit_id)
        row.action = "tampered"
        with pytest.raises(RuntimeError, match="append-only"):
            db.commit()
        db.rollback()

    with SessionLocal() as db:
        row = db.get(AuditEvent, audit_id)
        db.delete(row)
        with pytest.raises(RuntimeError, match="append-only"):
            db.commit()
        db.rollback()

    # Policy-driven retention/organization deletion uses an explicit bulk DELETE;
    # this is the intentional escape hatch and is separately audited by callers.
    with SessionLocal() as db:
        db.execute(delete(AuditEvent).where(AuditEvent.id == audit_id))
        db.commit()
        assert db.get(AuditEvent, audit_id) is None
