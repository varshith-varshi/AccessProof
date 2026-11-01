"""Durable orchestration may observe proof but must never create fake certification."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import (
    Base, AIApplication, GuardRegistration, Organization, SourceConnection,
    Project, VerificationRun, VerificationStep, VerificationOutbox, VerificationEvent,
)
from apps.api.accessproof_api.verification_engine import (
    start_or_resume, reconcile_checks, describe, safe_step_state,
)


@pytest.fixture
def setup_db():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        org = Organization(name="r11-org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="r11-project")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id,
                                  provider="sharepoint", name="test", boundary="test-library")
        guard = GuardRegistration(organization_id=org.id, name="guard",
                                  enrolled_at=datetime.now(timezone.utc), active_policy_version=8)
        db.add_all([source, guard])
        db.flush()
        app = AIApplication(organization_id=org.id, application_id="sharepoint-rag-staging",
                            name="RAG", source_id=source.id, guard_id=guard.id,
                            adapter_type="accessproof-gateway")
        db.add(app)
        db.commit()
        yield db, app
    engine.dispose()



def test_installation_idempotent_and_superseding(setup_db):
    db, app = setup_db
    first = start_or_resume(db, app, deployment="a" * 64, route="b" * 64)
    db.commit()
    repeated = start_or_resume(db, app, deployment="a" * 64, route="b" * 64)
    assert repeated.id == first.id
    assert db.scalar(select(VerificationOutbox).where(VerificationOutbox.run_id == first.id))
    changed = start_or_resume(db, app, deployment="c" * 64, route="b" * 64)
    db.commit()
    assert changed.id != first.id
    assert first.superseded_at is not None
    assert db.scalar(select(VerificationRun).where(VerificationRun.id == changed.id)).state == "QUEUED"


def test_unverified_checks_require_admin_and_never_activate_protect(setup_db):
    db, app = setup_db
    run = start_or_resume(db, app, deployment="a" * 64, route="b" * 64)
    checks = [
        {"code": "GUARD_POLICY_INSTALLED", "ok": True},
        {"code": "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", "ok": False,
         "reason": "Scope unavailable"},
        {"code": "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED", "ok": False},
    ]
    reconcile_checks(db, run, checks)
    db.commit()
    snapshot = describe(db, run)
    assert snapshot["state"] == "WAITING_FOR_AUTHORIZATION"
    assert snapshot["checks_passed"] == 1
    assert snapshot["checks_total"] == 3
    assert snapshot["protect_activated"] is False
    assert snapshot["production_certification"] is False
    assert any(s["state"] == "WAITING_FOR_ADMIN" for s in snapshot["steps"])
    assert db.scalar(select(VerificationStep).where(VerificationStep.run_id == run.id)).evidence_id is None
    before = db.query(VerificationEvent).count()
    reconcile_checks(db, run, checks)
    db.commit()
    assert db.query(VerificationEvent).count() == before  # no event spam on unchanged state
    assert app.mode != "protect"


def test_checklist_cannot_be_empty_malformed_or_duplicate(setup_db):
    db, app = setup_db
    run = start_or_resume(db, app, deployment="a" * 64, route="b" * 64)
    for checks in ([], [{"code": "X", "ok": 1}], [{"code": "X", "ok": True}] * 2):
        with pytest.raises(ValueError):
            reconcile_checks(db, run, checks)


def test_security_gate_categories_are_not_inferred_from_container_health():
    assert safe_step_state("MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", False) == "WAITING_FOR_ADMIN"
    assert safe_step_state("LAYER2_INTEGRATION_CONFIRMED", False) == "WAITING_FOR_CHALLENGE"
    assert safe_step_state("CUSTOMER_RAG_CUTOVER_NOT_VERIFIED", False) == "WAITING_FOR_CUTOVER"
    assert safe_step_state("GUARD_HEARTBEAT_RECENT", False) == "RETRY_SCHEDULED"
    assert safe_step_state("GUARD_POLICY_INSTALLED", True) == "SATISFIED"


def test_worker_reconciles_installation_and_persists_outbox_across_cycles(setup_db, monkeypatch):
    from sqlalchemy.orm import sessionmaker
    from apps.api.accessproof_api import gateway_pairing, verification_engine
    from apps.api.accessproof_api import app as api_module

    db, app = setup_db
    local_factory = sessionmaker(bind=db.get_bind(), autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(verification_engine, "SessionLocal", local_factory)
    monkeypatch.setattr(gateway_pairing, "status", lambda **_kwargs: {
        "state": "installation_reported_unverified",
        "deployment_sha256": "a" * 64,
        "route_sha256": "b" * 64,
    })
    monkeypatch.setattr(api_module, "_automatic_activation_checklist", lambda _db, _app: [
        {"code": "GUARD_POLICY_INSTALLED", "ok": True, "reason": None},
        {"code": "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
         "ok": False, "reason": "Live tenant scope missing"},
    ])
    assert verification_engine.run_worker_cycle(max_runs=2) == 1
    rows = list(db.scalars(select(VerificationRun)))
    assert len(rows) == 1
    db.refresh(rows[0])
    assert rows[0].state == "WAITING_FOR_AUTHORIZATION"
    assert verification_engine.run_worker_cycle(max_runs=2) == 0  # next check scheduled
    assert db.query(VerificationOutbox).count() == 1
    assert db.query(VerificationStep).count() == 2
    assert app.mode != "protect"
