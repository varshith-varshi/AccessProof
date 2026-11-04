"""Route certificate state must expire, never guess, and never widen scope."""
from __future__ import annotations

import json

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from apps.api.accessproof_api.db import (
    AIApplication, Base, GuardRegistration, Organization, Project, RAGRouteChallenge,
    SourceConnection,
    SessionLocal, engine,
)
from apps.api.accessproof_api.route_certification import (
    CERTIFICATE_TTL, describe_route_certificate, route_configuration_fingerprint,
)


def _setup(adapter: str = "accessproof-gateway"):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Organization(id="org-1", name="Route Org"))
        db.flush()  # PostgreSQL enforces the FK; no ORM relationship orders inserts
        guard = GuardRegistration(
            organization_id="org-1", name="guard", status="enrolled",
            active_policy_version=2, enrolled_at=now, health="healthy",
        )
        db.add(guard)
        db.flush()
        project = Project(organization_id="org-1", name="Route project")
        db.add(project)
        db.flush()
        db.add(SourceConnection(id="source-1", organization_id="org-1", project_id=project.id,
                                name="Drive", provider="google-drive", boundary="root"))
        db.flush()  # PostgreSQL enforces the source FK
        row = AIApplication(
            organization_id="org-1", application_id="rag", name="RAG",
            guard_id=guard.id, source_id="source-1", adapter_type=adapter,
            adapter_contract_version="accessproof.rag/v1",
        )
        db.add(row)
        db.commit()
        return row.id, guard.id


def _challenge(row_id: str, guard_id: str, *, status: str, verified_at, cutover_at=None,
               fingerprint: str | None = None, nonce: str = "1", policy_version: int | None = 2):
    return RAGRouteChallenge(
        result_json=json.dumps({} if policy_version is None
                               else {"guard_policy_version_at_verification": policy_version}),
        organization_id="org-1", application_row_id=row_id, guard_id=guard_id,
        source_id="source-1", nonce_digest=nonce * 64,
        configuration_fingerprint=fingerprint or "0" * 64, status=status,
        deployment_sha256="a" * 64, route_sha256="b" * 64,
        verified_at=verified_at, cutover_at=cutover_at,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def test_non_gateway_adapter_is_not_applicable_and_has_no_certificate():
    row_id, _ = _setup(adapter="generic-python")
    with SessionLocal() as db:
        certificate = describe_route_certificate(db, db.get(AIApplication, row_id))
    assert certificate["status"] == "NOT_APPLICABLE"
    assert certificate["applicable"] is False
    assert certificate["certified"] is False
    assert certificate["reason"] == "ADAPTER_IS_NOT_REFERENCE_GATEWAY"


def test_missing_tested_expired_and_certified_states():
    row_id, guard_id = _setup()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        fingerprint = route_configuration_fingerprint(row)
        missing = describe_route_certificate(db, row, now=now)
        assert missing["status"] == "MISSING"
        assert missing["configuration_fingerprint"] == fingerprint
        assert missing["verified_at"] is None

        db.add(_challenge(
            row_id, guard_id, status="tested", verified_at=now - timedelta(minutes=5),
            fingerprint=fingerprint,
        ))
        db.commit()
        tested = describe_route_certificate(db, row, now=now)
        assert tested["status"] == "TESTED_NOT_CUTOVER"
        assert tested["certified"] is False
        assert tested["cutover_at"] is None
        assert tested["evidence_level"] == "LOCAL_INTEGRATION_VERIFIED"
        assert tested["expires_at"] is not None

        challenge = db.scalar(select(RAGRouteChallenge))
        challenge.status = "cutover_verified"
        challenge.cutover_at = now - timedelta(minutes=4)
        db.commit()
        certified = describe_route_certificate(db, row, now=now)
        assert certified["status"] == "CERTIFIED"
        assert certified["certified"] is True
        assert certified["certificate_id"] == challenge.id
        assert certified["independent_certification"] is False

        challenge.verified_at = now - CERTIFICATE_TTL - timedelta(seconds=1)
        db.commit()
        expired = describe_route_certificate(db, row, now=now)
        assert expired["status"] == "EXPIRED"
        assert expired["certified"] is False
        assert expired["reason"] == "CERTIFICATE_EXPIRED_OR_CONFIGURATION_CHANGED"
        assert expired["age_seconds"] > CERTIFICATE_TTL.total_seconds()


def test_guard_policy_advance_keeps_route_certified_but_rollback_or_config_change_invalidates():
    """D-26: ACL changes advance the Guard policy version constantly in a live
    tenant; they do not change the certified route. A policy ROLLBACK (Guard
    reset/re-enrolment), a configuration change, or a certificate without a
    recorded verification version is not certified."""
    row_id, guard_id = _setup()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        fingerprint = route_configuration_fingerprint(row)
        db.add(_challenge(
            row_id, guard_id, status="cutover_verified",
            verified_at=now - timedelta(minutes=5), cutover_at=now - timedelta(minutes=5),
            fingerprint=fingerprint, policy_version=2,
        ))
        db.commit()
        assert describe_route_certificate(db, row, now=now)["status"] == "CERTIFIED"

        guard = db.get(GuardRegistration, guard_id)
        guard.active_policy_version = 7                       # ordinary ACL changes
        db.commit()
        assert describe_route_certificate(db, row, now=now)["status"] == "CERTIFIED"

        guard.active_policy_version = 1                       # rollback below the verified state
        db.commit()
        rolled_back = describe_route_certificate(db, row, now=now)
        assert rolled_back["status"] == "EXPIRED" and rolled_back["certified"] is False

        guard.active_policy_version = 7
        row.adapter_contract_version = "changed-contract"     # configuration change
        db.commit()
        changed = describe_route_certificate(db, row, now=now)
        assert changed["status"] == "EXPIRED" and changed["certified"] is False


def test_certificate_without_recorded_policy_version_is_not_certified():
    row_id, guard_id = _setup()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        db.add(_challenge(
            row_id, guard_id, status="cutover_verified",
            verified_at=now - timedelta(minutes=5), cutover_at=now - timedelta(minutes=5),
            fingerprint=route_configuration_fingerprint(row), policy_version=None,
        ))
        db.commit()
        assert describe_route_certificate(db, row, now=now)["certified"] is False
