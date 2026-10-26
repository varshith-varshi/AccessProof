"""A signed source-specific certification is necessary, never sufficient, for Protect.

Synthetic cryptographic contract test only; no live SharePoint/OneDrive coverage
is certified or issued by the product.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from sqlalchemy import select
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, Organization, Project, SourceConnection,
    SourceEffectiveCertification, AIApplication,
)
from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.source_certification import (
    _source_scope, _certificate_signature, effective_source_certified,
)


def test_signed_certification_requires_exact_profile_source_and_fresh_evidence(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    key = "synthetic-private-hmac-key-0123456789-abcd"
    credentials = {
        "tenant_id": "11111111-2222-3333-4444-555555555555",
        "drive_id": "drive-A", "test_root_item_id": "root",
        "site_id": "site-validated", "list_id": "list-validated",
    }
    with SessionLocal() as db:
        org = Organization(name="Certificate isolated")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Only proof scope")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            name="MS source", provider="microsoft365", boundary="root",
            status="connected", last_validated_at=datetime.now(timezone.utc),
        )
        other = SourceConnection(
            organization_id=org.id, project_id=project.id,
            name="Other source", provider="microsoft365", boundary="root",
            status="connected", last_validated_at=datetime.now(timezone.utc),
        )
        db.add_all([source, other])
        db.flush()
        source.encrypted_credentials = api_module._secret_box.encrypt(json.dumps(credentials))
        app_row = AIApplication(organization_id=org.id, application_id="ms-synthetic", name="MS synthetic", source_id=source.id)
        db.add(app_row)
        db.flush()
        profile, digest = _source_scope(source, credentials)
        now = datetime.now(timezone.utc)
        cert = SourceEffectiveCertification(
            organization_id=source.organization_id, source_id=source.id,
            provider_profile=profile, scope_digest=digest,
            evidence_digest=hashlib.sha256(b"synthetic-independent-provider-validation-payload").hexdigest(),
            verifier_version="provider-live-v1", status="verified",
            certified_at=now, expires_at=now + timedelta(days=1), signature="0" * 64,
        )
        db.add(cert)
        db.flush()
        # An admin can't flip a row/status to mint valid evidence.
        assert not effective_source_certified(db, source, credentials)
        monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_HMAC_KEY", key)
        assert not effective_source_certified(db, source, credentials)
        cert.signature = _certificate_signature(cert, key)
        assert effective_source_certified(db, source, credentials)
        # A complete signed record changes only the Microsoft-specific check.
        # A RAG challenge, Guard enrollment, live provider verification and
        # all other independent readiness checks are still required.
        checks = {check["code"]: check["ok"] for check in api_module._automatic_activation_checklist(db, app_row)}
        assert checks["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"] is True
        assert checks["CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED"] is False
        assert not effective_source_certified(db, other, credentials)
        assert not effective_source_certified(db, source, {**credentials, "drive_id": "another-drive"})
        assert not effective_source_certified(db, source, {**credentials, "list_id": "other-library"})
        assert not effective_source_certified(db, source, {**credentials, "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
        assert not effective_source_certified(db, source, {**credentials, "test_root_item_id": "other-root"})
        assert not effective_source_certified(db, source, {"tenant_id": credentials["tenant_id"], "drive_id": "drive-A", "test_root_item_id": "root"})
        cert.expires_at = now - timedelta(seconds=1)
        assert not effective_source_certified(db, source, credentials)
        cert.expires_at = now + timedelta(days=1)
        cert.evidence_digest = "a" * 64
        assert not effective_source_certified(db, source, credentials)
        cert.evidence_digest = hashlib.sha256(b"synthetic-independent-provider-validation-payload").hexdigest()
        monkeypatch.delenv("ACCESSPROOF_SOURCE_CERTIFICATION_HMAC_KEY")
        assert not effective_source_certified(db, source, credentials)
        assert len(list(db.scalars(select(SourceEffectiveCertification)))) == 1


def test_microsoft_ambiguous_drive_cannot_claim_sharepoint_or_onedrive():
    source = SourceConnection(id="source", organization_id="org", provider="microsoft365", boundary="root")
    assert _source_scope(source, {"tenant_id": "11111111-2222-3333-4444-555555555555", "drive_id": "drive-A", "test_root_item_id": "root"}) is None
