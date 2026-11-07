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
    SourceEffectiveCertification, AIApplication, GuardRegistration,
)
from apps.api.accessproof_api import app as api_module
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from apps.api.accessproof_api.source_certification import (
    _source_scope, certificate_fields, effective_source_certified,
)
from packages.crypto.source_certificate import VERIFIER_VERSION, public_key_b64, sign_certificate

_CERTIFIER_KEY = Ed25519PrivateKey.generate()


def _certificate_signature(cert, _unused_key=None):
    """Signed by the independent certifier, outside the API process."""
    return sign_certificate(certificate_fields(cert), _CERTIFIER_KEY, "certifier-test")


def test_signed_certification_requires_exact_profile_source_and_fresh_evidence(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    key = json.dumps({"certifier-test": public_key_b64(_CERTIFIER_KEY)})
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
            verifier_version=VERIFIER_VERSION, status="verified",
            certified_at=now, expires_at=now + timedelta(days=1), signature="ed25519:certifier-test:" + "A" * 86,
        )
        db.add(cert)
        db.flush()
        # An admin can't flip a row/status to mint valid evidence.
        assert not effective_source_certified(db, source, credentials)
        monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON", key)
        assert not effective_source_certified(db, source, credentials)
        cert.signature = _certificate_signature(cert, key)
        assert effective_source_certified(db, source, credentials)
        # A signed certificate does not override separate provider identity,
        # source synchronization, Gateway readiness or owner approval checks.
        # The four manual customer challenges are post-activation diagnostics.
        checks = {check["code"]: check["ok"] for check in api_module._automatic_activation_checklist(db, app_row)}
        assert checks["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"] is True
        assert "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED" not in checks
        for code in (
            "LAYER1_INTEGRATION_CONFIRMED", "LAYER2_INTEGRATION_CONFIRMED",
            "PROVENANCE_READY", "BUFFERED_RESPONSE_GATE_READY",
            "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED",
        ):
            assert code not in checks
        # Independent provider proof and identity controls must remain.
        assert "PRODUCTION_OIDC_READY" in checks
        assert "PERMISSION_SOURCE_USABLE" in checks
        # Production SharePoint requires both independent signed certification
        # and a separate operator release gate, never just an admin toggle.
        from apps.api.accessproof_api.config import Settings
        source.provider = "sharepoint"
        profile, digest = _source_scope(source, credentials)
        cert.provider_profile, cert.scope_digest = profile, digest
        cert.signature = _certificate_signature(cert, key)
        assert effective_source_certified(db, source, credentials)
        monkeypatch.setattr(api_module, "settings", Settings(
            env="production", microsoft_certified_protect=False,
        ))
        denied = {check["code"]: check["ok"] for check in api_module._automatic_activation_checklist(db, app_row)}
        assert denied["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"] is True
        assert denied["V1_PROVIDER_SCOPE"] is False
        monkeypatch.setattr(api_module, "settings", Settings(
            env="production", microsoft_certified_protect=True,
        ))
        released = {check["code"]: check["ok"] for check in api_module._automatic_activation_checklist(db, app_row)}
        assert released["V1_PROVIDER_SCOPE"] is True
        assert "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED" not in released
        # D-18: a certificate alone never satisfies employee OIDC readiness;
        # a healthy, heartbeating Guard is also required ...
        assert released["PRODUCTION_OIDC_READY"] is False
        guard = GuardRegistration(organization_id=org.id, name="certified-guard", status="enrolled",
                                  health="healthy", enrolled_at=datetime.now(timezone.utc),
                                  last_heartbeat_at=datetime.now(timezone.utc))
        db.add(guard)
        db.flush()
        app_row.guard_id = guard.id
        with_guard = {check["code"]: check["ok"] for check in api_module._automatic_activation_checklist(db, app_row)}
        # ... and with both, a certified SharePoint source CAN become OIDC-ready
        # (previously impossible for any Microsoft source).
        assert with_guard["PRODUCTION_OIDC_READY"] is True
        guard.health = "degraded"
        assert {c["code"]: c["ok"] for c in api_module._automatic_activation_checklist(db, app_row)}["PRODUCTION_OIDC_READY"] is False
        guard.health = "healthy"
        cert.signature = "ed25519:certifier-test:" + "A" * 86
        tampered = {check["code"]: check["ok"] for check in api_module._automatic_activation_checklist(db, app_row)}
        assert tampered["V1_PROVIDER_SCOPE"] is False
        assert tampered["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"] is False
        # Without a valid certificate, a healthy Guard never makes Microsoft OIDC-ready.
        assert tampered["PRODUCTION_OIDC_READY"] is False
        app_row.guard_id = None
        # Restore the original synthetic proof for the remaining tamper tests.
        source.provider = "microsoft365"
        profile, digest = _source_scope(source, credentials)
        cert.provider_profile, cert.scope_digest = profile, digest
        cert.signature = _certificate_signature(cert, key)
        monkeypatch.setattr(api_module, "settings", Settings())
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
        monkeypatch.delenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON")
        assert not effective_source_certified(db, source, credentials)
        assert len(list(db.scalars(select(SourceEffectiveCertification)))) == 1


def test_microsoft_ambiguous_drive_cannot_claim_sharepoint_or_onedrive():
    source = SourceConnection(id="source", organization_id="org", provider="microsoft365", boundary="root")
    assert _source_scope(source, {"tenant_id": "11111111-2222-3333-4444-555555555555", "drive_id": "drive-A", "test_root_item_id": "root"}) is None

def test_validation_first_sharepoint_is_eligible_without_certificate_but_never_after_revocation(monkeypatch):
    from apps.api.accessproof_api.config import Settings

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    credentials = {
        "tenant_id": "11111111-2222-3333-4444-555555555555",
        "drive_id": "drive-A", "test_root_item_id": "root",
        "site_id": "site-valid", "list_id": "library-valid",
    }
    monkeypatch.setattr(api_module, "settings", Settings(
        env="production", microsoft_certified_protect=True,
        microsoft_validation_first=True,
    ))
    with SessionLocal() as db:
        org = Organization(name="Validation-first isolated")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Validation project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="sharepoint", name="Test SharePoint",
            boundary="root", status="connected",
            last_validated_at=datetime.now(timezone.utc),
        )
        db.add(source)
        db.flush()
        source.encrypted_credentials = api_module._secret_box.encrypt(json.dumps(credentials))
        row = AIApplication(
            organization_id=org.id, application_id="first-validation-rag",
            name="First validation", adapter_type="accessproof-gateway",
            source_id=source.id, adapter_contract_version="accessproof.rag/v1",
        )
        db.add(row)
        db.flush()
        assert api_module._microsoft_validation_first_eligible(db, source, credentials)
        checks = {c["code"]: c for c in api_module._automatic_activation_checklist(db, row)}
        cert = checks["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"]
        assert cert["ok"] is False
        assert cert["required_for_activation"] is False
        assert checks["V1_PROVIDER_SCOPE"]["ok"] is True
        # The missing certificate is only an informational status; the lack of
        # live Guard, identity/permissions and Gateway still blocks activation.
        blockers = api_module._activation_failed_checks(list(checks.values()))
        assert "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" not in {c["code"] for c in blockers}
        assert "GATEWAY_LIVE_AND_ENFORCEMENT_READY" in {c["code"] for c in blockers}
        # Creating a certificate row, even a REVOKED/invalid one, must forbid
        # falling back to first-time validation and re-opening its ACL.
        profile, digest = _source_scope(source, credentials)
        db.add(SourceEffectiveCertification(
            organization_id=org.id, source_id=source.id,
            provider_profile=profile, scope_digest=digest,
            evidence_digest="a" * 64, verifier_version=VERIFIER_VERSION,
            status="revoked", certified_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=2),
            signature="ed25519:invalid:" + "A" * 86,
        ))
        db.flush()
        assert not api_module._microsoft_validation_first_eligible(db, source, credentials)
        revoked = {c["code"]: c for c in api_module._automatic_activation_checklist(db, row)}
        assert revoked["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"]["required_for_activation"] is True
        assert revoked["V1_PROVIDER_SCOPE"]["ok"] is False
        source.provider = "onedrive"
        assert not api_module._microsoft_validation_first_eligible(db, source, credentials)
        db.rollback()


def test_validation_first_protection_state_never_claims_independent_certification():
    from apps.api.accessproof_api.protection_state import classify_protection_state

    checks = [
        {"code": "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", "ok": False,
         "required_for_activation": False},
        {"code": "GATEWAY_LIVE_AND_ENFORCEMENT_READY", "ok": True},
    ]
    common = {
        "adapter_protect_capable": True, "has_guard": True,
        "has_source": True, "guard_revoked": False,
        "source_disconnected": False, "certification_expired": False,
    }
    assert classify_protection_state(checks, "protect", route_certified=False, **common) == (
        "PROTECTED_MANUAL_VALIDATION_PENDING"
    )
    checks[-1]["ok"] = False
    assert classify_protection_state(checks, "protect", route_certified=False, **common) == "DEGRADED"
