"""D-01 regression: the API can verify, but never mint, source certificates.

Synthetic keys and synthetic evidence only. Nothing here certifies a real
SharePoint/OneDrive tenant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.api.accessproof_api.db import (
    Base, Organization, Project, SessionLocal, SourceConnection,
    SourceEffectiveCertification, engine,
)
from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.source_certification import (
    _source_scope, certificate_fields, certifier_trust_configured, effective_source_certified,
)
from packages.crypto.source_certificate import (
    EVIDENCE_SCHEMA, REQUIRED_CHECKS, VERIFIER_VERSION, CertificateError,
    issue_certificate, public_key_b64, sign_certificate, validate_evidence,
)

ROOT = Path(__file__).resolve().parents[2]
CREDENTIALS = {
    "tenant_id": "11111111-2222-3333-4444-555555555555",
    "drive_id": "drive-A", "test_root_item_id": "root",
    "site_id": "site-validated", "list_id": "list-validated",
}


def _evidence(org: str, source: str, profile: str, scope: str, *, now: datetime, overrides=None) -> dict:
    checks = [{
        "code": code, "status": "PASS",
        "observed_at": (now - timedelta(hours=1)).isoformat(),
        "artifact_sha256": hashlib.sha256(code.encode()).hexdigest(),
    } for code in REQUIRED_CHECKS]
    for code, patch in (overrides or {}).items():
        for check in checks:
            if check["code"] == code:
                check.update(patch)
    return {"schema": EVIDENCE_SCHEMA, "organization_id": org, "source_id": source,
            "profile": profile, "scope_digest": scope, "checks": checks}


@pytest.fixture()
def source():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="D-01 tenant")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        row = SourceConnection(
            organization_id=org.id, project_id=project.id, name="SharePoint",
            provider="sharepoint", boundary="root", status="connected",
            last_validated_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.flush()
        row.encrypted_credentials = api_module._secret_box.encrypt(json.dumps(CREDENTIALS))
        db.commit()
        yield db, row


def _store(db, row, record):
    cert = SourceEffectiveCertification(
        organization_id=row.organization_id, source_id=row.id,
        provider_profile=record["provider_profile"], scope_digest=record["scope_digest"],
        evidence_digest=record["evidence_digest"], verifier_version=record["verifier_version"],
        status="verified", certified_at=datetime.fromisoformat(record["certified_at"]),
        expires_at=datetime.fromisoformat(record["expires_at"]), signature=record["signature"],
    )
    db.add(cert)
    db.flush()
    return cert


def test_independently_issued_certificate_verifies_with_public_key_only(source, monkeypatch):
    db, row = source
    certifier = Ed25519PrivateKey.generate()
    profile, scope = _source_scope(row, CREDENTIALS)
    now = datetime.now(timezone.utc)
    record = issue_certificate(
        _evidence(row.organization_id, row.id, profile, scope, now=now),
        organization_id=row.organization_id, source_id=row.id, profile=profile,
        scope_digest=scope, private_key=certifier, key_id="certifier-1",
    )
    _store(db, row, record)
    monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON",
                       json.dumps({"certifier-1": public_key_b64(certifier)}))
    assert certifier_trust_configured()
    assert effective_source_certified(db, row, CREDENTIALS)
    # Signer material placed in the API environment disables verification.
    monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_PRIVATE_KEY", "anything")
    assert not certifier_trust_configured()
    assert not effective_source_certified(db, row, CREDENTIALS)


def test_api_environment_cannot_mint_a_certificate(source, monkeypatch):
    """Everything the API holds (DB write + public keys + legacy HMAC key) is insufficient."""
    db, row = source
    certifier = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    profile, scope = _source_scope(row, CREDENTIALS)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    legacy_key = "legacy-hmac-key-held-by-the-api-0123456789"
    monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_HMAC_KEY", legacy_key)
    monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON",
                       json.dumps({"certifier-1": public_key_b64(certifier)}))
    cert = SourceEffectiveCertification(
        organization_id=row.organization_id, source_id=row.id, provider_profile=profile,
        scope_digest=scope, evidence_digest="a" * 64, verifier_version=VERIFIER_VERSION,
        status="verified", certified_at=now, expires_at=now + timedelta(days=1), signature="x",
    )
    db.add(cert)
    db.flush()
    # 1. Old-style HMAC computed with a key the API holds.
    cert.signature = hmac.new(legacy_key.encode(), b"anything", hashlib.sha256).hexdigest()
    assert not effective_source_certified(db, row, CREDENTIALS)
    # 2. Signed by a key that is not pinned.
    cert.signature = sign_certificate(certificate_fields(cert), attacker, "certifier-1")
    assert not effective_source_certified(db, row, CREDENTIALS)
    # 3. Attacker pins its own key id alongside: not in the configured map.
    cert.signature = sign_certificate(certificate_fields(cert), attacker, "attacker")
    assert not effective_source_certified(db, row, CREDENTIALS)
    # 4. The genuine signature is bound to every field.
    cert.signature = sign_certificate(certificate_fields(cert), certifier, "certifier-1")
    assert effective_source_certified(db, row, CREDENTIALS)
    cert.expires_at = now + timedelta(days=2)
    assert not effective_source_certified(db, row, CREDENTIALS)
    cert.expires_at = now + timedelta(days=1)
    cert.verifier_version = "provider-live-v1"
    assert not effective_source_certified(db, row, CREDENTIALS)


@pytest.mark.parametrize("override", [
    {"PROVIDER_REVOKE_OBSERVED": {"status": "BLOCKED"}},
    {"GATEWAY_INFLIGHT_REVOCATION_DENIED": {"status": "NOT_TESTED"}},
    {"EMPLOYEE_OIDC_POSITIVE_IDENTITY": {"status": "FAIL"}},
    {"CACHED_ANSWER_REUSE_DENIED": {"artifact_sha256": "not-a-digest"}},
    {"PROVENANCE_TAMPER_REJECTED": {"observed_at": "2020-01-01T00:00:00+00:00"}},
])
def test_issuer_refuses_incomplete_or_stale_evidence(override):
    now = datetime.now(timezone.utc)
    evidence = _evidence("org", "src", "sharepoint_list_item_effective", "d" * 64,
                         now=now, overrides=override)
    with pytest.raises(CertificateError):
        validate_evidence(evidence, organization_id="org", source_id="src",
                          profile="sharepoint_list_item_effective", scope_digest="d" * 64)


def test_issuer_refuses_missing_check_and_scope_mismatch():
    now = datetime.now(timezone.utc)
    evidence = _evidence("org", "src", "sharepoint_list_item_effective", "d" * 64, now=now)
    evidence["checks"] = [c for c in evidence["checks"] if c["code"] != "GATEWAY_ROUTE_UNAUTHORIZED_DENIED"]
    with pytest.raises(CertificateError, match="REQUIRED_CHECK_MISSING"):
        validate_evidence(evidence, organization_id="org", source_id="src",
                          profile="sharepoint_list_item_effective", scope_digest="d" * 64)
    full = _evidence("org", "src", "sharepoint_list_item_effective", "d" * 64, now=now)
    with pytest.raises(CertificateError, match="EVIDENCE_SCOPE_MISMATCH"):
        validate_evidence(full, organization_id="org", source_id="OTHER",
                          profile="sharepoint_list_item_effective", scope_digest="d" * 64)
    with pytest.raises(CertificateError, match="VALIDITY"):
        issue_certificate(full, organization_id="org", source_id="src",
                          profile="sharepoint_list_item_effective", scope_digest="d" * 64,
                          private_key=Ed25519PrivateKey.generate(), key_id="k",
                          validity=timedelta(days=30))


def test_api_package_never_imports_signing():
    """The API source must not call the certifier's signing function."""
    api_dir = ROOT / "apps" / "api" / "accessproof_api"
    offenders = [p.name for p in api_dir.glob("*.py")
                 if "sign_certificate" in p.read_text() or "issue_certificate" in p.read_text()]
    assert offenders == []


def test_certifier_cli_keygen_is_private_and_issue_refuses_empty_evidence(tmp_path):
    key = tmp_path / "certifier.pem"
    out = subprocess.run([sys.executable, str(ROOT / "scripts/issue_source_certificate.py"),
                          "keygen", "--private-key", str(key)],
                         capture_output=True, text=True, check=True)
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert "certifier-1" in json.loads(out.stdout.strip())
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({"schema": EVIDENCE_SCHEMA, "organization_id": "o",
                                    "source_id": "s", "profile": "p", "scope_digest": "d",
                                    "checks": []}))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/issue_source_certificate.py"),
                             "issue", "--private-key", str(key), "--evidence", str(evidence),
                             "--organization-id", "o", "--source-id", "s", "--profile", "p",
                             "--scope-digest", "d"], capture_output=True, text=True)
    assert result.returncode == 2 and "NOT ISSUED" in result.stderr and result.stdout == ""
