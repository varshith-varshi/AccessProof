"""Production certification gates: never PASS without genuine evidence.

Synthetic state only. A synthetic certificate here is signed by a TEST key
inside the test process to exercise verification code; it is not, and can
never become, a production certificate (production pins the real certifier's
public key, and the private key never exists in the product).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api import gateway_presence
from apps.api.accessproof_api.db import (
    AIApplication, Base, GuardAuditEvent, GuardPolicy, GuardRegistration, Organization, Project,
    ProviderSyncCursor, SessionLocal, SourceConnection, SourceEffectiveCertification, engine,
)
from apps.api.accessproof_api.production_gates import evaluate
from apps.api.accessproof_api.source_certification import _source_scope, certificate_fields
from packages.crypto.source_certificate import (
    EVIDENCE_SCHEMA, REQUIRED_CHECKS, VERIFIER_VERSION, evidence_digest, public_key_b64, sign_certificate,
)

TEST_CERTIFIER = Ed25519PrivateKey.generate()
CREDS = {"tenant_id": "11111111-2222-3333-4444-555555555555", "drive_id": "drive", "test_root_item_id": "root",
         "site_id": "site", "list_id": "list"}


def _today_state():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        org = Organization(name="sai")
        db.add(org)
        db.flush()
        api_module.set_tenant_context(db, org.id)
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, name="SharePoint",
                                  provider="sharepoint", boundary="root", status="connected",
                                  last_validated_at=now,
                                  encrypted_credentials=api_module._secret_box.encrypt(json.dumps(CREDS)))
        guard = GuardRegistration(organization_id=org.id, name="g", status="enrolled", enrolled_at=now,
                                  health="degraded", active_policy_version=8, last_heartbeat_at=now - timedelta(hours=2))
        db.add_all([source, guard])
        db.flush()
        db.add(GuardPolicy(organization_id=org.id, policy_key="k", version=8, mode="protect", decision="allow",
                           source_id=source.id, subject_id="s", resource_id="r"))
        row = AIApplication(organization_id=org.id, application_id="sharepoint-rag", name="RAG",
                            guard_id=guard.id, source_id=source.id, adapter_type="accessproof-gateway",
                            mode="protect_pending")
        db.add(row)
        db.commit()
        return org.id, row.id, source.id, guard.id


def test_todays_state_is_not_verified_for_the_documented_reasons():
    org, _, _, _ = _today_state()
    with SessionLocal() as db:
        report = evaluate(db, organization_id=org, application_id="sharepoint-rag")
    assert report["verdict"] == "SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED"
    gates = report["gates"]
    assert gates["C_SHAREPOINT_SOURCE"]["checks"]["independent_certificate_valid"]["status"] == "FAIL"
    assert gates["D_GUARD"]["checks"]["guard_online"]["status"] == "FAIL"
    assert gates["D_GUARD"]["checks"]["guard_security_ready"]["status"] == "FAIL"
    assert gates["E_GATEWAY"]["checks"]["gateway_connected"]["status"] == "FAIL"
    assert gates["F_LAYER1"]["status"] == "FAIL" and gates["G_LAYER2"]["status"] != "PASS"
    assert gates["H_REVOCATION_AND_CACHE"]["status"] == "BLOCKED"
    assert gates["A_INFRASTRUCTURE"]["status"] == "BLOCKED"  # no host facts supplied
    assert gates["J_ACTIVATION"]["checks"]["protect_acknowledged_by_guard"]["status"] == "FAIL"


def test_each_gate_flips_only_on_genuine_evidence(tmp_path, monkeypatch):
    org, row_id, source_id, guard_id = _today_state()
    now = datetime.now(timezone.utc)
    monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON",
                       json.dumps({"test-certifier": public_key_b64(TEST_CERTIFIER)}))
    with SessionLocal() as db:
        api_module.set_tenant_context(db, org)
        source = db.get(SourceConnection, source_id)
        profile, scope = _source_scope(source, CREDS)
        evidence = {"schema": EVIDENCE_SCHEMA, "organization_id": org, "source_id": source_id, "profile": profile,
                    "scope_digest": scope, "checks": [{"code": c, "status": "PASS", "observed_at": now.isoformat(),
                                                       "artifact_sha256": "a" * 64} for c in REQUIRED_CHECKS]}
        cert = SourceEffectiveCertification(organization_id=org, source_id=source_id, provider_profile=profile,
                                            scope_digest=scope, evidence_digest=evidence_digest(evidence),
                                            verifier_version=VERIFIER_VERSION, status="verified",
                                            certified_at=now.replace(microsecond=0),
                                            expires_at=now.replace(microsecond=0) + timedelta(days=7), signature="x")
        db.add(cert)
        db.flush()
        cert.signature = sign_certificate(certificate_fields(cert), TEST_CERTIFIER, "test-certifier")
        for kind in ("acl", "directory"):
            db.add(ProviderSyncCursor(organization_id=org, source_id=source_id, sync_kind=kind, status="connected",
                                      last_success_at=now, provider="sharepoint"))
        guard = db.get(GuardRegistration, guard_id)
        guard.last_heartbeat_at, guard.health = now, "healthy"
        row = db.get(AIApplication, row_id)
        record, _ = gateway_presence.issue_installation(db, row, deployment_sha256="d" * 64, route_sha256="c" * 64)
        record.last_heartbeat_at, record.last_reported_ready, record.last_sequence = now, True, 1
        for layer, result in (("layer1", "allow"), ("layer1", "block"), ("layer2", "allow")):
            db.add(GuardAuditEvent(organization_id=org, guard_id=guard_id, event_id=f"{layer}-{result}",
                                   application_id="sharepoint-rag", subject_id="s", request_id="r",
                                   layer=layer, result=result, reason="TEST", created_at=now))
        db.commit()
    good = tmp_path / "evidence.json"
    good.write_text(json.dumps(evidence))
    facts = {k: True for k in ("api_healthy", "worker_running", "db_healthy", "redis_healthy", "web_healthy",
                               "migration_at_head", "rollback_available")}
    with SessionLocal() as db:
        report = evaluate(db, organization_id=org, application_id="sharepoint-rag",
                          host_facts=facts, evidence_path=good)
    g = report["gates"]
    for gate in ("A_INFRASTRUCTURE", "C_SHAREPOINT_SOURCE", "D_GUARD", "F_LAYER1", "G_LAYER2", "H_REVOCATION_AND_CACHE"):
        assert g[gate]["status"] == "PASS", (gate, g[gate])
    assert g["E_GATEWAY"]["checks"]["gateway_connected"]["status"] == "PASS"
    assert g["E_GATEWAY"]["checks"]["route_certified"]["status"] == "FAIL"   # no real route certificate
    assert g["B_IDENTITY"]["status"] == "FAIL"                                # no verified employee mappings
    assert report["verdict"] == "SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED"

    # Streamed (in-memory) evidence — used when the container rootfs is
    # read-only — is judged exactly like a file, including tampering.
    with SessionLocal() as db:
        streamed = evaluate(db, organization_id=org, application_id="sharepoint-rag",
                            host_facts=facts, evidence=evidence)
        streamed_bad = evaluate(db, organization_id=org, application_id="sharepoint-rag",
                                host_facts=facts, evidence={**evidence, "profile": "other"})
    assert streamed["gates"]["C_SHAREPOINT_SOURCE"] == g["C_SHAREPOINT_SOURCE"]
    assert streamed_bad["gates"]["C_SHAREPOINT_SOURCE"]["checks"]["certificate_evidence_matches"]["status"] == "FAIL"

    # Tampered or incomplete evidence never passes, even with a valid certificate.
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps({**evidence, "profile": "other"}))
    skipped = tmp_path / "skipped.json"
    skipped.write_text(json.dumps({**evidence, "checks": [dict(c, status="NOT_TESTED") if c["code"] ==
                                                          "GATEWAY_INFLIGHT_REVOCATION_DENIED" else c
                                                          for c in evidence["checks"]]}))
    for path in (tampered, skipped):
        with SessionLocal() as db:
            again = evaluate(db, organization_id=org, application_id="sharepoint-rag",
                             host_facts=facts, evidence_path=path)
        assert again["gates"]["C_SHAREPOINT_SOURCE"]["checks"]["certificate_evidence_matches"]["status"] == "FAIL"
        assert again["gates"]["H_REVOCATION_AND_CACHE"]["status"] == "BLOCKED"
