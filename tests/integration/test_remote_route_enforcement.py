"""Production enforcement of remote RAG route certificates.

Synthetic certificates signed by a TEST key pinned only inside this process;
production pins the real offline certifier key.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api import remote_route_enforcement as rre
from apps.api.accessproof_api.db import AIApplication, SessionLocal
from apps.api.accessproof_api.production_gates import evaluate
from apps.gateway.accessproof_gateway import remote_route_certification as rrc
from tests.integration.test_production_gates import _today_state

KEY = Ed25519PrivateKey.generate()
KID = "test-certifier"


def _pub(key):
    return base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                                  serialization.PublicFormat.Raw)).rstrip(b"=").decode()


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON", json.dumps({KID: _pub(KEY)}))
    org, row_id, source_id, guard_id = _today_state()
    e = {"org": org, "row_id": row_id, "source_id": source_id, "sessions": []}
    yield e
    for db in e["sessions"]:
        db.rollback(); db.close()


def binding(env, **over):
    b = {f: f"v-{f}" for f in rrc.BINDING_FIELDS}
    b.update(tenant_id=env["org"], application_id="sharepoint-rag", source_id=env["source_id"],
             route_url="http://rag-1.internal:8187", framework="langchain")
    b.update(over)
    return rrc.make_binding(b)


def passing():
    return [{"code": c, "status": "PASS", "evidence": {k: [1] for k in kinds}} for c, kinds in rrc.REQUIRED_CHECKS.items()]


def cert(env, key=KEY, checks=None, now=None, **over):
    return rrc.issue(binding(env, **over), checks or passing(), key, key_id=KID, now=now)


def _db(env):
    for old in env["sessions"]:
        old.close()
    db = SessionLocal()
    env["sessions"].append(db)
    api_module.set_tenant_context(db, env["org"])
    return db, db.get(AIApplication, env["row_id"])


def test_valid_certificate_imports_and_is_certified(env):
    db, row = _db(env)
    rre.import_certificate(db, row, cert(env)); db.commit()
    st = rre.status(db, row)
    assert st["applicable"] and st["certified"] and st["routes"][0]["state"] == "VALID"


@pytest.mark.parametrize("bad,code", [
    ("other_key", "SIGNATURE_INVALID"), ("other_tenant", "BINDING_NOT_THIS_APPLICATION"),
    ("other_app", "BINDING_NOT_THIS_APPLICATION"), ("other_source", "BINDING_NOT_THIS_APPLICATION"),
    ("not_certified", "NOT_CERTIFIED"), ("expired", "VALIDITY_INVALID"), ("tampered_binding", "SIGNATURE_INVALID"),
    ("schema", "SCHEMA_UNSUPPORTED")])
def test_import_rejects(env, bad, code):
    db, row = _db(env)
    if bad == "other_key":
        c = cert(env, key=Ed25519PrivateKey.generate())
    elif bad == "other_tenant":
        c = cert(env, tenant_id="another-org")
    elif bad == "other_app":
        c = cert(env, application_id="another-app")
    elif bad == "other_source":
        c = cert(env, source_id="another-source")
    elif bad == "not_certified":
        checks = passing(); checks[0]["status"] = "FAIL"; c = cert(env, checks=checks)
    elif bad == "expired":
        c = cert(env, now=datetime.now(timezone.utc) - timedelta(days=8))
    elif bad == "tampered_binding":
        c = cert(env); c["binding"]["route_url"] = "http://evil:1"; c["fingerprint"] = rrc.fingerprint(c["binding"])
    else:
        c = cert(env); c["schema"] = "accessproof.source-certificate/v1"
    with pytest.raises(rre.RemoteRouteError, match=code):
        rre.import_certificate(db, row, c)


def test_configuration_change_attestation_invalidates_and_blocks_reimport(env):
    db, row = _db(env)
    c = cert(env); rre.import_certificate(db, row, c); db.commit()
    live_same = c["binding"]
    rre.apply_attestation(db, row, rrc.issue_attestation(c, live_same, KEY, key_id=KID,
                                                         now=datetime.now(timezone.utc) + timedelta(seconds=1)))
    assert rre.status(db, row)["certified"]
    changed = {**live_same, "rag_runtime_config_sha256": "changed"}
    rre.apply_attestation(db, row, rrc.issue_attestation(c, changed, KEY, key_id=KID,
                                                         now=datetime.now(timezone.utc) + timedelta(seconds=2)))
    db.commit()
    st = rre.status(db, row)
    assert not st["certified"] and st["routes"][0]["state"] == "INVALIDATED"
    assert "rag_runtime_config_sha256" in st["routes"][0]["reason"]
    with pytest.raises(rre.RemoteRouteError, match="PREVIOUSLY_INVALIDATED"):
        rre.import_certificate(db, row, c)                       # the same (old) certificate stays refused
    # Configuration reverted and a NEW full certification run issued afterwards: importable.
    fresh = cert(env, now=datetime.now(timezone.utc) + timedelta(seconds=5))
    assert fresh["fingerprint"] == c["fingerprint"]
    rre.import_certificate(db, row, fresh, now=datetime.now(timezone.utc) + timedelta(seconds=6)); db.commit()
    assert rre.status(db, row, now=datetime.now(timezone.utc) + timedelta(seconds=7))["certified"]


def test_attestation_forgery_staleness_and_replay(env):
    db, row = _db(env)
    c = cert(env); rre.import_certificate(db, row, c)
    with pytest.raises(rre.RemoteRouteError, match="SIGNATURE"):
        rre.apply_attestation(db, row, rrc.issue_attestation(c, c["binding"], Ed25519PrivateKey.generate(), key_id=KID))
    with pytest.raises(rre.RemoteRouteError, match="NOT_FRESH"):
        rre.apply_attestation(db, row, rrc.issue_attestation(c, c["binding"], KEY, key_id=KID,
                                                             now=datetime.now(timezone.utc) - timedelta(hours=2)))
    att = rrc.issue_attestation(c, c["binding"], KEY, key_id=KID, now=datetime.now(timezone.utc) + timedelta(seconds=1))
    rre.apply_attestation(db, row, att)
    with pytest.raises(rre.RemoteRouteError, match="REPLAYED"):
        rre.apply_attestation(db, row, att)


def test_stale_attestation_expiry_and_revocation_fail(env):
    db, row = _db(env)
    c = cert(env); rre.import_certificate(db, row, c); db.commit()
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    assert rre.status(db, row, now=later)["routes"][0]["state"] == "ATTESTATION_STALE"
    assert rre.status(db, row, now=datetime.now(timezone.utc) + timedelta(days=8))["routes"][0]["state"] in ("EXPIRED", "ATTESTATION_STALE")
    rre.revoke(db, row, c["fingerprint"]); db.commit()
    assert rre.status(db, row)["routes"][0]["state"] == "REVOKED"
    with pytest.raises(rre.RemoteRouteError, match="REVOKED_BY_OWNER"):
        rre.import_certificate(db, row, cert(env, now=datetime.now(timezone.utc) + timedelta(seconds=5)))


def test_certifier_trust_not_configured_means_not_certified(env, monkeypatch):
    db, row = _db(env)
    rre.import_certificate(db, row, cert(env)); db.commit()
    monkeypatch.delenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON")
    assert not rre.status(db, row)["certified"]


def test_gate_e_enforces_remote_routes_only_when_present(env):
    facts = {k: True for k in ("api_healthy", "worker_running", "db_healthy", "redis_healthy", "web_healthy",
                               "migration_at_head", "rollback_available")}
    with SessionLocal() as db:
        g = evaluate(db, organization_id=env["org"], application_id="sharepoint-rag", host_facts=facts)["gates"]
    assert "remote_routes_certified" not in g["E_GATEWAY"]["checks"]             # no remote route: unchanged
    db, row = _db(env)
    c = cert(env); rre.import_certificate(db, row, c); db.commit(); db.close()
    with SessionLocal() as db:
        g = evaluate(db, organization_id=env["org"], application_id="sharepoint-rag", host_facts=facts)["gates"]
    assert g["E_GATEWAY"]["checks"]["remote_routes_certified"]["status"] == "PASS"
    db, row = _db(env)
    rre.revoke(db, row, c["fingerprint"]); db.commit(); db.close()
    with SessionLocal() as db:
        g = evaluate(db, organization_id=env["org"], application_id="sharepoint-rag", host_facts=facts)["gates"]
    assert g["E_GATEWAY"]["checks"]["remote_routes_certified"]["status"] == "FAIL"
    assert g["E_GATEWAY"]["status"] == "FAIL"


def test_new_certificate_for_same_route_supersedes(env):
    db, row = _db(env)
    first = cert(env); rre.import_certificate(db, row, first)
    second = cert(env, framework_version="2"); rre.import_certificate(db, row, second); db.commit()
    st = rre.status(db, row)
    assert st["certified"] and sorted(r["state"] for r in st["routes"]) == ["SUPERSEDED", "VALID"]


def test_api_enforcement_does_not_depend_on_gateway_package():
    """The production API image ships packages/ and apps/api only (r38 defect)."""
    import ast
    from pathlib import Path
    for mod in ("apps/api/accessproof_api/remote_route_enforcement.py", "apps/api/accessproof_api/production_gates.py"):
        tree = ast.parse(Path(mod).read_text())
        imported = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module]
        assert not [m for m in imported if m.startswith("apps.gateway")], mod


def test_invalidation_reason_fits_column_when_many_fields_change(env):
    """Found live on PostgreSQL: a reason longer than status_reason (100) rolled the
    invalidation back, leaving a changed configuration VALID. SQLite ignores lengths."""
    from apps.api.accessproof_api.db import RemoteRouteCertificate
    db, row = _db(env)
    c = cert(env); rre.import_certificate(db, row, c); db.commit()
    changed = {**c["binding"], **{f: "changed" for f in ("tenant_id", "gateway_tls_cert_sha256", "gateway_audit_public_key",
                                                         "source_id", "source_scope_digest", "rag_runtime_config_sha256")}}
    rec = rre.apply_attestation(db, row, rrc.issue_attestation(c, changed, KEY, key_id=KID,
                                                               now=datetime.now(timezone.utc) + timedelta(seconds=1)))
    limit = RemoteRouteCertificate.__table__.c.status_reason.type.length
    assert rec.status == "invalidated" and len(rec.status_reason) <= limit
    assert rec.status_reason.startswith("CONFIGURATION_CHANGED:")
