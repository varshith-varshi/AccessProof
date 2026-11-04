"""Remote route certification decision logic: HTTP success alone never
certifies, unobservable paths fail, and any binding change invalidates."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.gateway.accessproof_gateway import remote_route_certification as rrc

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
KEY = Ed25519PrivateKey.generate()


def binding(**over):
    b = {f: f"value-{f}" for f in rrc.BINDING_FIELDS}
    b.update(over)
    return rrc.make_binding(b)


def passing():
    return [{"code": c, "status": "PASS", "evidence": {k: [{"ok": True}] for k in kinds}}
            for c, kinds in rrc.REQUIRED_CHECKS.items()]


def test_all_checks_with_evidence_certify_and_verify():
    cert = rrc.issue(binding(), passing(), KEY, key_id="k", now=NOW)
    assert cert["status"] == "CERTIFIED"
    assert rrc.verify_certificate(cert, KEY.public_key(), binding(), now=NOW + timedelta(hours=1)) == (True, "VALID", [])


def test_http_success_without_independent_evidence_does_not_certify():
    checks = passing()
    checks[0]["evidence"] = {"http": [{"status": 200}]}           # only an HTTP status
    status, failing = rrc.evaluate(checks)
    assert status == "NOT_CERTIFIED" and failing[0]["why"].startswith("EVIDENCE_MISSING")


@pytest.mark.parametrize("status", ["UNOBSERVABLE", "FAIL", "NOT_OBSERVED", None])
def test_any_unobserved_or_failed_check_blocks(status):
    checks = passing()
    checks[3]["status"] = status
    assert rrc.evaluate(checks)[0] == "NOT_CERTIFIED"


def test_missing_check_blocks():
    assert rrc.evaluate(passing()[:-1])[0] == "NOT_CERTIFIED"


def test_not_certified_result_never_verifies():
    checks = passing(); checks[5]["status"] = "FAIL"
    cert = rrc.issue(binding(), checks, KEY, key_id="k", now=NOW)
    assert rrc.verify_certificate(cert, KEY.public_key(), binding(), now=NOW)[1] == "NOT_CERTIFIED"


@pytest.mark.parametrize("field", ["rag_code_sha256", "gateway_tls_cert_sha256", "gateway_exposure", "route_path",
                                   "framework_version", "gateway_audit_public_key", "source_scope_digest", "guard_image",
                                   "client_id", "application_id"])
def test_any_security_configuration_change_invalidates(field):
    cert = rrc.issue(binding(), passing(), KEY, key_id="k", now=NOW)
    ok, code, changed = rrc.verify_certificate(cert, KEY.public_key(), binding(**{field: "changed"}), now=NOW)
    assert not ok and code == "INVALIDATED_CONFIGURATION_CHANGED" and changed == [field]


def test_expiry_signature_and_binding_tamper():
    cert = rrc.issue(binding(), passing(), KEY, key_id="k", now=NOW)
    assert rrc.verify_certificate(cert, KEY.public_key(), binding(), now=NOW + rrc.MAX_AGE)[1] == "EXPIRED"
    forged = {**cert, "binding": {**cert["binding"], "route_path": "/other"}}
    assert rrc.verify_certificate(forged, KEY.public_key(), forged["binding"], now=NOW)[1] == "SIGNATURE_INVALID"
    assert rrc.verify_certificate(cert, Ed25519PrivateKey.generate().public_key(), binding(), now=NOW)[1] == "SIGNATURE_INVALID"


def test_unobservable_binding_cannot_be_built():
    values = {f: "x" for f in rrc.BINDING_FIELDS}
    values["gateway_tls_cert_sha256"] = None
    with pytest.raises(rrc.RouteCertificationError, match="BINDING_UNOBSERVABLE"):
        rrc.make_binding(values)
