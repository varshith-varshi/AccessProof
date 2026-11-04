"""Signed, hash-chained Gateway audit: every protected request (allow, deny,
failed application auth) is recorded; tampering is detected; no release
without an audit record."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.gateway.accessproof_gateway.gateway_audit import (GatewayAuditError, GatewayAuditLog,
                                                            verify_log)
from tests.security import test_gateway_all_response_routes as routes
from tests.security.test_gateway_all_response_routes import _answer_body, _gateway
from tests.security.test_gateway_remote_exposure import ROUTE, _remote_env, _signed
from tests.security.test_multisource_guard_v2 import _token


@pytest.fixture()
def audited(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    log = GatewayAuditLog(str(tmp_path / "audit.jsonl"), key, "gw-test")
    real = routes.create_app
    monkeypatch.setattr(routes, "create_app", lambda *a, **k: real(*a, **{**k, "audit_log": log}))
    return log, key


def _records(log, key):
    return verify_log(log.path.read_bytes().splitlines(), key.public_key())


def test_allow_deny_and_auth_failure_are_signed_and_chained(tmp_path, monkeypatch, audited):
    log, key = audited
    _remote_env(monkeypatch)
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    body = {**_answer_body(chunk, stream=False), "request_id": "req-allow"}
    raw, h = _signed(body, "alice")
    raw_b, h_b = _signed({**body, "request_id": "req-deny"}, "bob")
    raw_x, h_x = _signed({**body, "request_id": "req-forged"}, "alice", secret=b"x" * 40)
    with gateway:
        assert gateway.post(ROUTE, content=raw, headers=h).status_code == 200
        deny = gateway.post(ROUTE, content=raw_b, headers=h_b)
        assert gateway.post(ROUTE, content=raw_x, headers=h_x).status_code == 401
    recs = {r["request_id"]: r for r in _records(log, key)}
    allow = recs["req-allow"]
    assert allow["http_status"] == 200 and allow["decision"] == "allow" and allow["decision_id"]
    assert allow["client_id"] == "rag-prod" and len(allow["response_sha256"]) == 64
    assert recs["req-deny"]["http_status"] == deny.status_code and recs["req-deny"]["http_status"] >= 400
    assert recs["req-forged"]["reason"] == "CLIENT_AUTHENTICATION_FAILED" and recs["req-forged"]["http_status"] == 401
    # No content is written: no token, question or document text.
    text = log.path.read_text()
    assert _token("alice") not in text and chunk.content not in text and "What is available" not in text


def test_tampering_is_detected(tmp_path, monkeypatch, audited):
    log, key = audited
    _remote_env(monkeypatch)
    gateway, _p, _o, chunk, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        for i in range(3):
            raw, h = _signed({**_answer_body(chunk, stream=False), "request_id": f"r{i}"}, "alice")
            gateway.post(ROUTE, content=raw, headers=h)
    lines = log.path.read_bytes().splitlines()
    edited = json.loads(lines[1]); edited["http_status"] = 200 if edited["http_status"] != 200 else 403
    with pytest.raises(GatewayAuditError, match="SIGNATURE"):
        verify_log([lines[0], json.dumps(edited).encode(), lines[2]], key.public_key())
    with pytest.raises(GatewayAuditError, match="CHAIN"):
        verify_log([lines[0], lines[2]], key.public_key())                # deleted record
    with pytest.raises(GatewayAuditError):
        verify_log(lines, Ed25519PrivateKey.generate().public_key())      # other key


def test_no_release_without_audit(tmp_path, monkeypatch, audited):
    log, _key = audited
    _remote_env(monkeypatch)
    gateway, _p, _o, chunk, *_ = _gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(log, "append", lambda **k: (_ for _ in ()).throw(OSError("disk full")))
    raw, h = _signed(_answer_body(chunk, stream=False), "alice")
    with gateway:
        r = gateway.post(ROUTE, content=raw, headers=h)
    assert r.status_code == 503 and r.json()["detail"] == "GATEWAY_AUDIT_UNAVAILABLE"
    assert "choices" not in r.text


def test_audit_requires_both_settings(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_AUDIT_LOG", "/tmp/x.jsonl")
    monkeypatch.delenv("ACCESSPROOF_GATEWAY_AUDIT_KEY_FILE", raising=False)
    with pytest.raises(GatewayAuditError):
        GatewayAuditLog.from_env()
