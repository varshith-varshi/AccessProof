"""Cross-host Gateway: application authentication, integrity, replay, rate limit,
fail-closed startup. Runs through the real Gateway + real Guard HTTP app."""
from __future__ import annotations

import base64
import json
import time

import pytest

from apps.gateway.accessproof_gateway.remote_access import RemoteAccess, RemoteAccessConfigError
from packages.rag_core.request_signing import SignatureError, sign, signed_headers
from tests.security.test_gateway_all_response_routes import _answer_body, _gateway
from tests.security.test_multisource_guard_v2 import _token

SECRET = b"s" * 40
OTHER = b"o" * 40
ROUTE = "/v1/chat/completions"


def _remote_env(monkeypatch, rate=600):
    keys = {"rag-prod": base64.urlsafe_b64encode(SECRET).decode().rstrip("="),
            "rag-other": base64.urlsafe_b64encode(OTHER).decode().rstrip("=")}
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_EXPOSURE", "remote")
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON", json.dumps(keys))
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_TLS_TERMINATION", "proxy")
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_CLIENT_RATE_PER_MINUTE", str(rate))


def _signed(body: dict, employee: str, *, client="rag-prod", secret=SECRET, **kw):
    raw = json.dumps(body).encode()
    auth = "Bearer " + _token(employee)
    headers = {"Authorization": auth, "Content-Type": "application/json",
               **signed_headers(client, secret, "POST", ROUTE, raw, auth, **kw)}
    return raw, headers


def test_signed_request_from_remote_rag_is_released(tmp_path, monkeypatch):
    _remote_env(monkeypatch)
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    raw, headers = _signed(_answer_body(chunk, stream=False), "alice")
    with gateway:
        assert gateway.get("/health/exposure").json() == {"exposure": "remote", "tls": "proxy", "client_authentication": "required"}
        r = gateway.post(ROUTE, content=raw, headers=headers)
    assert r.status_code == 200, r.text
    assert observed["llm_count"] == 1


@pytest.mark.parametrize("attack", ["unsigned", "wrong_secret", "unknown_client", "tampered_body",
                                    "swapped_employee_token", "expired", "wrong_path"])
def test_unauthenticated_or_tampered_requests_never_reach_guard_or_model(tmp_path, monkeypatch, attack):
    _remote_env(monkeypatch)
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    body = _answer_body(chunk, stream=False)
    raw, headers = _signed(body, "alice")
    if attack == "unsigned":
        headers = {"Authorization": headers["Authorization"], "Content-Type": "application/json"}
    elif attack == "wrong_secret":
        raw, headers = _signed(body, "alice", secret=b"x" * 40)
    elif attack == "unknown_client":
        raw, headers = _signed(body, "alice", client="rag-unknown")
    elif attack == "tampered_body":
        tampered = json.loads(raw)
        tampered["retrieved_resources"][0]["resource_id"] = "someone-elses-document"
        raw = json.dumps(tampered).encode()
    elif attack == "swapped_employee_token":
        headers["Authorization"] = "Bearer " + _token("bob")     # signature was over Alice's token
    elif attack == "expired":
        raw, headers = _signed(body, "alice", now=int(time.time()) - 3600)
    elif attack == "wrong_path":
        headers["X-AccessProof-Signature"] = sign(SECRET, "POST", "/v1/cache/authorize", int(headers["X-AccessProof-Timestamp"]),
                                                  headers["X-AccessProof-Nonce"], raw, headers["Authorization"])
    with gateway:
        r = gateway.post(ROUTE, content=raw, headers=headers)
    assert r.status_code == 401
    assert observed["llm_count"] == 0 and observed["guard_paths"] == []


def test_replayed_request_is_rejected(tmp_path, monkeypatch):
    _remote_env(monkeypatch)
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    raw, headers = _signed(_answer_body(chunk, stream=False), "alice")
    with gateway:
        assert gateway.post(ROUTE, content=raw, headers=headers).status_code == 200
        again = gateway.post(ROUTE, content=raw, headers=headers)
    assert again.status_code == 401 and again.json()["detail"] == "CLIENT_REQUEST_REPLAYED"
    assert observed["llm_count"] == 1


def test_per_client_rate_limit(tmp_path, monkeypatch):
    _remote_env(monkeypatch, rate=2)
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        codes = [gateway.post(ROUTE, content=r, headers=h).status_code
                 for r, h in (_signed(_answer_body(chunk, stream=False), "alice") for _ in range(3))]
        raw, headers = _signed(_answer_body(chunk, stream=False), "alice", client="rag-other", secret=OTHER)
        other = gateway.post(ROUTE, content=raw, headers=headers)
    assert codes == [200, 200, 429]
    assert other.status_code == 200          # limits are per client


def test_valid_signature_but_unauthorized_employee_is_still_denied_by_guard(tmp_path, monkeypatch):
    _remote_env(monkeypatch)
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    raw, headers = _signed(_answer_body(chunk, stream=False), "bob")
    with gateway:
        r = gateway.post(ROUTE, content=raw, headers=headers)
    assert r.status_code in {403, 503} and observed["llm_count"] == 0


@pytest.mark.parametrize("env", [
    {"ACCESSPROOF_GATEWAY_EXPOSURE": "remote"},                                            # no keys, no TLS
    {"ACCESSPROOF_GATEWAY_EXPOSURE": "remote", "ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON": '{"c":"' + "a" * 50 + '"}'},  # no TLS
    {"ACCESSPROOF_GATEWAY_EXPOSURE": "remote", "ACCESSPROOF_GATEWAY_TLS_TERMINATION": "proxy",
     "ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON": '{"c":"c2hvcnQ"}'},                             # 5-byte secret
    {"ACCESSPROOF_GATEWAY_EXPOSURE": "public"},
])
def test_remote_exposure_refuses_to_start_without_tls_and_strong_client_keys(monkeypatch, env):
    for k in ("ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON", "ACCESSPROOF_GATEWAY_TLS_TERMINATION",
              "ACCESSPROOF_GATEWAY_TLS_CERT_FILE", "ACCESSPROOF_GATEWAY_TLS_KEY_FILE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(RemoteAccessConfigError):
        RemoteAccess.from_env()


def test_local_exposure_is_unchanged(monkeypatch):
    monkeypatch.delenv("ACCESSPROOF_GATEWAY_EXPOSURE", raising=False)
    assert RemoteAccess.from_env().remote is False


def test_replay_cache_fails_closed_when_full():
    ra = RemoteAccess(exposure="remote", secrets={"rag-prod": SECRET}, max_nonces=1)
    def call():
        raw = b"{}"
        h = signed_headers("rag-prod", SECRET, "POST", ROUTE, raw, "Bearer t")
        return ra.check(method="POST", path=ROUTE, headers={**h, "authorization": "Bearer t"}, body=raw)
    call()
    with pytest.raises(SignatureError, match="REPLAY_CACHE_FULL"):
        call()
