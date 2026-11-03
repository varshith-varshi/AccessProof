"""Offline checks for scripts/live/employee_identity.py (no Microsoft calls)."""
import importlib.util
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location("employee_identity", Path(__file__).resolve().parents[2] / "scripts/live/employee_identity.py")
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)


@pytest.mark.parametrize("status,location,expected", [
    (200, None, "ALLOW"), (302, "https://neuralmatrix093.sharepoint.com/x", "ALLOW"),
    (302, "https://evil.example/x", "AMBIGUOUS"), (403, None, "DENY"), (404, None, "DENY"),
    (401, None, "AMBIGUOUS"), (500, None, "AMBIGUOUS"),
])
def test_delegated_decision_maps_sharepoint_answers(status, location, expected):
    def handler(request):
        assert request.headers["Authorization"] == "Bearer user-token"
        return httpx.Response(status, headers={"location": location} if location else {})
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        assert ei.delegated_decision(http, "drive", "item", "user-token")[0] == expected


def test_expected_matrix_is_the_certified_fixture():
    assert ei.EXPECTED["alice"] == {"finance_alice.txt": "ALLOW", "engineering_bob.txt": "DENY", "shared_control.txt": "ALLOW"}
    assert ei.EXPECTED["bob"] == {"finance_alice.txt": "DENY", "engineering_bob.txt": "ALLOW", "shared_control.txt": "ALLOW"}


def test_summary_never_contains_raw_subject():
    s = ei._summary({"sub": "pairwise-secret-sub", "oid": "o", "tid": "t", "iss": "i", "aud": "a"})
    assert "pairwise-secret-sub" not in str(s) and len(s["sub_sha256"]) == 64


def test_auth_code_flow_uses_pkce_state_and_nonce(monkeypatch):
    """Drive the loopback callback with a fake browser; never contacts Microsoft."""
    import base64, hashlib, threading, urllib.parse, urllib.request

    s = ei.Session("alice", "client-id")
    captured = {}

    def fake_post(url, data=None, **kw):
        captured["token_request"] = data
        return httpx.Response(400, json={"error": "synthetic_stop"}, request=httpx.Request("POST", url))
    monkeypatch.setattr(s.http, "post", fake_post)
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a))))

    def browser():
        import time
        for _ in range(200):
            urls = [p.strip() for p in printed if p.strip().startswith("https://")]
            if urls:
                break
            time.sleep(0.02)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(urls[0]).query))
        captured["authorize"] = q
        urllib.request.urlopen(q["redirect_uri"] + "/?" + urllib.parse.urlencode({"code": "c0de", "state": q["state"]}))
    threading.Thread(target=browser, daemon=True).start()
    with pytest.raises(ei.IdentityFailure, match="CODE_REDEMPTION_FAILED"):
        s.auth_code_sign_in(timeout_s=20)
    q, tr = captured["authorize"], captured["token_request"]
    assert q["code_challenge_method"] == "S256" and q["response_type"] == "code"
    assert q["redirect_uri"].startswith("http://127.0.0.1:") and q["nonce"] and q["state"]
    assert base64.urlsafe_b64encode(hashlib.sha256(tr["code_verifier"].encode()).digest()).rstrip(b"=").decode() == q["code_challenge"]
    assert tr["code"] == "c0de" and tr["redirect_uri"] == q["redirect_uri"] and "client_secret" not in tr


def test_auth_code_flow_rejects_state_mismatch(monkeypatch):
    import threading, urllib.parse, urllib.request
    s = ei.Session("alice", "client-id")
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a))))

    def browser():
        import time
        for _ in range(200):
            urls = [p.strip() for p in printed if p.strip().startswith("https://")]
            if urls:
                break
            time.sleep(0.02)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(urls[0]).query))
        urllib.request.urlopen(q["redirect_uri"] + "/?" + urllib.parse.urlencode({"code": "c", "state": "forged"}))
    threading.Thread(target=browser, daemon=True).start()
    with pytest.raises(ei.IdentityFailure, match="STATE_MISMATCH"):
        s.auth_code_sign_in(timeout_s=20)


def test_serve_fails_on_bad_socket_before_asking_anyone_to_sign_in(tmp_path, monkeypatch):
    """A local socket failure must never waste a completed employee sign-in."""
    import argparse
    asked = []
    monkeypatch.setattr(ei.Session, "auth_code_sign_in", lambda self, **k: asked.append("signin"))
    deep = tmp_path / ("d" * 120)
    deep.mkdir(mode=0o700)
    args = argparse.Namespace(socket=str(deep / "alice.sock"), actor="alice", client_id="c",
                              flow="auth-code", signin_timeout=5, max_hours=0.0)
    import os
    before = os.umask(0o022); os.umask(before)
    with pytest.raises(OSError):
        ei.serve(args)
    assert asked == []
    after = os.umask(0o022); os.umask(after)
    assert after == before  # the restrictive socket umask never leaks


def test_probe_without_positive_control_is_inconclusive(tmp_path, monkeypatch):
    """D-21: all-403 (e.g. insufficient token scope) must never pass deny cells."""
    import json
    monkeypatch.setattr(ei, "fetch", lambda sock, what: json.dumps({"actor": "alice"}) if what == "claims" else "t")
    monkeypatch.setattr(ei, "item_refs", lambda http: ("d", {n: n for n in ei.EXPECTED["alice"]}))
    monkeypatch.setattr(ei, "delegated_decision", lambda http, d, i, t: ("DENY", 403))
    out = tmp_path / "o.json"
    rc = ei.probe(type("A", (), {"socket": "s", "actor": "alice", "out": str(out)})())
    body = json.loads(out.read_text())
    assert rc == 1 and body["pass"] is False and body["positive_control"] is False
    assert {r["actual"] for r in body["results"]} == {"INCONCLUSIVE_NO_POSITIVE_CONTROL"}
