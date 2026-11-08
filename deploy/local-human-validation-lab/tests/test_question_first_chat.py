"""Question-first protected RAG; real network/Microsoft tokens never used."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

BASE = Path(__file__).resolve().parents[1]


@pytest.fixture
def console(tmp_path, monkeypatch):
    private = tmp_path / ".ap-id"
    private.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(tmp_path))
    name = "ap_operator_console_question_first_tests"
    spec = importlib.util.spec_from_file_location(name, BASE / "operator_console.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        monkeypatch.setattr(module, "_runtime_readiness", lambda: {"ready_to_test": True})
        monkeypatch.setattr(module, "_verified_claims", lambda actor: {"state": "SIGNED_IN", "actor": actor})
        monkeypatch.setattr(module, "_socket_get", lambda actor, what: "fake-employee-token-for-test")
        yield module
    finally:
        sys.modules.pop(name, None)


def make_client(module, monkeypatch, outcome="allow"):
    posted = []

    class Gateway:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def post(self, url, *, json, headers):
            posted.append((url, json, headers))
            if outcome == "deny":
                return httpx.Response(403, json={"detail": "ACCESSPROOF_AUTHORIZATION_DENIED"})
            return httpx.Response(200, json={
                "mode": "protected", "security": "GATEWAY_ALLOWED",
                "answer": "Authorized content only",
                "accessproof": {"decision": "allow", "decision_id": "test-decision"},
            })
    monkeypatch.setattr(module.httpx, "Client", Gateway)
    client = TestClient(module.app, base_url=module.ORIGIN)
    client.cookies.set(module.COOKIE, module.SESSION)
    return client, posted


def test_plain_question_has_no_selected_document_and_uses_gateway(console, monkeypatch):
    client, posted = make_client(console, monkeypatch)
    result = client.post("/api/chat", json={
        "actor": "alice", "question": "What does the engineering policy say?"
    }, headers={"origin":console.ORIGIN,"x-accessproof-human-test":"1"})
    assert result.status_code == 200, result.text
    data=result.json()
    assert data["retrieval_mode"] == "automatic"
    assert data["expected"] == "NOT_PREDETERMINED"
    assert data["outcome"] == "ALLOWED"
    assert "document_name" not in posted[0][1]
    assert posted[0][1] == {"question": "What does the engineering policy say?"}
    assert posted[0][2]["Authorization"] == "Bearer fake-employee-token-for-test"


def test_denied_automatic_retrieval_never_returns_answer(console, monkeypatch):
    client, posted = make_client(console, monkeypatch, "deny")
    response = client.post("/api/chat", json={
        "actor": "bob", "question": "Summarize Finance records"
    }, headers={"origin":console.ORIGIN,"x-accessproof-human-test":"1"})
    assert response.status_code == 200
    data=response.json()
    assert data["retrieval_mode"]=="automatic"
    assert data["outcome"]=="DENIED"
    assert data["answer"] is None
    assert data["expected"]=="NOT_PREDETERMINED"
    assert "document_name" not in posted[0][1]


def test_manual_canary_requires_explicit_selection_and_still_uses_gateway(console, monkeypatch):
    client, posted = make_client(console, monkeypatch, "deny")
    response = client.post("/api/chat", json={
        "actor": "bob", "question": "What is in it?",
        "document_name": "finance_alice.txt"
    }, headers={"origin":console.ORIGIN,"x-accessproof-human-test":"1"})
    assert response.status_code == 200
    assert response.json()["retrieval_mode"] == "diagnostic"
    assert response.json()["expected"] == "DENY"
    assert posted[0][1]["document_name"] == "finance_alice.txt"
    assert response.json()["answer"] is None


def test_unknown_document_rejected_before_gateway(console, monkeypatch):
    client, posted = make_client(console, monkeypatch)
    response = client.post("/api/chat", json={
        "actor":"alice", "question":"Hi there",
        "document_name":"other-company-private.docx"
    }, headers={"origin":console.ORIGIN,"x-accessproof-human-test":"1"})
    assert response.status_code == 400
    assert posted == []


def test_missing_identity_rejected_before_gateway(console, monkeypatch):
    monkeypatch.setattr(console,"_verified_claims",lambda actor: (_ for _ in ()).throw(RuntimeError("not signed in")))
    client, posted = make_client(console, monkeypatch)
    response = client.post("/api/chat", json={
        "actor":"alice", "question":"Summarize the policy"
    }, headers={"origin":console.ORIGIN,"x-accessproof-human-test":"1"})
    assert response.status_code == 409
    assert posted == []


def test_ui_default_document_selection_is_empty(console):
    html=(BASE/"operator_console.html").read_text()
    js=(BASE/"operator_console.js").read_text()
    assert 'id="diagnostics"' in html
    assert 'id="document" required' not in html
    assert 'value="finance_alice.txt"' not in html
    assert '$("document").value = "";' in js
    assert 'else "NOT_PREDETERMINED"' in (BASE/"operator_console.py").read_text()
