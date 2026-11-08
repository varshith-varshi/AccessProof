"""Missing restricted AWS route verification refuses before a login or ACL change."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/live/remote_route_challenge_run.py"


def _load():
    spec = importlib.util.spec_from_file_location("accessproof_remote_challenge_preflight_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (RuntimeError("RESTRICTED_CERTIFIER_AWS_PROFILE_REQUIRED"), "RESTRICTED_REMOTE_ROUTE_PREFLIGHT_REQUIRED"),
        ({"certified": False, "routes": []}, "REMOTE_ROUTES_NOT_CERTIFIED"),
    ],
)
def test_refuses_before_network_login_or_revocation(monkeypatch, tmp_path, outcome, reason):
    runner = _load()
    cfg = tmp_path / "pilot.json"
    cfg.write_text(json.dumps({"organization_id": "pilot", "application_id": "pilot-rag"}))
    output = tmp_path / "result.json"

    def never(*_args, **_kwargs):
        raise AssertionError("OWNER_LOGIN_OR_SHAREPOINT_CHANGE_BEFORE_CERTIFIER_PREFLIGHT")

    def check(_cfg):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(runner, "remote_route_status", check)
    monkeypatch.setattr(runner.httpx, "post", never)
    monkeypatch.setattr(sys, "argv", [
        str(SCRIPT), "--config", str(cfg), "--out", str(output), "--attempts", "1",
    ])
    with pytest.raises(SystemExit, match=reason):
        runner.main()
    assert not output.exists()


def test_valid_remote_preflight_does_not_issue_cert_without_owner_login(monkeypatch, tmp_path):
    runner = _load()
    cfg = tmp_path / "pilot.json"
    password_file = tmp_path / "owner-password.txt"
    password_file.write_text("synthetic-test-password")
    cfg.write_text(json.dumps({
        "organization_id": "pilot", "application_id": "pilot-rag", "api": "https://example.test",
        "admin_email": "owner@example.test", "admin_password_file": str(password_file),
    }))
    output = tmp_path / "result.json"
    monkeypatch.setattr(runner, "remote_route_status", lambda _: {"certified": True, "routes": [{"state": "VALID"}]})
    called = []

    def fail_owner_login(*_args, **_kwargs):
        called.append(True)
        raise RuntimeError("OWNER_LOGIN_REQUIRED")
    monkeypatch.setattr(runner.httpx, "post", fail_owner_login)
    monkeypatch.setattr(sys, "argv", [
        str(SCRIPT), "--config", str(cfg), "--out", str(output),
        "--controlled-recertification",
    ])
    with pytest.raises(RuntimeError, match="OWNER_LOGIN_REQUIRED"):
        runner.main()
    assert called and not output.exists()
