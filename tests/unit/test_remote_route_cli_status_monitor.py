"""The certifier read-only remote route status also reports live app and Gateway states."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

from scripts import remote_route_certificate as cli


class FakeDB:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def scalar(self, *_):
        return SimpleNamespace(organization_id="org", application_id="app")


def test_readonly_status_contract_has_no_secrets(monkeypatch, capsys):
    monkeypatch.setattr(cli, "SessionLocal", FakeDB)
    monkeypatch.setattr(cli, "set_tenant_context", lambda *_: None)
    monkeypatch.setattr(cli.rre, "status", lambda db, row: {
        "applicable": True,
        "certified": True,
        "routes": [{"state": "VALID", "expires_at": "2030-01-01T00:00:00+00:00"}],
    })
    monkeypatch.setattr(cli, "describe_route_certificate", lambda db, row: {
        "status": "CERTIFIED", "certified": True,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "certification_scope": "REFERENCE_GATEWAY_ROUTE_ONLY",
    })
    monkeypatch.setattr(cli.gateway_presence, "connectivity", lambda db, row: {
        "connection": "CONNECTED", "enforcement_ready_reported": True,
        "reason": None,
        "credential": "MUST_NEVER_OUTPUT", "installation_id": "REDACT",
    })
    monkeypatch.setattr(sys, "argv", [
        "remote_route_certificate.py", "status", "--organization-id", "org",
        "--application-id", "app",
    ])
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert "MUST_NEVER_OUTPUT" not in out and "REDACT" not in out
    data = json.loads(out)
    assert data["routes"][0]["state"] == "VALID"
    assert data["application_route_certificate"]["certified"] is True
    assert data["application_route_certificate"]["status"] == "CERTIFIED"
    assert data["gateway_presence"]["connection"] == "CONNECTED"
    assert data["gateway_presence"]["enforcement_ready_reported"] is True
    assert set(data["gateway_presence"]) == {"connection", "enforcement_ready_reported", "reason"}
