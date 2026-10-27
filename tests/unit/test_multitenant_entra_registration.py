"""Operator Entra registration blueprint: one app, no secrets or broad sites scopes."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "register_accessproof_multitenant_entra.py"


def helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("accessproof_entra_register", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_one_multitenant_app_graph_permissions_and_trusted_callback():
    script = helper()
    definition = script.manifest()
    assert definition["displayName"] == "AccessProof"
    assert definition["signInAudience"] == "AzureADMultipleOrgs"
    assert definition["web"]["redirectUris"] == [
        "https://api.accessproof.in/api/v1/current/sources/microsoft-admin-consent/callback"
    ]
    graph, = definition["requiredResourceAccess"]
    assert graph["resourceAppId"] == "00000003-0000-0000-c000-000000000000"
    assert set(script.PERMISSIONS) == {"Sites.Selected", "User.Read.All", "Group.Read.All"}
    assert all(permission["type"] == "Role" for permission in graph["resourceAccess"])
    assert len(set(permission["id"] for permission in graph["resourceAccess"])) == 3
    manifest_dump = json.dumps(definition).lower()
    for forbidden in (
        "sites.readwrite.all", "sites.read.all", "group.readwrite.all",
        "client_secret", "secrettoken", "access_token"
    ):
        assert forbidden not in manifest_dump


def test_default_is_dry_run_not_external_registration(monkeypatch, capsys):
    script = helper()
    monkeypatch.setattr(sys, "argv", ["register_accessproof_multitenant_entra.py"])
    monkeypatch.setattr(script, "_login", lambda: pytest.fail("dry run must never log in"))
    script.main()
    content = capsys.readouterr().out
    assert "NO MICROSOFT APPLICATION HAS BEEN CREATED" in content
    assert '"dry_run": true' in content


def test_private_output_mode_and_no_overwrite(tmp_path):
    script = helper()
    path = tmp_path / "credential" / "client-secret.json"
    script._save(path, {"client_secret": "synthetic-test-only"})
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        script._save(path, {"client_secret": "different"})
    assert json.loads(path.read_text())["client_secret"] == "synthetic-test-only"


def test_registration_apply_uses_correct_home_tenant_and_never_prints_secrets(
    monkeypatch, tmp_path, capsys
):
    script = helper()
    monkeypatch.setattr(sys, "argv", [
        "register_accessproof_multitenant_entra.py",
        "--apply", "--create-secret", "--output-dir", str(tmp_path)
    ])
    monkeypatch.setattr(script, "_login", lambda: (
        "11111111-2222-3333-4444-555555555555", "synthetic-ms-graph-auth-token"
    ))
    calls: list[tuple[str, str, dict | None]] = []

    def graph(token: str, method: str, path: str, body: dict | None = None):
        assert token == "synthetic-ms-graph-auth-token"
        calls.append((method, path, body))
        if method == "GET":
            return {"value": []}
        if path == "/applications":
            return {"id": "app-object-id", "appId": "22222222-3333-4444-5555-666666666666"}
        if path.endswith("/addPassword"):
            assert "endDateTime" in body["passwordCredential"]
            return {"secretText": "synthetic-app-secret", "endDateTime": "2027-01-27T00:00:00Z"}
        pytest.fail("Unexpected Graph call")

    monkeypatch.setattr(script, "_graph", graph)
    script.main()
    assert calls[1] == ("POST", "/applications", script.manifest())
    assert calls[2][1] == "/applications/app-object-id/addPassword"
    registration = json.loads((tmp_path / "entra-app-registration.json").read_text())
    assert registration["client_id"] == "22222222-3333-4444-5555-666666666666"
    secret_path = tmp_path / "entra-client-secret.json"
    assert secret_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(secret_path.read_text())["client_secret"] == "synthetic-app-secret"
    output = capsys.readouterr().out
    assert "synthetic-app-secret" not in output
    assert "synthetic-ms-graph-auth-token" not in output


def test_production_compose_api_and_worker_receive_operator_credentials():
    import yaml

    for compose_file in ("docker-compose.ec2.yml", "docker-compose.production.yml"):
        document = yaml.safe_load((ROOT / compose_file).read_text())
        for service in ("api", "worker"):
            environment = document["services"][service]["environment"]
            assert environment["ACCESSPROOF_MICROSOFT_CLIENT_ID"] == "${ACCESSPROOF_MICROSOFT_CLIENT_ID:-}"
            assert environment["ACCESSPROOF_MICROSOFT_CLIENT_SECRET"] == "${ACCESSPROOF_MICROSOFT_CLIENT_SECRET:-}"
