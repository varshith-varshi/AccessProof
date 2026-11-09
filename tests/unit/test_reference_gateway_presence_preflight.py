"""Reference Gateway readiness does not masquerade as authenticated presence."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from scripts.drills import reference_gateway_presence_preflight as p


def gateway(*, missing_presence: bool = True) -> dict:
    names = [f"{k}=synthetic-secret-not-to-print" for k in p.PRESENCE]
    return {
        "Image": p.IMAGE,
        "State": {"Status": "running"},
        "Config": {"Env": [
            "ACCESSPROOF_GATEWAY_TENANT_ID=" + p.ORG,
            "ACCESSPROOF_GATEWAY_APPLICATION_ID=" + p.APP,
            "ACCESSPROOF_GATEWAY_MODEL_BEARER_TOKEN=synthetic-password",
            *([] if missing_presence else names),
        ], "Labels": {}},
        "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"],
                       "SecurityOpt": ["no-new-privileges"]},
        "NetworkSettings": {
            "Ports": {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8443"}]},
            "Networks": {
                "ap-remote-edge": {},
                "sharepoint-rag-lab_guard-internal": {},
            },
        },
    }


def test_legacy_runtime_can_be_healthy_without_heartbeat():
    status = p.inspect_bindings(gateway())
    assert status["runtime_verified"] is True
    assert status["authenticated_presence_configured"] is False
    assert status["presence_keys_configured_count"] == 0
    assert status["legacy_manual_runtime"] is True
    assert "synthetic-password" not in json.dumps(status)


def test_presence_configuration_is_not_live_heartbeat():
    status = p.inspect_bindings(gateway(missing_presence=False))
    assert status["runtime_verified"] is True
    assert status["authenticated_presence_configured"] is True
    assert status["presence_keys_configured_count"] == len(p.PRESENCE)


def test_any_binding_or_port_change_refuses_migration():
    cases = [
        lambda d: d.update(Image="sha256:wrong"),
        lambda d: d["Config"]["Env"].__setitem__(
            1, "ACCESSPROOF_GATEWAY_APPLICATION_ID=other-app"),
        lambda d: d["NetworkSettings"]["Ports"]["8443/tcp"].__setitem__(
            0, {"HostIp": "0.0.0.0", "HostPort": "8443"}),
        lambda d: d["HostConfig"].update(ReadonlyRootfs=False),
        lambda d: d["NetworkSettings"]["Networks"].pop("ap-remote-edge"),
    ]
    for change in cases:
        entry = gateway()
        change(entry)
        assert p.inspect_bindings(entry)["runtime_verified"] is False


def test_real_scoped_pairing_must_be_fresh_private_and_never_echoed(tmp_path):
    now = datetime(2026, 11, 9, 5, 15, tzinfo=timezone.utc)
    data = {
        "schema": "accessproof.gateway_pairing/v1",
        "application_id": p.APP,
        "organization_id": p.ORG,
        "control_plane_url": "https://api.accessproof.in",
        "pairing_token": "NOT_REAL_" + "t" * 50,
        "expires_at": (now + timedelta(minutes=14)).isoformat(),
    }
    file = tmp_path / "pairing.json"
    file.write_text(json.dumps(data))
    os.chmod(file, 0o600)
    assert p.pairing_status(file, now) == "FRESH_UNCONSUMED_NOT_VERIFIED"
    assert p.pairing_status(file, now + timedelta(hours=1)) == "EXPIRED_OR_INVALID"
    data["application_id"] = "accessproof-human-validation-rag"
    file.write_text(json.dumps(data))
    assert p.pairing_status(file, now) == "WRONG_SCOPE"
    data["application_id"] = p.APP
    file.write_text(json.dumps(data))
    os.chmod(file, 0o644)
    assert p.pairing_status(file, now) == "PRIVATE_FILE_REQUIRED"


def test_symlinked_pairing_file_refused(tmp_path):
    target = tmp_path / "real"
    target.write_text("not a pairing")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    assert p.pairing_status(link) == "UNREADABLE_OR_INVALID"
