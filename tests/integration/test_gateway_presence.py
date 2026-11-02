"""D-02 regression: Gateway liveness is authenticated, fresh and non-replayable.

"Previously installed" != "currently online" != "enforcement ready" != Protect.
Synthetic tenants only; exercises the real API heartbeat route over HTTP.
"""
from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api import gateway_presence
from apps.api.accessproof_api.db import (
    AIApplication, Base, GatewayInstallation, GuardRegistration, Organization, Project,
    SessionLocal, SourceConnection, engine,
)
from apps.gateway.accessproof_gateway.installer import (
    InstallationError, PRESENCE_ENV_NAME, write_presence_environment,
)
from apps.gateway.accessproof_gateway.presence import PresenceReporter, PresenceSettings

ROUTE = "c" * 64


def _tenant(db, name: str):
    org = Organization(name=name)
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="p")
    db.add(project)
    db.flush()
    source = SourceConnection(organization_id=org.id, project_id=project.id, name="s",
                              provider="sharepoint", boundary="root", status="connected")
    guard = GuardRegistration(organization_id=org.id, name="g", status="enrolled",
                              enrolled_at=datetime.now(timezone.utc))
    db.add_all([source, guard])
    db.flush()
    row = AIApplication(organization_id=org.id, application_id=f"{name}-rag", name="rag",
                        guard_id=guard.id, source_id=source.id, adapter_type="accessproof-gateway",
                        mode="protect_pending")
    db.add(row)
    db.flush()
    return row


@pytest.fixture()
def world():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        alpha, beta = _tenant(db, "alpha"), _tenant(db, "beta")
        record, credential = gateway_presence.issue_installation(
            db, alpha, deployment_sha256="d" * 64, route_sha256=ROUTE)
        beta_record, beta_credential = gateway_presence.issue_installation(
            db, beta, deployment_sha256="e" * 64, route_sha256=ROUTE)
        db.commit()
        ids = {"alpha_app": alpha.id, "alpha_org": alpha.organization_id,
               "alpha_application_id": alpha.application_id, "alpha_install": record.id,
               "alpha_credential": credential, "beta_org": beta.organization_id,
               "beta_install": beta_record.id, "beta_credential": beta_credential}
    with TestClient(api_module.app) as client:
        yield client, ids


def _beat(client, ids, *, sequence, ready=True, credential=None, org=None, install=None,
          route=ROUTE, application_id=None, code=None):
    return client.post("/api/v1/gateway-installations/heartbeat", headers={
        "Authorization": "Bearer " + (credential or ids["alpha_credential"]),
    }, json={
        "organization_id": org or ids["alpha_org"],
        "installation_id": install or ids["alpha_install"],
        "application_id": application_id or ids["alpha_application_id"],
        "route_sha256": route, "sequence": sequence, "version": "gateway-v1",
        "ready": ready, "readiness_code": code,
    })


def _connectivity(ids):
    with SessionLocal() as db:
        row = db.get(AIApplication, ids["alpha_app"])
        return gateway_presence.connectivity(db, row), gateway_presence.activation_check(db, row)


def test_fresh_authenticated_ready_heartbeat_is_connected_and_ready(world):
    client, ids = world
    status, check = _connectivity(ids)
    assert status["connection"] == "DISCONNECTED" and status["reason"] == "NO_HEARTBEAT_YET"
    assert check["ok"] is False
    assert _beat(client, ids, sequence=1).status_code == 200
    status, check = _connectivity(ids)
    assert status["connection"] == "CONNECTED" and status["enforcement_ready_reported"] is True
    assert status["production_certification"] is False
    assert check["ok"] is True


def test_connected_but_not_ready_gateway_never_satisfies_activation(world):
    client, ids = world
    assert _beat(client, ids, sequence=1, ready=False, code="GUARD_NOT_READY").status_code == 200
    status, check = _connectivity(ids)
    assert status["connection"] == "CONNECTED"
    assert status["enforcement_ready_reported"] is False and status["reason"] == "GUARD_NOT_READY"
    assert check["ok"] is False


def test_replay_forgery_and_cross_tenant_heartbeats_are_rejected(world):
    client, ids = world
    assert _beat(client, ids, sequence=5).status_code == 200
    assert _beat(client, ids, sequence=5).status_code == 409   # exact replay
    assert _beat(client, ids, sequence=4).status_code == 409   # older replay
    assert _beat(client, ids, sequence=6, credential="x" * 64).status_code == 401
    # Beta's valid credential cannot drive alpha's installation, and alpha's
    # installation id cannot be addressed under beta's tenant context.
    assert _beat(client, ids, sequence=7, credential=ids["beta_credential"]).status_code == 401
    assert _beat(client, ids, sequence=7, org=ids["beta_org"]).status_code == 401
    assert _beat(client, ids, sequence=7, application_id="beta-rag").status_code == 403
    assert _beat(client, ids, sequence=7, route="f" * 64).status_code == 409
    missing = client.post("/api/v1/gateway-installations/heartbeat", json={
        "organization_id": ids["alpha_org"], "installation_id": ids["alpha_install"],
        "application_id": ids["alpha_application_id"], "route_sha256": ROUTE,
        "sequence": 9, "version": "v", "ready": True,
    })
    assert missing.status_code == 401


def test_heartbeat_expiry_rebinding_and_rotation_disconnect(world, monkeypatch):
    client, ids = world
    assert _beat(client, ids, sequence=1).status_code == 200
    with SessionLocal() as db:
        record = db.scalar(select(GatewayInstallation).where(GatewayInstallation.id == ids["alpha_install"]))
        record.last_heartbeat_at = datetime.now(timezone.utc) - timedelta(
            seconds=api_module.settings.gateway_offline_seconds + 1)
        db.commit()
    status, check = _connectivity(ids)
    assert status["connection"] == "DISCONNECTED" and status["reason"] == "HEARTBEAT_EXPIRED"
    assert check["ok"] is False
    # Rebinding the application to another Guard invalidates this Gateway.
    with SessionLocal() as db:
        row = db.get(AIApplication, ids["alpha_app"])
        other = GuardRegistration(organization_id=row.organization_id, name="other")
        db.add(other)
        db.flush()
        original_guard, row.guard_id = row.guard_id, other.id
        db.commit()
    assert _beat(client, ids, sequence=2).status_code == 409
    assert _connectivity(ids)[0]["reason"] == "GATEWAY_BINDING_CHANGED_REPAIR_REQUIRED"
    with SessionLocal() as db:
        row = db.get(AIApplication, ids["alpha_app"])
        row.guard_id = original_guard
        # Re-pair: rotation revokes the old credential and identity.
        new_record, new_credential = gateway_presence.issue_installation(
            db, row, deployment_sha256="d" * 64, route_sha256=ROUTE)
        db.commit()
        new_id = new_record.id
    assert _beat(client, ids, sequence=3).status_code == 401
    assert _beat(client, ids, sequence=1, credential=new_credential, install=new_id).status_code == 200


def test_gateway_without_heartbeat_capability_is_unknown_not_connected(world):
    _, ids = world
    with SessionLocal() as db:
        db.query(GatewayInstallation).delete()
        db.commit()
    status, check = _connectivity(ids)
    assert status["connection"] == "UNKNOWN" and check["ok"] is False


def test_activation_checklist_requires_live_ready_gateway(world):
    client, ids = world
    with SessionLocal() as db:
        row = db.get(AIApplication, ids["alpha_app"])
        codes = {c["code"]: c["ok"] for c in api_module._automatic_activation_checklist(db, row)}
    assert codes["GATEWAY_LIVE_AND_ENFORCEMENT_READY"] is False
    assert _beat(client, ids, sequence=1).status_code == 200
    with SessionLocal() as db:
        row = db.get(AIApplication, ids["alpha_app"])
        codes = {c["code"]: c["ok"] for c in api_module._automatic_activation_checklist(db, row)}
    assert codes["GATEWAY_LIVE_AND_ENFORCEMENT_READY"] is True
    # Gateway liveness alone never satisfies the remaining Protect gates.
    assert not all(codes.values())


def test_gateway_reporter_drives_real_api_route(world):
    client, ids = world
    reporter = PresenceReporter(PresenceSettings(
        control_plane_url="https://testserver", organization_id=ids["alpha_org"],
        installation_id=ids["alpha_install"], credential=ids["alpha_credential"],
        application_id=ids["alpha_application_id"], route_sha256=ROUTE,
    ), client=client)
    assert reporter.beat(ready=False, readiness_code="GUARD_UNAVAILABLE") == 200
    assert _connectivity(ids)[0]["reason"] == "GUARD_UNAVAILABLE"
    assert reporter.beat(ready=True, readiness_code=None) == 200
    assert _connectivity(ids)[0]["enforcement_ready_reported"] is True


def test_presence_settings_refuse_plaintext_remote_control_plane():
    with pytest.raises(ValueError):
        PresenceSettings(control_plane_url="http://api.example.com", organization_id="o",
                         installation_id="i", credential="x" * 64, application_id="a",
                         route_sha256=ROUTE)


def test_presence_env_file_is_private_and_rotates(tmp_path: Path):
    presence = {"control_plane_url": "https://api.example.com", "organization_id": "o",
                "installation_id": "i", "credential": "s" * 64, "route_sha256": ROUTE}
    path = write_presence_environment(tmp_path, presence)
    assert path.name == PRESENCE_ENV_NAME
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "ACCESSPROOF_GATEWAY_PRESENCE_CREDENTIAL=" + "s" * 64 in path.read_text()
    write_presence_environment(tmp_path, {**presence, "credential": "t" * 64})
    assert "s" * 64 not in path.read_text()
    with pytest.raises(InstallationError):
        write_presence_environment(tmp_path, {**presence, "credential": ""})


def test_d04_undecryptable_microsoft_credentials_fail_closed_without_crashing(world):
    """D-04: missing/corrupt SharePoint credentials must yield a failed check, not HTTP 500."""
    _, ids = world
    with SessionLocal() as db:
        row = db.get(AIApplication, ids["alpha_app"])
        source = db.get(SourceConnection, row.source_id)
        for credentials in (None, "not-a-valid-ciphertext"):
            source.encrypted_credentials = credentials
            db.flush()
            codes = {c["code"]: c["ok"] for c in api_module._automatic_activation_checklist(db, row)}
            assert codes["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"] is False
            assert not all(codes.values())
