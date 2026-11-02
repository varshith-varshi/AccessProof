"""Machine-authenticated Gateway presence (defect D-02).

Three distinct facts, never conflated:

* ``installation_reported_historical``: a pairing claim once succeeded.
* ``CONNECTED``: this exact installation credential sent a fresh, non-replayed
  heartbeat within ``gateway_offline_seconds`` (server clock).
* ``enforcement_ready_reported``: on that fresh heartbeat the Gateway reported
  its own ``/health/ready`` passing (Guard authorization-ready for this app).

None of these is Protect evidence. Protect additionally requires route
challenges, Guard acknowledgement and every other activation check.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.config import settings
from apps.api.accessproof_api.db import AIApplication, GatewayInstallation, set_tenant_context
from packages.crypto.secrets import constant_time_equal, hash_token

_UUIDISH = r"^[A-Za-z0-9-]{1,36}$"


class GatewayHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: str = Field(pattern=_UUIDISH)
    installation_id: str = Field(pattern=_UUIDISH)
    application_id: str = Field(min_length=1, max_length=255)
    route_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence: int = Field(ge=1, le=2**62)
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._+-]+$")
    ready: bool
    readiness_code: str | None = Field(default=None, max_length=80, pattern=r"^[A-Z0-9_]+$")


def _utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def issue_installation(
    db: Session, row: AIApplication, *, deployment_sha256: str, route_sha256: str,
) -> tuple[GatewayInstallation, str]:
    """Create or rotate the single installation credential for this application.

    Caller must already have validated the one-use pairing token and the
    application's org/Guard/source binding. Returns the plaintext credential
    exactly once; only its hash is stored.
    """
    if not row.guard_id or not row.source_id:
        raise ValueError("APPLICATION_SOURCE_AND_GUARD_BINDING_REQUIRED")
    credential = secrets.token_urlsafe(48)
    record = db.scalar(select(GatewayInstallation).where(
        GatewayInstallation.organization_id == row.organization_id,
        GatewayInstallation.application_row_id == row.id,
    ))
    if record is None:
        record = GatewayInstallation(organization_id=row.organization_id, application_row_id=row.id)
        db.add(record)
    # Rotation: a fresh identity, sequence and readiness for the new Gateway.
    record.id = str(uuid4())
    record.credential_hash = hash_token(credential)
    record.guard_id = row.guard_id
    record.source_id = row.source_id
    record.deployment_sha256 = deployment_sha256
    record.route_sha256 = route_sha256
    record.created_at = datetime.now(timezone.utc)
    record.revoked_at = None
    record.last_heartbeat_at = None
    record.last_sequence = 0
    record.last_reported_ready = False
    record.last_readiness_code = "NO_HEARTBEAT_YET"
    record.gateway_version = None
    db.flush()
    return record, credential


def record_heartbeat(db: Session, payload: GatewayHeartbeat, authorization: str | None) -> dict[str, Any]:
    scheme, _, credential = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not credential or len(credential) > 512:
        raise HTTPException(401, "GATEWAY_CREDENTIAL_REQUIRED")
    # Forced-RLS table: scope the lookup to the claimed tenant. A wrong
    # organization simply finds nothing; it can never read another tenant.
    set_tenant_context(db, payload.organization_id)
    record = db.scalar(select(GatewayInstallation).where(
        GatewayInstallation.id == payload.installation_id,
        GatewayInstallation.organization_id == payload.organization_id,
    ).with_for_update())
    if (record is None or record.revoked_at is not None
            or not constant_time_equal(record.credential_hash, hash_token(credential))):
        raise HTTPException(401, "GATEWAY_CREDENTIAL_INVALID")
    row = db.get(AIApplication, record.application_row_id)
    if row is None or row.organization_id != record.organization_id or row.application_id != payload.application_id:
        raise HTTPException(403, "GATEWAY_APPLICATION_BINDING_MISMATCH")
    # A Guard or source rebinding invalidates this Gateway's enforcement path;
    # it must be re-paired rather than silently appear connected.
    if row.guard_id != record.guard_id or row.source_id != record.source_id:
        raise HTTPException(409, "GATEWAY_BINDING_CHANGED_REPAIR_REQUIRED")
    if payload.route_sha256 != record.route_sha256:
        raise HTTPException(409, "GATEWAY_ROUTE_CHANGED_REPAIR_REQUIRED")
    if payload.sequence <= int(record.last_sequence or 0):
        raise HTTPException(409, "GATEWAY_HEARTBEAT_REPLAY")
    now = datetime.now(timezone.utc)
    record.last_sequence = payload.sequence
    record.last_heartbeat_at = now
    record.last_reported_ready = bool(payload.ready)
    record.last_readiness_code = None if payload.ready else (payload.readiness_code or "GATEWAY_NOT_READY")
    record.gateway_version = payload.version
    db.commit()
    return {"ok": True, "received_at": now.isoformat(),
            "offline_after_seconds": settings.gateway_offline_seconds}


def connectivity(db: Session, row: AIApplication, now: datetime | None = None) -> dict[str, Any]:
    """Evidence-derived connectivity; never inferred from install history."""
    now = now or datetime.now(timezone.utc)
    record = db.scalar(select(GatewayInstallation).where(
        GatewayInstallation.organization_id == row.organization_id,
        GatewayInstallation.application_row_id == row.id,
    ))
    if record is None:
        return {"connection": "UNKNOWN", "installation_id": None, "enforcement_ready_reported": False,
                "last_heartbeat_at": None, "heartbeat_age_seconds": None,
                "reason": "NO_HEARTBEAT_CAPABLE_INSTALLATION", "production_certification": False}
    seen = _utc(record.last_heartbeat_at)
    age = None if seen is None else max(0, int((now - seen).total_seconds()))
    binding_current = row.guard_id == record.guard_id and row.source_id == record.source_id
    if record.revoked_at is not None:
        connection, reason = "DISCONNECTED", "INSTALLATION_REVOKED"
    elif not binding_current:
        connection, reason = "DISCONNECTED", "GATEWAY_BINDING_CHANGED_REPAIR_REQUIRED"
    elif age is None:
        connection, reason = "DISCONNECTED", "NO_HEARTBEAT_YET"
    elif age > settings.gateway_offline_seconds:
        connection, reason = "DISCONNECTED", "HEARTBEAT_EXPIRED"
    else:
        connection, reason = "CONNECTED", None
    ready = connection == "CONNECTED" and bool(record.last_reported_ready)
    if connection == "CONNECTED" and not ready:
        reason = record.last_readiness_code or "GATEWAY_NOT_READY"
    return {
        "connection": connection, "installation_id": record.id,
        "enforcement_ready_reported": ready,
        "last_heartbeat_at": seen.isoformat() if seen else None,
        "heartbeat_age_seconds": age, "gateway_version": record.gateway_version,
        "reason": reason, "production_certification": False,
    }


def activation_check(db: Session, row: AIApplication) -> dict[str, Any]:
    status = connectivity(db, row)
    ok = status["connection"] == "CONNECTED" and status["enforcement_ready_reported"] is True
    return {
        "code": "GATEWAY_LIVE_AND_ENFORCEMENT_READY", "ok": ok,
        "reason": None if ok else (
            "The installed Gateway must be sending authenticated heartbeats and report "
            f"enforcement readiness (current: {status['connection']}"
            f"{', ' + status['reason'] if status['reason'] else ''})."
        ),
    }


def revoke(db: Session, row: AIApplication) -> bool:
    record = db.scalar(select(GatewayInstallation).where(
        GatewayInstallation.organization_id == row.organization_id,
        GatewayInstallation.application_row_id == row.id,
        GatewayInstallation.revoked_at.is_(None),
    ))
    if record is None:
        return False
    record.revoked_at = datetime.now(timezone.utc)
    return True

