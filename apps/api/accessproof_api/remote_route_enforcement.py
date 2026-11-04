"""Production verification and enforcement of REMOTE RAG route certificates.

Trusted signing authority: the offline certifier keys already pinned for source
certificates (``ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON``); the API
never holds signing material. Route certificates use their own schema
(``accessproof.remote-route-certificate/v1``), so a certificate of one kind can
never be presented as the other.

A certificate is VALID only while ALL hold:
  * signature by a pinned certifier key, schema, status CERTIFIED, every
    required check PASS, fingerprint == fingerprint(binding);
  * binding tenant/application/source == this production application record;
  * not expired (7 days), not revoked/invalidated/superseded;
  * a signed live attestation (certifier ``--verify``) within 24 h, whose live
    fingerprint matched. A mismatching attestation (configuration changed)
    invalidates the certificate permanently: re-certification is required.

Enforcement: Gate E fails for an application that has a remote route
certificate on record but no currently VALID one.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import AIApplication, RemoteRouteCertificate
from packages.crypto import remote_route_certificate as rrc
from packages.crypto.source_certificate import load_public_keys

ATTESTATION_STALE_AFTER = timedelta(hours=24)


class RemoteRouteError(ValueError):
    pass


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _keys():
    keys = load_public_keys(os.getenv("ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON", ""))
    if not keys:
        raise RemoteRouteError("CERTIFIER_TRUST_NOT_CONFIGURED")
    return keys


def _parse(ts: Any) -> datetime:
    try:
        return _utc(datetime.fromisoformat(str(ts)))
    except ValueError as exc:
        raise RemoteRouteError("TIMESTAMP_INVALID") from exc


def import_certificate(db: Session, row: AIApplication, cert: dict, *, now: datetime | None = None) -> RemoteRouteCertificate:
    now = now or datetime.now(timezone.utc)
    if not isinstance(cert, dict) or cert.get("schema") != rrc.SCHEMA:
        raise RemoteRouteError("SCHEMA_UNSUPPORTED")
    if not rrc.verify_signed(cert, _keys()):
        raise RemoteRouteError("SIGNATURE_INVALID")
    binding = cert.get("binding") or {}
    if cert.get("status") != "CERTIFIED" or cert.get("failing"):
        raise RemoteRouteError("NOT_CERTIFIED")
    passed = {c.get("code") for c in cert.get("checks") or [] if c.get("status") == "PASS"}
    if not set(rrc.REQUIRED_CHECKS) <= passed:
        raise RemoteRouteError("REQUIRED_CHECKS_MISSING")
    if rrc.fingerprint(binding) != cert.get("fingerprint"):
        raise RemoteRouteError("FINGERPRINT_MISMATCH")
    if (binding.get("tenant_id"), binding.get("application_id"), binding.get("source_id")) != (
            row.organization_id, row.application_id, row.source_id):
        raise RemoteRouteError("BINDING_NOT_THIS_APPLICATION")
    issued, expires = _parse(cert.get("issued_at")), _parse(cert.get("expires_at"))
    if issued > now + timedelta(minutes=5) or expires <= now or expires - issued > rrc.MAX_AGE:
        raise RemoteRouteError("VALIDITY_INVALID")
    existing = db.scalar(select(RemoteRouteCertificate).where(
        RemoteRouteCertificate.organization_id == row.organization_id,
        RemoteRouteCertificate.application_row_id == row.id,
        RemoteRouteCertificate.fingerprint == cert["fingerprint"]))
    if existing is not None and existing.status == "revoked":
        raise RemoteRouteError("CERTIFICATE_REVOKED_BY_OWNER")          # owner revocation is permanent per binding
    if existing is not None and existing.status == "invalidated":
        # A configuration change invalidated this binding. Reverting to it requires a
        # NEW full certification run, issued after the invalidating observation.
        try:
            invalidated_at = _parse(json.loads(existing.last_attestation_json or "{}").get("observed_at"))
        except RemoteRouteError:
            invalidated_at = now
        if issued <= invalidated_at:
            raise RemoteRouteError("CONFIGURATION_PREVIOUSLY_INVALIDATED")
    # One active certificate per route URL: older ones for the same route are superseded.
    for old in db.scalars(select(RemoteRouteCertificate).where(
            RemoteRouteCertificate.organization_id == row.organization_id,
            RemoteRouteCertificate.application_row_id == row.id,
            RemoteRouteCertificate.route_url == str(binding.get("route_url")),
            RemoteRouteCertificate.status == "active")):
        if old is not existing:
            old.status, old.status_reason = "superseded", "NEWER_CERTIFICATE_IMPORTED"
    record = existing or RemoteRouteCertificate(organization_id=row.organization_id, application_row_id=row.id,
                                                fingerprint=cert["fingerprint"])
    record.key_id, record.route_url = str(cert.get("key_id")), str(binding.get("route_url"))[:512]
    record.certificate_json, record.issued_at, record.expires_at = json.dumps(cert, sort_keys=True), issued, expires
    record.status, record.status_reason = "active", None
    # The certification run itself is the first observation of the live binding.
    record.last_attested_at = issued
    db.add(record)
    db.flush()
    return record


def apply_attestation(db: Session, row: AIApplication, att: dict, *, now: datetime | None = None) -> RemoteRouteCertificate:
    now = now or datetime.now(timezone.utc)
    if not isinstance(att, dict) or att.get("schema") != rrc.ATTESTATION_SCHEMA:
        raise RemoteRouteError("ATTESTATION_SCHEMA_UNSUPPORTED")
    if not rrc.verify_signed(att, _keys()):
        raise RemoteRouteError("ATTESTATION_SIGNATURE_INVALID")
    observed = _parse(att.get("observed_at"))
    if observed > now + timedelta(minutes=5) or now - observed > rrc.ATTESTATION_MAX_AGE:
        raise RemoteRouteError("ATTESTATION_NOT_FRESH")
    if (att.get("tenant_id"), att.get("application_id")) != (row.organization_id, row.application_id):
        raise RemoteRouteError("ATTESTATION_NOT_THIS_APPLICATION")
    record = db.scalar(select(RemoteRouteCertificate).where(
        RemoteRouteCertificate.organization_id == row.organization_id,
        RemoteRouteCertificate.application_row_id == row.id,
        RemoteRouteCertificate.fingerprint == att.get("certificate_fingerprint")))
    if record is None:
        raise RemoteRouteError("CERTIFICATE_NOT_FOUND")
    if record.last_attested_at and observed <= _utc(record.last_attested_at):
        raise RemoteRouteError("ATTESTATION_REPLAYED")
    record.last_attestation_json = json.dumps(att, sort_keys=True)
    if att.get("matches") is True and att.get("live_fingerprint") == record.fingerprint:
        record.last_attested_at = observed
    elif record.status == "active":
        record.status = "invalidated"
        record.status_reason = "CONFIGURATION_CHANGED:" + ",".join(att.get("changed_fields") or [])[:80]
    db.flush()
    return record


def revoke(db: Session, row: AIApplication, fingerprint: str) -> RemoteRouteCertificate:
    record = db.scalar(select(RemoteRouteCertificate).where(
        RemoteRouteCertificate.organization_id == row.organization_id,
        RemoteRouteCertificate.application_row_id == row.id, RemoteRouteCertificate.fingerprint == fingerprint))
    if record is None:
        raise RemoteRouteError("CERTIFICATE_NOT_FOUND")
    record.status, record.status_reason = "revoked", "OWNER_REVOKED"
    db.flush()
    return record


def status(db: Session, row: AIApplication, *, now: datetime | None = None) -> dict[str, Any]:
    """Remote route certification state; ``applicable`` only once a remote route is on record."""
    now = now or datetime.now(timezone.utc)
    records = list(db.scalars(select(RemoteRouteCertificate).where(
        RemoteRouteCertificate.organization_id == row.organization_id,
        RemoteRouteCertificate.application_row_id == row.id).order_by(RemoteRouteCertificate.imported_at.desc())))
    out: dict[str, Any] = {"applicable": bool(records), "certified": False, "routes": []}
    try:
        keys = _keys()
    except RemoteRouteError:
        keys = {}
    for r in records:
        state, reason = "VALID", None
        cert = json.loads(r.certificate_json)
        if not keys or not rrc.verify_signed(cert, keys):
            state, reason = "INVALID", "SIGNATURE_NOT_VERIFIABLE"
        elif r.status != "active":
            state, reason = r.status.upper(), r.status_reason
        elif _utc(r.expires_at) <= now:
            state, reason = "EXPIRED", "CERTIFICATE_EXPIRED"
        elif r.last_attested_at is None or now - _utc(r.last_attested_at) > ATTESTATION_STALE_AFTER:
            state, reason = "ATTESTATION_STALE", "NO_LIVE_ATTESTATION_WITHIN_24H"
        out["routes"].append({"route_url": r.route_url, "fingerprint": r.fingerprint, "framework": cert["binding"].get("framework"),
                              "state": state, "reason": reason, "expires_at": _utc(r.expires_at).isoformat(),
                              "last_attested_at": _utc(r.last_attested_at).isoformat() if r.last_attested_at else None})
    active_urls = {r["route_url"] for r in out["routes"]}
    # Every remote route ever certified for this application must currently have a VALID certificate.
    out["certified"] = bool(records) and all(
        any(x["route_url"] == url and x["state"] == "VALID" for x in out["routes"]) for url in active_urls)
    return out
