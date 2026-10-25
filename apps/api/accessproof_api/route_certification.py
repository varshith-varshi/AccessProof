"""Reference-route certificate state derived from machine-observed challenges.

A certificate is deliberately narrow: it proves the documented Gateway route
was exercised with a nonce-bound request and matching Guard audit evidence for
the exact current tenant/application/Guard/source/adapter/policy fingerprint.
It is not certification of every response path in a customer application.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from apps.api.accessproof_api.db import AIApplication, GuardRegistration, RAGRouteChallenge

ROUTE_CERTIFICATE_SCHEMA = "accessproof.route_certificate/v1"
CERTIFICATE_TTL = timedelta(hours=24)


def route_configuration_fingerprint(row: AIApplication, guard_policy_version: int) -> str:
    """Bind a challenge to the exact tenant/app/Guard/source/adapter/policy."""
    return hashlib.sha256(json.dumps({
        "organization_id": row.organization_id, "application_id": row.application_id,
        "guard_id": row.guard_id, "source_id": row.source_id,
        "adapter": row.adapter_type, "contract_version": row.adapter_contract_version,
        "guard_policy_version": guard_policy_version,
    }, sort_keys=True).encode()).hexdigest()


def _guard(db: OrmSession, row: AIApplication) -> GuardRegistration | None:
    if row.adapter_type != "accessproof-gateway" or not row.guard_id or not row.source_id:
        return None
    guard = db.get(GuardRegistration, row.guard_id)
    if not guard or guard.revoked_at or guard.enrolled_at is None or guard.active_policy_version < 1:
        return None
    return guard


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _latest_challenge(
    db: OrmSession, row: AIApplication, *, statuses: tuple[str, ...] | None = None,
) -> RAGRouteChallenge | None:
    guard = _guard(db, row)
    if guard is None:
        return None
    query = select(RAGRouteChallenge).where(
        RAGRouteChallenge.organization_id == row.organization_id,
        RAGRouteChallenge.application_row_id == row.id,
        RAGRouteChallenge.guard_id == row.guard_id,
        RAGRouteChallenge.source_id == row.source_id,
        RAGRouteChallenge.configuration_fingerprint == route_configuration_fingerprint(
            row, guard.active_policy_version
        ),
    )
    if statuses:
        query = query.where(RAGRouteChallenge.status.in_(statuses))
    query = query.where(RAGRouteChallenge.verified_at.is_not(None))
    query = query.where(
        RAGRouteChallenge.verified_at >= datetime.now(timezone.utc) - CERTIFICATE_TTL
    )
    return db.scalar(query.order_by(
        RAGRouteChallenge.verified_at.desc().nullslast(),
        RAGRouteChallenge.created_at.desc(),
    ).limit(1))


def reference_route_tested(db: OrmSession, row: AIApplication) -> bool:
    return _latest_challenge(db, row, statuses=("tested", "cutover_verified")) is not None


def _superseded_challenge(db: OrmSession, row: AIApplication) -> RAGRouteChallenge | None:
    """Latest verified challenge for this binding, regardless of fingerprint.

    Used only to distinguish "never tested" from "tested but the certificate
    expired or the Guard policy/configuration changed since".
    """
    guard = _guard(db, row)
    if guard is None:
        return None
    return db.scalar(select(RAGRouteChallenge).where(
        RAGRouteChallenge.organization_id == row.organization_id,
        RAGRouteChallenge.application_row_id == row.id,
        RAGRouteChallenge.guard_id == row.guard_id,
        RAGRouteChallenge.source_id == row.source_id,
        RAGRouteChallenge.status.in_(("tested", "cutover_verified")),
        RAGRouteChallenge.verified_at.is_not(None),
    ).order_by(
        RAGRouteChallenge.verified_at.desc(),
        RAGRouteChallenge.created_at.desc(),
    ).limit(1))


def valid_route_certificate(db: OrmSession, row: AIApplication) -> bool:
    challenge = _latest_challenge(db, row, statuses=("cutover_verified",))
    return challenge is not None and challenge.cutover_at is not None


def describe_route_certificate(
    db: OrmSession, row: AIApplication, *, now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    base: dict[str, Any] = {
        "schema": ROUTE_CERTIFICATE_SCHEMA,
        "status": "NOT_APPLICABLE",
        "applicable": False,
        "certified": False,
        "certificate_id": None,
        "configuration_fingerprint": None,
        "verified_at": None,
        "cutover_at": None,
        "expires_at": None,
        "age_seconds": None,
        "evidence_level": None,
        "independent_certification": False,
        "certification_scope": "REFERENCE_GATEWAY_ROUTE_ONLY",
        "limitations": [
            "Certifies only the documented Gateway response route exercised by the nonce-bound challenge.",
            "Does not discover or certify arbitrary application API, SSE, WebSocket, tool, cache or worker paths.",
        ],
    }
    if row.adapter_type != "accessproof-gateway":
        base["reason"] = "ADAPTER_IS_NOT_REFERENCE_GATEWAY"
        return base
    base["applicable"] = True
    guard = _guard(db, row)
    if guard is None:
        base["status"] = "MISSING"
        base["reason"] = "GUARD_NOT_READY"
        return base
    base["configuration_fingerprint"] = route_configuration_fingerprint(
        row, guard.active_policy_version
    )
    challenge = _latest_challenge(db, row, statuses=("tested", "cutover_verified"))
    if challenge is None:
        previous = _superseded_challenge(db, row)
        base["status"] = "EXPIRED" if previous is not None else "MISSING"
        base["reason"] = "CERTIFICATE_EXPIRED_OR_CONFIGURATION_CHANGED" if previous else "NO_ROUTE_CHALLENGE"
        if previous is not None and previous.verified_at is not None:
            verified = _aware(previous.verified_at)
            base["verified_at"] = verified.isoformat()
            base["age_seconds"] = max(0.0, (now - verified).total_seconds())
            base["evidence_level"] = "PRODUCTION_OBSERVED"
        return base
    verified_at = _aware(challenge.verified_at) if challenge.verified_at else None
    cutover_at = _aware(challenge.cutover_at) if challenge.cutover_at else None
    base.update({
        "certificate_id": challenge.id,
        "verified_at": verified_at.isoformat() if verified_at else None,
        "cutover_at": cutover_at.isoformat() if cutover_at else None,
        "expires_at": (verified_at + CERTIFICATE_TTL).isoformat() if verified_at else None,
        "age_seconds": max(0.0, (now - verified_at).total_seconds()) if verified_at else None,
        "evidence_level": "PRODUCTION_OBSERVED" if verified_at else None,
    })
    if challenge.status == "cutover_verified" and cutover_at is not None:
        base["status"] = "CERTIFIED"
        base["certified"] = True
        base["reason"] = "REFERENCE_ROUTE_CERTIFIED"
    else:
        base["status"] = "TESTED_NOT_CUTOVER"
        base["reason"] = "CUTOVER_NOT_VERIFIED"
    return base


__all__ = [
    "CERTIFICATE_TTL",
    "ROUTE_CERTIFICATE_SCHEMA",
    "describe_route_certificate",
    "reference_route_tested",
    "route_configuration_fingerprint",
    "valid_route_certificate",
]
