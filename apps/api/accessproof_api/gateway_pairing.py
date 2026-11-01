"""Short-lived, tenant-bound pairing for customer-installed Gateway manifests.

A claim only records installation metadata; it NEVER certifies a route, bypass,
SharePoint effective permission, or enables Protect. Redis is mandatory and
fail-closed. No customer installation credential is stored in plaintext.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from redis import Redis

from apps.api.accessproof_api.config import settings

SCHEMA = "accessproof.gateway_pairing/v1"
TOKEN_SECONDS = 900
STATUS_SECONDS = 86400
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class PairingError(ValueError):
    pass


def _client() -> Redis:
    if not settings.redis_url:
        raise PairingError("PAIRING_STORE_UNAVAILABLE")
    return Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)


def _status_key(org: str, app_row: str) -> str:
    # IDs are internal UUIDs and never customer-provided Redis key fragments.
    return f"accessproof:gateway-pair:v1:status:{org}:{app_row}"


def _token_key(token: str) -> str:
    return "accessproof:gateway-pair:v1:token:" + hashlib.sha256(token.encode()).hexdigest()


def issue(*, org_id: str, app_row_id: str, application_id: str, api_url: str) -> dict[str, Any]:
    if not api_url.startswith("https://") and settings.env == "production":
        raise PairingError("PAIRING_API_HTTPS_REQUIRED")
    token = secrets.token_urlsafe(40)
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    with _client() as redis:
        record = json.dumps(
            {
                "organization_id": org_id,
                "application_row_id": app_row_id,
                "application_id": application_id,
                "digest": digest,
            }
        )
        if not redis.set(_token_key(token), record, ex=TOKEN_SECONDS, nx=True):
            raise PairingError("PAIRING_COLLISION")
        redis.set(
            _status_key(org_id, app_row_id),
            json.dumps(
                {
                    "state": "awaiting_customer_install",
                    "digest": digest,
                    "created_at": now.isoformat(),
                    "expires_at": (now + timedelta(seconds=TOKEN_SECONDS)).isoformat(),
                }
            ),
            ex=STATUS_SECONDS,
        )
    return {
        "schema": SCHEMA,
        "application_id": application_id,
        "organization_id": org_id,
        "control_plane_url": api_url.rstrip("/"),
        "pairing_token": token,
        "expires_at": (now + timedelta(seconds=TOKEN_SECONDS)).isoformat(),
        "state": "awaiting_customer_install",
    }


def status(*, org_id: str, app_row_id: str) -> dict[str, Any]:
    with _client() as redis:
        data = redis.get(_status_key(org_id, app_row_id))
    if not data:
        return {"state": "not_started", "production_certification": False}
    record = json.loads(data)
    expires_at = record.get("expires_at")
    state = record.get("state", "not_started")
    if state == "awaiting_customer_install" and isinstance(expires_at, str):
        try:
            if datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= datetime.now(
                timezone.utc
            ):
                state = "pairing_expired"
        except ValueError:
            state = "pairing_expired"
    return {
        "state": state,
        "received_at": record.get("received_at"),
        "expires_at": record.get("expires_at"),
        "deployment_sha256": record.get("deployment_sha256"),
        "route_sha256": record.get("route_sha256"),
        "production_certification": False,
    }


def receive(
    *, token: str, installation: dict[str, Any], application_is_valid: Any
) -> dict[str, Any]:
    """Accept an actual staged installation manifest exactly once.

    The caller must independently re-check that the DB application is still
    bound to the same org and Guard. A reported install is NOT a certificate.
    """
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        raise PairingError("INVALID_PAIRING_TOKEN")
    if not isinstance(installation, dict):
        raise PairingError("INVALID_INSTALLATION_MANIFEST")
    if (
        installation.get("reference_contract") != "accessproof.gateway/v1"
        or installation.get("state") != "INSTALLED_UNVERIFIED"
        or not isinstance(installation.get("application_id"), str)
    ):
        raise PairingError("INVALID_INSTALLATION_MANIFEST")
    hashes = [installation.get("deployment_sha256"), installation.get("route_sha256")]
    if any(not isinstance(h, str) or not _DIGEST.fullmatch(h) for h in hashes):
        raise PairingError("INVALID_INSTALLATION_DIGEST")
    key = _token_key(token)
    with _client() as redis:
        raw = redis.get(key)
        if not raw:
            raise PairingError("PAIRING_EXPIRED_OR_CONSUMED")
        record = json.loads(raw)
        if installation["application_id"] != record["application_id"]:
            raise PairingError("PAIRING_APPLICATION_MISMATCH")
        if installation.get("tenant_id") != record["organization_id"]:
            raise PairingError("PAIRING_TENANT_MISMATCH")
        if not application_is_valid(
            record["organization_id"], record["application_row_id"], record["application_id"]
        ):
            raise PairingError("PAIRING_APPLICATION_NOT_ELIGIBLE")
        status_key = _status_key(record["organization_id"], record["application_row_id"])
        current_raw = redis.get(status_key)
        current = json.loads(current_raw) if current_raw else {}
        if current.get("digest") != record["digest"]:
            raise PairingError("PAIRING_SUPERSEDED")
        # Consume before accepting the claimed installation. Any concurrent
        # second claim can no longer use the same secret.
        if not redis.getdel(key):
            raise PairingError("PAIRING_EXPIRED_OR_CONSUMED")
        accepted = {
            "state": "installation_reported_unverified",
            "digest": record["digest"],
            "received_at": datetime.now(timezone.utc).isoformat(),
            "deployment_sha256": hashes[0],
            "route_sha256": hashes[1],
        }
        redis.set(status_key, json.dumps(accepted), ex=STATUS_SECONDS)
    return {
        "state": "installation_reported_unverified",
        "application_id": record["application_id"],
        "production_certification": False,
        "message": "Installation reported; independent Guard route challenge still required.",
    }
