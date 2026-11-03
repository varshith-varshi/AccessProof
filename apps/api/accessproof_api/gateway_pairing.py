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
from typing import Any, cast

from redis import Redis
from redis.exceptions import WatchError

from apps.api.accessproof_api.config import settings

SCHEMA = "accessproof.gateway_pairing/v1"
TOKEN_SECONDS = 900
STATUS_SECONDS = 86400
INVENTORY_LIMIT = 32
# These are installation discovery facts, NEVER a security certificate.
_APP_ID = re.compile(r"^host-app-[a-f0-9]{24}$")
_SAFE_TEXT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/@ -]{0,119}$")

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


def _discovery_key(org: str, app_row: str) -> str:
    return f"accessproof:gateway-pair:v1:discovery:{org}:{app_row}"


def _validate_discovery(applications: Any) -> list[dict[str, str]]:
    """Never store secrets, arbitrary container JSON or control instructions."""
    if not isinstance(applications, list) or len(applications) > INVENTORY_LIMIT:
        raise PairingError("DISCOVERY_INVENTORY_TOO_LARGE")
    result: list[dict[str, str]] = []
    ids: set[str] = set()
    for item in applications:
        if not isinstance(item, dict):
            raise PairingError("DISCOVERY_INVALID")
        if set(item) != {"stable_id", "display_name", "compose_project", "service", "state"}:
            raise PairingError("DISCOVERY_INVALID_FIELDS")
        stable_id = item.get("stable_id")
        if not isinstance(stable_id, str) or not _APP_ID.fullmatch(stable_id) or stable_id in ids:
            raise PairingError("DISCOVERY_INVALID_ID")
        ids.add(stable_id)
        for name in ("display_name", "compose_project", "service"):
            value = item.get(name)
            if not isinstance(value, str) or not _SAFE_TEXT.fullmatch(value):
                raise PairingError("DISCOVERY_INVALID_METADATA")
        if item.get("state") not in {"SUPPORTED", "REQUIRES_INTEGRATION", "AMBIGUOUS", "NON_AI_SERVICE"}:
            raise PairingError("DISCOVERY_INVALID_STATE")
        result.append({k: item[k] for k in (
            "stable_id", "display_name", "compose_project", "service", "state",
        )})
    return result


def _authenticated_pending(redis: Redis, token: str) -> dict[str, str]:
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        raise PairingError("PAIRING_TOKEN_REQUIRED")
    record_raw = redis.get(_token_key(token))
    if not record_raw:
        raise PairingError("PAIRING_EXPIRED_OR_CONSUMED")
    record = cast(dict[str, str], json.loads(cast(bytes, record_raw)))
    current_raw = redis.get(_status_key(record["organization_id"], record["application_row_id"]))
    current = json.loads(cast(bytes, current_raw)) if current_raw else {}
    if current.get("digest") != record["digest"] or current.get("state") != "awaiting_customer_install":
        raise PairingError("PAIRING_SUPERSEDED")
    return record


def publish_discovery(*, token: str, applications: Any) -> dict[str, Any]:
    sanitized = _validate_discovery(applications)
    try:
        with _client() as redis:
            record = _authenticated_pending(redis, token)
            key = _discovery_key(record["organization_id"], record["application_row_id"])
            status_key = _status_key(record["organization_id"], record["application_row_id"])
            token_key = _token_key(token)
            with redis.pipeline() as pipe:
                pipe.watch(key, status_key, token_key)
                # Revalidate under a watched transaction; a renewed/consumed
                # token or a finished selection must not be overwritten.
                _authenticated_pending(pipe, token)
                old = pipe.get(key)
                if old:
                    prior = json.loads(old)
                    if prior.get("digest") == record["digest"] and prior.get("selected_id"):
                        raise PairingError("DISCOVERY_ALREADY_SELECTED")
                ttl = pipe.ttl(token_key)
                if ttl <= 0:
                    raise PairingError("PAIRING_EXPIRED_OR_CONSUMED")
                payload = {"digest": record["digest"], "applications": sanitized, "selected_id": None}
                pipe.multi()
                pipe.set(key, json.dumps(payload), ex=ttl)
                pipe.execute()
    except WatchError as exc:
        raise PairingError("DISCOVERY_CHANGED_RETRY") from exc
    return {"state": "awaiting_dashboard_selection", "applications_found": len(sanitized),
            "production_certification": False}

def discovery_status(*, org_id: str, app_row_id: str) -> dict[str, Any]:
    with _client() as redis:
        current_raw = redis.get(_status_key(org_id, app_row_id))
        raw = redis.get(_discovery_key(org_id, app_row_id))
    if not current_raw or not raw:
        return {"state": "not_ready", "applications": [], "selected_id": None,
                "production_certification": False}
    current = json.loads(current_raw)
    payload = json.loads(raw)
    if current.get("state") != "awaiting_customer_install" or payload.get("digest") != current.get("digest"):
        return {"state": "not_ready", "applications": [], "selected_id": None,
                "production_certification": False}
    return {"state": "selected" if payload.get("selected_id") else "awaiting_selection",
            "applications": payload.get("applications", []),
            "selected_id": payload.get("selected_id"),
            "production_certification": False}


def select_discovered(*, org_id: str, app_row_id: str, stable_id: str) -> dict[str, Any]:
    if not isinstance(stable_id, str) or not _APP_ID.fullmatch(stable_id):
        raise PairingError("DISCOVERY_INVALID_ID")
    key = _discovery_key(org_id, app_row_id)
    try:
        with _client() as redis:
            with redis.pipeline() as pipe:
                pipe.watch(key, _status_key(org_id, app_row_id))
                raw = pipe.get(key)
                status_raw = pipe.get(_status_key(org_id, app_row_id))
                if not raw or not status_raw:
                    raise PairingError("DISCOVERY_NOT_AVAILABLE")
                payload = json.loads(raw)
                status = json.loads(status_raw)
                if (payload.get("digest") != status.get("digest")
                        or status.get("state") != "awaiting_customer_install"):
                    raise PairingError("DISCOVERY_EXPIRED")
                if payload.get("selected_id"):
                    raise PairingError("DISCOVERY_ALREADY_SELECTED")
                if not any(x.get("stable_id") == stable_id and x.get("state") == "SUPPORTED"
                           for x in payload.get("applications", [])):
                    raise PairingError("SELECTED_CHATBOT_NOT_SUPPORTED")
                payload["selected_id"] = stable_id
                ttl = pipe.ttl(key)
                if ttl <= 0:
                    raise PairingError("DISCOVERY_EXPIRED")
                pipe.multi()
                pipe.set(key, json.dumps(payload), ex=ttl)
                pipe.execute()
    except WatchError as exc:
        raise PairingError("DISCOVERY_CHANGED_RETRY") from exc
    return {"state": "selected", "selected_id": stable_id, "production_certification": False}

def selected_for_host(*, token: str) -> dict[str, Any]:
    with _client() as redis:
        record = _authenticated_pending(redis, token)
        key = _discovery_key(record["organization_id"], record["application_row_id"])
        raw = redis.get(key)
    if not raw:
        return {"state": "not_ready", "selected_id": None}
    payload = json.loads(raw)
    if payload.get("digest") != record["digest"]:
        raise PairingError("DISCOVERY_SUPERSEDED")
    return {"state": "selected" if payload.get("selected_id") else "awaiting_selection",
            "selected_id": payload.get("selected_id")}


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


def clear(*, org_id: str, app_row_id: str) -> None:
    """Forget pending pairing/discovery state for an archived application.

    Outstanding one-use tokens become unusable because the status digest they
    must match no longer exists.
    """
    with _client() as redis:
        redis.delete(_status_key(org_id, app_row_id), _discovery_key(org_id, app_row_id))
