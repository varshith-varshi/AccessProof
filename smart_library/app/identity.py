"""Signed member identity.

The system never trusts a bare email or a member id sent by the client. Every request
carries a token signed by the library's identity service; the token's ``sub`` is the
member's immutable id, which is what the Guard maps to access grants.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

from .clock import Clock


class IdentityError(Exception):
    """Raised when an identity cannot be verified. Callers must fail closed."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(secret: str, payload: dict) -> str:
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    mac = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(mac)}"


def verify(secret: str, token: str) -> dict:
    try:
        body, mac = token.split(".")
    except ValueError as exc:
        raise IdentityError("malformed token") from exc
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    try:
        given = _unb64(mac)
    except Exception as exc:  # noqa: BLE001 - any decode failure is a verification failure
        raise IdentityError("malformed signature") from exc
    if not hmac.compare_digest(expected, given):
        raise IdentityError("bad signature")
    try:
        return json.loads(_unb64(body))
    except Exception as exc:  # noqa: BLE001
        raise IdentityError("malformed payload") from exc


@dataclass(frozen=True)
class VerifiedMember:
    member_id: str


class IdentityService:
    def __init__(self, secret: str, ttl_seconds: int, clock: Clock) -> None:
        self._secret = secret
        self._ttl = ttl_seconds
        self._clock = clock

    def issue(self, member_id: str) -> str:
        now = self._clock.now()
        return sign(self._secret, {"typ": "member", "sub": member_id, "iat": now, "exp": now + self._ttl})

    def verify(self, token: str | None) -> VerifiedMember:
        if not token:
            raise IdentityError("missing token")
        claims = verify(self._secret, token)
        if claims.get("typ") != "member" or not isinstance(claims.get("sub"), str):
            raise IdentityError("not a member token")
        if float(claims.get("exp", 0)) < self._clock.now():
            raise IdentityError("token expired")
        return VerifiedMember(member_id=claims["sub"])
