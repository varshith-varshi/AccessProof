from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _decode(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))


def totp_code(secret: str, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    counter = (at if at is not None else int(time.time())) // step
    digest = hmac.new(_decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return f"{value:0{digits}d}"


def verify_totp(secret: str, code: str, at: int | None = None, window: int = 1) -> bool:
    now = at if at is not None else int(time.time())
    return any(
        hmac.compare_digest(totp_code(secret, now + drift * 30), code)
        for drift in range(-window, window + 1)
    )


def matched_totp_step(secret: str, code: str, at: int | None = None, window: int = 1) -> int | None:
    """The time-step counter the code is valid for, or None.

    Callers persist the last accepted step and reject any step at or before
    it (RFC 6238 section 5.2), so an observed code cannot be replayed.
    """
    now = at if at is not None else int(time.time())
    for drift in range(-window, window + 1):
        moment = now + drift * 30
        if hmac.compare_digest(totp_code(secret, moment), code):
            return moment // 30
    return None


def provisioning_uri(secret: str, email: str, issuer: str = "AccessProof") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
