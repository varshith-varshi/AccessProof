from __future__ import annotations

from typing import Any

import hashlib
import hmac
import json
import time


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_payload(
    secret: str, payload: dict[str, Any], timestamp: int | None = None
) -> dict[str, str]:
    ts = timestamp or int(time.time())
    body = canonical_payload(payload)
    message = str(ts).encode() + b"." + body
    signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return {"X-AccessProof-Timestamp": str(ts), "X-AccessProof-Signature": f"v1={signature}"}


def verify_signature(
    secret: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    *,
    now: int | None = None,
    tolerance_seconds: int = 300,
) -> bool:
    try:
        ts = int(headers["X-AccessProof-Timestamp"])
        given = headers["X-AccessProof-Signature"]
    except (KeyError, ValueError):
        return False
    now = now or int(time.time())
    if abs(now - ts) > tolerance_seconds:
        return False
    expected = sign_payload(secret, payload, timestamp=ts)["X-AccessProof-Signature"]
    return hmac.compare_digest(given, expected)
