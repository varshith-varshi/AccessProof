"""ap-req-v1 request signatures (must match the Gateway; see the shared test vectors)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

SCHEME = "ap-req-v1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonical(method: str, path: str, timestamp: int, nonce: str, body: bytes, authorization: str) -> bytes:
    return "\n".join([SCHEME, method.upper(), path, str(int(timestamp)), nonce,
                      hashlib.sha256(body).hexdigest(),
                      hashlib.sha256(authorization.encode("utf-8")).hexdigest()]).encode("utf-8")


def sign(secret: bytes, method: str, path: str, timestamp: int, nonce: str, body: bytes, authorization: str) -> str:
    return _b64url(hmac.new(secret, canonical(method, path, timestamp, nonce, body, authorization), hashlib.sha256).digest())


def signed_headers(client_id: str, secret: bytes, method: str, path: str, body: bytes, authorization: str,
                   *, now: int | None = None, nonce: str | None = None) -> dict[str, str]:
    ts = int(time.time()) if now is None else int(now)
    nonce = nonce or secrets.token_urlsafe(24)
    return {"X-AccessProof-Client": client_id, "X-AccessProof-Timestamp": str(ts), "X-AccessProof-Nonce": nonce,
            "X-AccessProof-Signature": sign(secret, method, path, ts, nonce, body, authorization)}
