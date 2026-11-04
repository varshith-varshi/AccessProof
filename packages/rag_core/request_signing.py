"""Remote RAG -> Gateway request authentication (``ap-req-v1``).

A customer RAG application that is NOT on the Gateway's private Compose network
(another host, OS, cloud or cluster) must authenticate as an *application* on
every protected call, in addition to forwarding the employee's own identity
token (verified separately by the Guard).

Canonical string (UTF-8, newline separated)::

    ap-req-v1
    <METHOD>
    <PATH>                      (no query string; protected routes take none)
    <unix seconds>
    <nonce>                     ([A-Za-z0-9_-]{16,128}, single use)
    <sha256 hex of the exact body bytes>
    <sha256 hex of the Authorization header value>   (binds the employee token)

signature = base64url(HMAC-SHA256(client_secret, canonical)), no padding.

Headers: X-AccessProof-Client, X-AccessProof-Timestamp, X-AccessProof-Nonce,
X-AccessProof-Signature. The body hash prevents tampering (content, document
references, attestations); the Authorization hash prevents swapping a captured
signature onto another employee's token; timestamp + nonce prevent replay.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from typing import Mapping

SCHEME = "ap-req-v1"
HEADER_CLIENT = "X-AccessProof-Client"
HEADER_TIMESTAMP = "X-AccessProof-Timestamp"
HEADER_NONCE = "X-AccessProof-Nonce"
HEADER_SIGNATURE = "X-AccessProof-Signature"
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_CLIENT = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


class SignatureError(ValueError):
    pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonical(method: str, path: str, timestamp: int, nonce: str, body: bytes, authorization: str) -> bytes:
    return "\n".join([
        SCHEME, method.upper(), path, str(int(timestamp)), nonce,
        hashlib.sha256(body).hexdigest(),
        hashlib.sha256(authorization.encode("utf-8")).hexdigest(),
    ]).encode("utf-8")


def sign(secret: bytes, method: str, path: str, timestamp: int, nonce: str, body: bytes, authorization: str) -> str:
    return _b64url(hmac.new(secret, canonical(method, path, timestamp, nonce, body, authorization), hashlib.sha256).digest())


def signed_headers(client_id: str, secret: bytes, method: str, path: str, body: bytes, authorization: str,
                   *, now: int | None = None, nonce: str | None = None) -> dict[str, str]:
    if not _CLIENT.fullmatch(client_id):
        raise SignatureError("INVALID_CLIENT_ID")
    if len(secret) < 32:
        raise SignatureError("CLIENT_SECRET_TOO_SHORT")
    ts = int(time.time()) if now is None else int(now)
    nonce = nonce or secrets.token_urlsafe(24)
    return {HEADER_CLIENT: client_id, HEADER_TIMESTAMP: str(ts), HEADER_NONCE: nonce,
            HEADER_SIGNATURE: sign(secret, method, path, ts, nonce, body, authorization)}


def verify(headers: Mapping[str, str], *, method: str, path: str, body: bytes, authorization: str,
           secrets_by_client: Mapping[str, bytes], now: int, max_skew: int) -> tuple[str, str]:
    """Return (client_id, nonce) or raise SignatureError. Replay (nonce reuse) is
    checked by the caller's nonce store, after the signature is valid."""
    client = str(headers.get(HEADER_CLIENT) or "")
    ts_raw = str(headers.get(HEADER_TIMESTAMP) or "")
    nonce = str(headers.get(HEADER_NONCE) or "")
    signature = str(headers.get(HEADER_SIGNATURE) or "")
    if not client or not ts_raw or not nonce or not signature:
        raise SignatureError("CLIENT_AUTHENTICATION_REQUIRED")
    if not _CLIENT.fullmatch(client) or not _NONCE.fullmatch(nonce) or not ts_raw.isdigit() or len(signature) > 128:
        raise SignatureError("CLIENT_AUTHENTICATION_MALFORMED")
    secret = secrets_by_client.get(client)
    if secret is None:
        # Spend comparable time for unknown clients (no client enumeration).
        hmac.compare_digest(signature, sign(b"\0" * 32, method, path, int(ts_raw), nonce, body, authorization))
        raise SignatureError("CLIENT_AUTHENTICATION_FAILED")
    expected = sign(secret, method, path, int(ts_raw), nonce, body, authorization)
    if not hmac.compare_digest(signature, expected):
        raise SignatureError("CLIENT_AUTHENTICATION_FAILED")
    if abs(now - int(ts_raw)) > max_skew:
        raise SignatureError("CLIENT_REQUEST_EXPIRED")
    return client, nonce
