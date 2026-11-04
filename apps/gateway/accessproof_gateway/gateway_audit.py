"""Signed, hash-chained Gateway audit log (evidence for route certification).

Every protected request (``/v1/*``) the Gateway answers, including application
authentication failures and denials, appends one JSON line:

    {"v":1, "seq":N, "at":..., "key_id":..., "prev":"<sha256 of previous line>",
     "client_id":..., "method":..., "path":..., "http_status":...,
     "request_id":..., "decision_id":..., "decision":..., "reason":...,
     "request_sha256":..., "response_sha256":..., "sig":"<base64url Ed25519>"}

The signature covers the canonical JSON of every other field, and ``prev``
chains the lines, so a deleted, reordered or edited record is detected. The
Gateway refuses to release a response it couldn't audit: 503
``GATEWAY_AUDIT_UNAVAILABLE``, which fails closed.

Env: ACCESSPROOF_GATEWAY_AUDIT_LOG (file path), ACCESSPROOF_GATEWAY_AUDIT_KEY_FILE
(raw 32-byte or PEM Ed25519 private key, 0600), ACCESSPROOF_GATEWAY_AUDIT_KEY_ID.
No employee tokens, questions, document content or answers are written:
only identifiers, status codes and hashes.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

AUDIT_CONTEXT: contextvars.ContextVar[dict | None] = contextvars.ContextVar("accessproof_gateway_audit", default=None)
_FIELDS = ("request_id", "decision_id", "decision", "reason")


class GatewayAuditError(RuntimeError):
    pass


def audit_note(**fields: Any) -> None:
    """Record decision identifiers for the current request (no content)."""
    ctx = AUDIT_CONTEXT.get()
    if ctx is not None:
        ctx.update({k: (str(v) if v is not None else None) for k, v in fields.items() if k in _FIELDS})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _canonical(record: dict) -> bytes:
    return json.dumps({k: v for k, v in record.items() if k != "sig"}, sort_keys=True, separators=(",", ":")).encode()


def load_private_key(path: str) -> Ed25519PrivateKey:
    raw = Path(path).read_bytes()
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise GatewayAuditError("AUDIT_KEY_NOT_ED25519")
    return key


class GatewayAuditLog:
    def __init__(self, path: str, key: Ed25519PrivateKey, key_id: str) -> None:
        self.path, self.key, self.key_id = Path(path), key, key_id
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = 0, "0" * 64
        if self.path.exists():
            # Resume the chain; refuse to continue a log whose tail is not ours.
            last = None
            with self.path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        last = line.rstrip(b"\n")
            if last is not None:
                rec = json.loads(last)
                verify_record(rec, key.public_key())
                self._seq, self._prev = int(rec["seq"]), hashlib.sha256(last).hexdigest()

    @classmethod
    def from_env(cls) -> "GatewayAuditLog | None":
        path = os.getenv("ACCESSPROOF_GATEWAY_AUDIT_LOG", "")
        key_file = os.getenv("ACCESSPROOF_GATEWAY_AUDIT_KEY_FILE", "")
        if not path and not key_file:
            return None
        if not (path and key_file):
            raise GatewayAuditError("ACCESSPROOF_GATEWAY_AUDIT_LOG and _AUDIT_KEY_FILE go together")
        return cls(path, load_private_key(key_file), os.getenv("ACCESSPROOF_GATEWAY_AUDIT_KEY_ID", "gateway-audit"))

    def public_key_b64(self) -> str:
        return _b64(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def append(self, *, client_id: str | None, method: str, path: str, http_status: int,
               request_body: bytes, response_body: bytes, notes: dict | None) -> dict:
        notes = dict(notes or {})
        if not notes.get("request_id"):
            try:
                rid = json.loads(request_body or b"{}").get("request_id")
                notes["request_id"] = rid if isinstance(rid, str) and len(rid) <= 255 else None
            except (ValueError, AttributeError):
                notes["request_id"] = None
        if not notes.get("reason") and http_status >= 400:
            try:
                detail = json.loads(response_body or b"{}").get("detail")
                notes["reason"] = detail.get("code") if isinstance(detail, dict) else (str(detail)[:120] if detail else None)
            except (ValueError, AttributeError):
                notes["reason"] = None
        with self._lock:
            record = {"v": 1, "seq": self._seq + 1, "at": datetime.now(timezone.utc).isoformat(),
                      "key_id": self.key_id, "prev": self._prev, "client_id": client_id,
                      "method": method, "path": path, "http_status": int(http_status),
                      **{k: notes.get(k) for k in _FIELDS},
                      "request_sha256": hashlib.sha256(request_body or b"").hexdigest(),
                      "response_sha256": hashlib.sha256(response_body or b"").hexdigest()}
            record["sig"] = _b64(self.key.sign(_canonical(record)))
            line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            with self.path.open("ab") as fh:
                fh.write(line + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq, self._prev = record["seq"], hashlib.sha256(line).hexdigest()
            return record


def verify_record(record: dict, public_key: Ed25519PublicKey) -> None:
    sig = record.get("sig")
    if not isinstance(sig, str):
        raise GatewayAuditError("AUDIT_SIGNATURE_MISSING")
    try:
        public_key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), _canonical(record))
    except Exception as exc:
        raise GatewayAuditError("AUDIT_SIGNATURE_INVALID") from exc


def verify_log(lines: Iterable[bytes], public_key: Ed25519PublicKey) -> list[dict]:
    """Verify every signature and the hash chain; return the records."""
    out, prev, seq = [], "0" * 64, 0
    for raw in lines:
        raw = raw.rstrip(b"\n")
        if not raw:
            continue
        rec = json.loads(raw)
        verify_record(rec, public_key)
        if rec.get("prev") != prev or int(rec.get("seq", -1)) != seq + 1:
            raise GatewayAuditError("AUDIT_CHAIN_BROKEN")
        prev, seq = hashlib.sha256(raw).hexdigest(), int(rec["seq"])
        out.append(rec)
    return out


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
