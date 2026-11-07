"""Independent local *readiness* check for signed SharePoint index chunks.

This never authorizes access: the customer Gateway's Guard and signed-source
verifier remain the only answer-release boundary. This verifies freshness,
signature and source binding to prevent stale-data false-ready UIs.
"""
from __future__ import annotations

import base64
from contextlib import closing
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class IndexEvidenceInvalid(ValueError):
    pass


def _decode(value: str) -> bytes:
    if not value or len(value) > 8000:
        raise IndexEvidenceInvalid("BAD_TOKEN_ENCODING")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IndexEvidenceInvalid("BAD_TOKEN_ENCODING") from exc


def _keys() -> dict[str, Ed25519PublicKey]:
    try:
        obj = json.loads(os.getenv("LAB_SOURCE_PUBLIC_KEYS_JSON", ""))
        if not isinstance(obj, dict) or not obj or len(obj) > 8:
            raise ValueError("INVALID_KEYS")
        keys = {key: Ed25519PublicKey.from_public_bytes(_decode(value))
                for key, value in obj.items() if isinstance(key, str) and isinstance(value, str)}
        if len(keys) != len(obj):
            raise ValueError("INVALID_KEY_ENTRY")
        return keys
    except (ValueError, TypeError, IndexEvidenceInvalid) as exc:
        raise IndexEvidenceInvalid("PINNED_SOURCE_PUBLIC_KEY_MISSING") from exc


def verify_chunk(row: sqlite3.Row, *, keys: dict[str, Ed25519PublicKey],
                 now: int, safety_margin_seconds: int = 120) -> int:
    token = row["attestation"]
    if not isinstance(token, str) or len(token) > 16000:
        raise IndexEvidenceInvalid("SIGNED_EVIDENCE_MISSING")
    try:
        encoded, signature = token.split(".")
        payload, sig = _decode(encoded), _decode(signature)
        claims = json.loads(payload)
        if (not isinstance(claims, dict) or
                json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() != payload):
            raise IndexEvidenceInvalid("NONCANONICAL_SIGNATURE")
        kid = claims.get("kid")
        if kid not in keys:
            raise IndexEvidenceInvalid("UNRECOGNIZED_SIGNING_KEY")
        keys[kid].verify(sig, payload)
        expires = claims.get("exp")
        issued = claims.get("iat")
        if (type(expires) is not int or type(issued) is not int or
                expires <= now + safety_margin_seconds or issued > now + 30
                or expires <= issued or expires - issued > 3600):
            raise IndexEvidenceInvalid("ATTESTATION_EXPIRED_OR_NEAR_EXPIRY")
        expected = {
            "v": 1,
            "tenant": os.environ["LAB_TENANT_ID"],
            "app": os.environ["LAB_APPLICATION_ID"],
            "source": os.environ["LAB_SOURCE_ID"],
            "resource": row["doc_id"],
            "chunk": row["chunk_id"],
            "revision": row["version"],
        }
        if any(claims.get(name) != value for name, value in expected.items()):
            raise IndexEvidenceInvalid("SIGNED_SOURCE_BINDING_MISMATCH")
        digest = hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
        if not isinstance(claims.get("sha256"), str) or not hmac.compare_digest(claims["sha256"], digest):
            raise IndexEvidenceInvalid("SIGNED_CONTENT_DIGEST_MISMATCH")
        return expires - now
    except (InvalidSignature, ValueError, TypeError, AttributeError, KeyError, OSError) as exc:
        if isinstance(exc, IndexEvidenceInvalid):
            raise
        raise IndexEvidenceInvalid("SIGNATURE_VERIFICATION_FAILED") from exc


def inspect_index(path: str, *, now: int | None = None) -> dict:
    current = int(time.time()) if now is None else int(now)
    state = {
        "signed_index_ready": False,
        "signed_chunks_valid": 0,
        "signed_chunks_total": 0,
        "oldest_signature_expires_in_seconds": 0,
        "last_sync_age_seconds": None,
        "reason_code": "SIGNED_INDEX_UNAVAILABLE",
    }
    try:
        if not Path(path).is_file():
            return state
        keys = _keys()
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            entry = db.execute("SELECT value FROM metadata WHERE key='last_sync'").fetchone()
            age = current - int(entry["value"]) if entry else 999999999
            state["last_sync_age_seconds"] = age
            if age < -30 or age > 900:
                state["reason_code"] = "SOURCE_SYNC_STALE"
                return state
            count = db.execute("SELECT count(*) FROM chunks").fetchone()[0]
            state["signed_chunks_total"] = int(count)
            if not 0 < count <= 50000:
                state["reason_code"] = "SIGNED_INDEX_EMPTY_OR_TOO_LARGE"
                return state
            oldest = 999999999
            for row in db.execute("SELECT doc_id,chunk_id,text,version,attestation FROM chunks"):
                lifetime = verify_chunk(row, keys=keys, now=current)
                oldest = min(oldest, lifetime)
                state["signed_chunks_valid"] += 1
        state["signed_index_ready"] = True
        state["oldest_signature_expires_in_seconds"] = oldest
        state["reason_code"] = "OK"
    except (sqlite3.Error, IndexEvidenceInvalid, OSError, ValueError, KeyError, TypeError) as exc:
        # Safe machine codes only. Never print document, token or source bytes.
        state["reason_code"] = (str(exc) if isinstance(exc, IndexEvidenceInvalid)
                                else "SIGNED_INDEX_INSPECTION_FAILED")
    return state
