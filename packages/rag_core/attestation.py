"""Opt-in source-backed content attestations for *certified* customer RAG routes.

Trust boundary: private signing keys belong to an independent, authenticated
source-ingestion service. Do NOT give signing keys to retrieval, model, tool,
or application code. The RAG SDK receives only the pinned verification key.
An attestation proves only what the trusted ingester signed: it cannot prove
the original bytes came from Google/Microsoft without secure provider fetch.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class AttestationError(ValueError):
    """Absent, forged, stale or wrong-bound source-content attestation."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(data: str) -> bytes:
    if not data or len(data) > 8000:
        raise AttestationError("Invalid attestation encoding")
    try:
        return base64.b64decode(
            data + "=" * (-len(data) % 4), altchars=b"-_", validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise AttestationError("Invalid attestation encoding") from exc


def _canonical(claims: Mapping[str, Any]) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ContentBinding:
    tenant_id: str
    application_id: str
    source_id: str
    resource_id: str
    chunk_id: str | None
    content_version: str
    content: str

    def __post_init__(self) -> None:
        if any(not value for value in (
            self.tenant_id, self.application_id, self.source_id,
            self.resource_id, self.content_version,
        )):
            raise AttestationError("Complete source and tenant binding is required")


class SourceAttestationSigner:
    """Trusted-ingestion-side only. Never instantiate inside the RAG application."""

    def __init__(self, *, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if not key_id or len(key_id) > 128:
            raise AttestationError("A key identifier is required")
        self.key_id = key_id
        self._private_key = private_key

    def issue(self, binding: ContentBinding, *, ttl_seconds: int = 300, now: int | None = None) -> str:
        if not 1 <= ttl_seconds <= 3600:
            raise AttestationError("Attestation TTL must be 1–3600 seconds")
        timestamp = int(time.time()) if now is None else int(now)
        claims = {
            "v": 1,
            "kid": self.key_id,
            "tenant": binding.tenant_id,
            "app": binding.application_id,
            "source": binding.source_id,
            "resource": binding.resource_id,
            "chunk": binding.chunk_id,
            "revision": binding.content_version,
            "sha256": _digest(binding.content),
            "iat": timestamp,
            "exp": timestamp + ttl_seconds,
        }
        payload = _canonical(claims)
        return f"{_b64url(payload)}.{_b64url(self._private_key.sign(payload))}"


class SourceAttestationVerifier:
    """Customer RAG side: pinned public keys only; does not trust document metadata."""

    def __init__(
        self, *, tenant_id: str, trusted_keys: Mapping[str, Ed25519PublicKey],
        max_clock_skew_seconds: int = 30,
        revoked_key_ids: Iterable[str] = (),
    ) -> None:
        if not tenant_id or not trusted_keys:
            raise AttestationError("Tenant and trusted ingestion public key are required")
        self.tenant_id = tenant_id
        self.trusted_keys = dict(trusted_keys)
        self.max_clock_skew_seconds = max_clock_skew_seconds
        # Revocation is checked before signature verification so a compromised
        # ingestion key cannot outlive its operator removal.
        self.revoked_key_ids = frozenset(revoked_key_ids)
        if self.revoked_key_ids & set(self.trusted_keys):
            raise AttestationError("A signing key cannot be both trusted and revoked")

    def verify_digest(
        self, *, tenant_id: str, application_id: str, source_id: str, resource_id: str,
        chunk_id: str | None, content_version: str, content_digest: str, token: str | None,
        now: int | None = None,
    ) -> None:
        """Verify an attestation against a stored digest without loading source text.

        Used by protected answer-cache delivery. The source bytes remain in the
        customer cache; their signed digest is still checked at the release boundary.
        """
        if (tenant_id != self.tenant_id or not token or len(token) > 16000
                or len(content_digest) != 64):
            raise AttestationError("Missing or invalid trusted provenance")
        try:
            encoded_payload, encoded_signature = token.split(".")
            payload = _unb64url(encoded_payload)
            signature = _unb64url(encoded_signature)
            claims = json.loads(payload)
            if not isinstance(claims, dict) or _canonical(claims) != payload:
                raise AttestationError("Non-canonical attestation")
            key_id = claims.get("kid")
            if not isinstance(key_id, str) or key_id in self.revoked_key_ids:
                raise AttestationError("Revoked or unknown ingestion key")
            public_key = self.trusted_keys.get(key_id)
            if public_key is None:
                raise AttestationError("Unknown ingestion key")
            public_key.verify(signature, payload)
            timestamp = int(time.time()) if now is None else int(now)
            if (
                type(claims.get("v")) is not int or claims["v"] != 1
                or type(claims.get("iat")) is not int or type(claims.get("exp")) is not int
                or claims["iat"] > timestamp + self.max_clock_skew_seconds
                or claims["exp"] <= timestamp or claims["exp"] <= claims["iat"]
                or claims["exp"] - claims["iat"] > 3600
            ):
                raise AttestationError("Stale or invalid attestation lifetime")
            expected = {"tenant": tenant_id, "app": application_id, "source": source_id,
                        "resource": resource_id, "chunk": chunk_id, "revision": content_version}
            if any(claims.get(name) != value for name, value in expected.items()):
                raise AttestationError("Source content binding mismatch")
            if not isinstance(claims.get("sha256"), str) or not hmac.compare_digest(
                claims["sha256"], content_digest,
            ):
                raise AttestationError("Source content digest mismatch")
        except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise AttestationError("Untrusted or invalid source attestation") from exc

    def verify(
        self, binding: ContentBinding, token: str | None, *, now: int | None = None,
    ) -> None:
        if binding.tenant_id != self.tenant_id or not token or len(token) > 16000:
            raise AttestationError("Missing or invalid trusted provenance")
        try:
            encoded_payload, encoded_signature = token.split(".")
            payload = _unb64url(encoded_payload)
            signature = _unb64url(encoded_signature)
            claims = json.loads(payload)
            if not isinstance(claims, dict) or _canonical(claims) != payload:
                raise AttestationError("Non-canonical attestation")
            key_id = claims.get("kid")
            if not isinstance(key_id, str) or key_id in self.revoked_key_ids:
                raise AttestationError("Revoked or unknown ingestion key")
            public_key = self.trusted_keys.get(key_id)
            if public_key is None:
                raise AttestationError("Unknown ingestion key")
            public_key.verify(signature, payload)
            timestamp = int(time.time()) if now is None else int(now)
            if (
                type(claims.get("v")) is not int or claims["v"] != 1
                or type(claims.get("iat")) is not int
                or type(claims.get("exp")) is not int
                or claims["iat"] > timestamp + self.max_clock_skew_seconds
                or claims["exp"] <= timestamp
                or claims["exp"] <= claims["iat"]
                or claims["exp"] - claims["iat"] > 3600
            ):
                raise AttestationError("Stale or invalid attestation lifetime")
            expected = {
                "tenant": binding.tenant_id,
                "app": binding.application_id,
                "source": binding.source_id,
                "resource": binding.resource_id,
                "chunk": binding.chunk_id,
                "revision": binding.content_version,
            }
            if any(claims.get(name) != value for name, value in expected.items()):
                raise AttestationError("Source content binding mismatch")
            if not isinstance(claims.get("sha256"), str) or not hmac.compare_digest(
                claims["sha256"], _digest(binding.content),
            ):
                raise AttestationError("Source content digest mismatch")
        except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise AttestationError("Untrusted or invalid source attestation") from exc
