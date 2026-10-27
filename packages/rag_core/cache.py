"""Cache-agnostic, signed answer-dependency manifests for protected RAG routes.

This module never reads a customer's cache.  The customer cache may be Redis,
an in-process map, or a database; the boundary is the authenticated manifest
written by a trusted generation service and verified before a cache hit is sent
to an employee.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .attestation import AttestationError


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    # A signed answer can legitimately depend on dozens of individually
    # attested chunks. Bound the decoder to 512 KiB rather than rejecting
    # otherwise valid manifests around ~20 dependencies.
    if not value or len(value) > 512_000:
        raise AttestationError("Invalid cache manifest encoding")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AttestationError("Invalid cache manifest encoding") from exc


def _canonical(claims: Mapping[str, Any]) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CacheDependency:
    source_id: str
    resource_id: str
    chunk_id: str | None
    content_version: str
    content_digest: str
    content_attestation: str
    derived_type: str = "cache"

    def __post_init__(self) -> None:
        if not all((self.source_id, self.resource_id, self.content_version, self.content_digest, self.content_attestation)):
            raise AttestationError("Complete cache dependency provenance is required")
        if len(self.content_digest) != 64 or any(char not in "0123456789abcdef" for char in self.content_digest):
            raise AttestationError("Invalid cache dependency digest")

    @property
    def identity(self) -> tuple[str, str, str | None]:
        return self.source_id, self.resource_id, self.chunk_id


@dataclass(frozen=True)
class CachedAnswerManifest:
    tenant_id: str
    application_id: str
    answer: str
    dependencies: tuple[CacheDependency, ...]
    producer_id: str
    # Optional while a legacy Guard is being upgraded. Once the Guard reports
    # the current authorization revision, release fails closed without it.
    authorization_revision: int | None = None
    authorization_revision_hash: str | None = None

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.application_id, self.answer, self.producer_id)) or not self.dependencies:
            raise AttestationError("Complete cached-answer binding is required")
        identities = [item.identity for item in self.dependencies]
        if len(set(identities)) != len(identities):
            raise AttestationError("Duplicate cache dependencies are not allowed")
        if (self.authorization_revision is None) != (self.authorization_revision_hash is None):
            raise AttestationError("Complete cached-answer authorization revision binding is required")
        if self.authorization_revision is not None:
            if (not isinstance(self.authorization_revision, int)
                    or isinstance(self.authorization_revision, bool)
                    or self.authorization_revision < 1):
                raise AttestationError("Invalid cached-answer authorization revision")
            _validate_revision_hash(self.authorization_revision_hash)


def _validate_revision_hash(value: str | None) -> None:
    if (not isinstance(value, str) or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise AttestationError("Invalid cached-answer authorization revision hash")


class CachedAnswerManifestSigner:
    """Trusted cache-write boundary only; never expose its private key to a model."""
    def __init__(self, *, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if not key_id or len(key_id) > 128:
            raise AttestationError("A cache manifest key identifier is required")
        self.key_id = key_id
        self._private_key = private_key

    def issue(self, manifest: CachedAnswerManifest, *, ttl_seconds: int = 300, now: int | None = None) -> str:
        if not 1 <= ttl_seconds <= 3600:
            raise AttestationError("Cache manifest TTL must be 1–3600 seconds")
        timestamp = int(time.time()) if now is None else int(now)
        claims = {
            "v": 1, "kind": "cached-answer", "kid": self.key_id,
            "tenant": manifest.tenant_id, "app": manifest.application_id,
            "answer_sha256": _digest(manifest.answer), "producer": manifest.producer_id,
            "dependencies": [
                {"source": item.source_id, "resource": item.resource_id, "chunk": item.chunk_id,
                 "revision": item.content_version, "sha256": item.content_digest,
                 "attestation": item.content_attestation, "type": item.derived_type}
                for item in manifest.dependencies
            ],
            "iat": timestamp, "exp": timestamp + ttl_seconds,
        }
        if manifest.authorization_revision is not None:
            claims["authz_revision"] = manifest.authorization_revision
            claims["authz_revision_hash"] = manifest.authorization_revision_hash
        payload = _canonical(claims)
        return f"{_b64url(payload)}.{_b64url(self._private_key.sign(payload))}"


class CachedAnswerManifestVerifier:
    """Verifies provenance and binding before a physical-cache hit is released."""
    def __init__(self, *, tenant_id: str, trusted_keys: Mapping[str, Ed25519PublicKey], max_clock_skew_seconds: int = 30) -> None:
        if not tenant_id or not trusted_keys:
            raise AttestationError("Tenant and trusted cache manifest keys are required")
        self.tenant_id = tenant_id
        self.trusted_keys = dict(trusted_keys)
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def verify(self, manifest: CachedAnswerManifest, token: str | None, *, now: int | None = None) -> None:
        if manifest.tenant_id != self.tenant_id or not token:
            raise AttestationError("Missing cached-answer manifest")
        try:
            encoded_payload, encoded_signature = token.split(".")
            payload, signature = _unb64url(encoded_payload), _unb64url(encoded_signature)
            claims = json.loads(payload)
            if not isinstance(claims, dict) or _canonical(claims) != payload:
                raise AttestationError("Non-canonical cache manifest")
            key_id = claims.get("kid")
            public_key = self.trusted_keys.get(key_id) if isinstance(key_id, str) else None
            if public_key is None:
                raise AttestationError("Unknown cache manifest key")
            public_key.verify(signature, payload)
            timestamp = int(time.time()) if now is None else int(now)
            if (claims.get("v") != 1 or claims.get("kind") != "cached-answer"
                    or not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int)
                    or claims["iat"] > timestamp + self.max_clock_skew_seconds or claims["exp"] <= timestamp
                    or claims["exp"] <= claims["iat"] or claims["exp"] - claims["iat"] > 3600):
                raise AttestationError("Stale or invalid cache manifest lifetime")
            expected = {"tenant": manifest.tenant_id, "app": manifest.application_id,
                        "answer_sha256": _digest(manifest.answer), "producer": manifest.producer_id}
            if any(claims.get(key) != value for key, value in expected.items()):
                raise AttestationError("Cached-answer manifest binding mismatch")
            # A signed token without revision claims is valid only for a
            # revision-less legacy manifest. A manifest claiming a revision
            # can never be paired with a token that omits or changes it.
            if (claims.get("authz_revision") != manifest.authorization_revision
                    or claims.get("authz_revision_hash") != manifest.authorization_revision_hash):
                raise AttestationError("Cached-answer authorization revision mismatch")
            dependencies = claims.get("dependencies")
            if not isinstance(dependencies, list) or len(dependencies) != len(manifest.dependencies):
                raise AttestationError("Incomplete cached-answer provenance")
            canonical_dependencies = [
                {"source": item.source_id, "resource": item.resource_id, "chunk": item.chunk_id,
                 "revision": item.content_version, "sha256": item.content_digest,
                 "attestation": item.content_attestation, "type": item.derived_type}
                for item in manifest.dependencies
            ]
            if dependencies != canonical_dependencies:
                raise AttestationError("Cached-answer dependency mismatch")
        except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise AttestationError("Untrusted or invalid cached-answer manifest") from exc
