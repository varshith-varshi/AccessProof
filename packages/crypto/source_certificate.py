"""Asymmetric source effective-permission certificates (defect D-01).

The control-plane API only *verifies* certificates with pinned Ed25519 public
keys. Signing happens in a separate, operator-controlled certifier process
(``scripts/issue_source_certificate.py``) that holds the private key and that
refuses to sign unless a complete set of independently observed live checks
passed for the exact source scope.

This module never fabricates evidence. It defines the canonical byte format,
the required-check contract, signing (certifier only) and verification.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

VERIFIER_VERSION = "provider-live-v2-ed25519"
EVIDENCE_SCHEMA = "accessproof.source_certification_evidence/v1"
SIGNATURE_PREFIX = "ed25519"
# A certificate attests that the provider-live profile of ONE exact source
# scope was verified end to end. Evidence must be < MAX_EVIDENCE_AGE at
# issuance; validity is only the buffer if rolling renewal (every ~3 weeks,
# fresh evidence each time) fails. Continuous ACL/directory freshness is
# enforced separately and is not extended by this value.
MAX_VALIDITY = timedelta(days=30)
MAX_EVIDENCE_AGE = timedelta(hours=72)
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Every check below must be independently observed against the real tenant,
# the real customer route and real employee identities. A permission matrix
# alone is not sufficient (see docs/SHAREPOINT_CERTIFICATION_ACTUAL_GATES_*.md).
REQUIRED_CHECKS: tuple[str, ...] = (
    "PROVIDER_EFFECTIVE_PERMISSION_MATRIX",   # item-level allow/deny per employee
    "EMPLOYEE_OIDC_POSITIVE_IDENTITY",        # real Entra sign-in, signature/iss/aud/tid
    "EMPLOYEE_OIDC_SECOND_IDENTITY",          # a distinct second employee
    "IDENTITY_MAPPING_IMMUTABLE_OBJECT_ID",   # oid -> source principal, not email
    "INHERITED_AND_GROUP_PERMISSIONS",        # inherited ACL and group-derived grants
    "PROVIDER_REVOKE_OBSERVED",               # effective rights actually changed
    "PROVIDER_RESTORE_OBSERVED",
    "GATEWAY_ROUTE_AUTHORIZED_RELEASE",       # Layer 1 + Layer 2 allow, real route
    "GATEWAY_ROUTE_UNAUTHORIZED_DENIED",      # Layer 1 deny, no model context
    "GATEWAY_POST_REVOCATION_DENIED",
    "GATEWAY_INFLIGHT_REVOCATION_DENIED",
    "CACHED_ANSWER_REUSE_DENIED",
    "PROVENANCE_TAMPER_REJECTED",
    "BUFFERED_RELEASE_VERIFIED",
)


class CertificateError(ValueError):
    pass


@dataclass(frozen=True)
class CertificateFields:
    organization_id: str
    source_id: str
    profile: str
    scope_digest: str
    evidence_digest: str
    verifier_version: str
    certified_at: datetime
    expires_at: datetime


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def canonical_payload(fields: CertificateFields, key_id: str) -> bytes:
    """Domain-separated canonical bytes; key ID is signed to stop key confusion."""
    payload = {
        "domain": "accessproof.source_effective_certificate/v2",
        "key_id": key_id,
        "organization_id": fields.organization_id,
        "source_id": fields.source_id,
        "profile": fields.profile,
        "scope_digest": fields.scope_digest,
        "evidence_digest": fields.evidence_digest,
        "verifier_version": fields.verifier_version,
        # Normalise to UTC so a DB round trip cannot change the signed bytes.
        "certified_at": _utc(fields.certified_at).replace(microsecond=0).isoformat(),
        "expires_at": _utc(fields.expires_at).replace(microsecond=0).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def load_public_keys(raw: str) -> dict[str, Ed25519PublicKey]:
    """Parse ``{"key_id": "<base64url raw 32-byte public key>"}``; empty on error."""
    if not raw:
        return {}
    try:
        encoded = json.loads(raw)
        if not isinstance(encoded, dict) or not encoded or len(encoded) > 8:
            return {}
        keys: dict[str, Ed25519PublicKey] = {}
        for key_id, value in encoded.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id) or not isinstance(value, str):
                return {}
            material = _b64d(value)
            if len(material) != 32:
                return {}
            keys[key_id] = Ed25519PublicKey.from_public_bytes(material)
        return keys
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError):
        return {}


def verify_certificate_signature(
    fields: CertificateFields, signature: str, trusted_keys: Mapping[str, Ed25519PublicKey],
) -> bool:
    if not isinstance(signature, str) or len(signature) > 160:
        return False
    parts = signature.split(":")
    if len(parts) != 3 or parts[0] != SIGNATURE_PREFIX or not _KEY_ID.fullmatch(parts[1]):
        return False
    key = trusted_keys.get(parts[1])
    if key is None or fields.verifier_version != VERIFIER_VERSION:
        return False
    try:
        raw = _b64d(parts[2])
        if len(raw) != 64:
            return False
        key.verify(raw, canonical_payload(fields, parts[1]))
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def sign_certificate(fields: CertificateFields, private_key: Ed25519PrivateKey, key_id: str) -> str:
    """Certifier-only. The control-plane API must never call this."""
    if not _KEY_ID.fullmatch(key_id):
        raise CertificateError("INVALID_KEY_ID")
    raw = private_key.sign(canonical_payload(fields, key_id))
    return f"{SIGNATURE_PREFIX}:{key_id}:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def evidence_digest(evidence: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_evidence(
    evidence: Mapping[str, Any], *, organization_id: str, source_id: str,
    profile: str, scope_digest: str, now: datetime | None = None,
) -> str:
    """Return the evidence digest only if every required check PASSED.

    BLOCKED, NOT_TESTED, FAIL, missing, duplicated, stale, future-dated or
    scope-mismatched entries all refuse issuance. Never counts a skip as a pass.
    """
    now = _utc(now or datetime.now(timezone.utc))
    if not isinstance(evidence, Mapping) or evidence.get("schema") != EVIDENCE_SCHEMA:
        raise CertificateError("EVIDENCE_SCHEMA_INVALID")
    for name, expected in (("organization_id", organization_id), ("source_id", source_id),
                           ("profile", profile), ("scope_digest", scope_digest)):
        if evidence.get(name) != expected:
            raise CertificateError(f"EVIDENCE_SCOPE_MISMATCH:{name}")
    checks = evidence.get("checks")
    if not isinstance(checks, list):
        raise CertificateError("EVIDENCE_CHECKS_MISSING")
    seen: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        if not isinstance(check, Mapping) or not isinstance(check.get("code"), str):
            raise CertificateError("EVIDENCE_CHECK_INVALID")
        if check["code"] in seen:
            raise CertificateError(f"EVIDENCE_CHECK_DUPLICATED:{check['code']}")
        seen[check["code"]] = check
    for code in REQUIRED_CHECKS:
        check = seen.get(code)
        if check is None:
            raise CertificateError(f"REQUIRED_CHECK_MISSING:{code}")
        if check.get("status") != "PASS":
            raise CertificateError(f"REQUIRED_CHECK_NOT_PASSED:{code}")
        if not isinstance(check.get("artifact_sha256"), str) or not _HEX64.fullmatch(check["artifact_sha256"]):
            raise CertificateError(f"REQUIRED_CHECK_ARTIFACT_MISSING:{code}")
        try:
            observed = _utc(datetime.fromisoformat(str(check.get("observed_at")).replace("Z", "+00:00")))
        except ValueError as exc:
            raise CertificateError(f"REQUIRED_CHECK_TIME_INVALID:{code}") from exc
        if observed > now + timedelta(minutes=5) or now - observed > MAX_EVIDENCE_AGE:
            raise CertificateError(f"REQUIRED_CHECK_STALE:{code}")
    return evidence_digest(evidence)


def issue_certificate(
    evidence: Mapping[str, Any], *, organization_id: str, source_id: str, profile: str,
    scope_digest: str, private_key: Ed25519PrivateKey, key_id: str,
    validity: timedelta = timedelta(days=30), now: datetime | None = None,
) -> dict[str, str]:
    """Certifier-only issuance; returns a record for operator import."""
    if validity <= timedelta(0) or validity > MAX_VALIDITY:
        raise CertificateError("CERTIFICATE_VALIDITY_UNSAFE")
    issued = _utc(now or datetime.now(timezone.utc)).replace(microsecond=0)
    digest = validate_evidence(
        evidence, organization_id=organization_id, source_id=source_id,
        profile=profile, scope_digest=scope_digest, now=issued,
    )
    fields = CertificateFields(
        organization_id=organization_id, source_id=source_id, profile=profile,
        scope_digest=scope_digest, evidence_digest=digest,
        verifier_version=VERIFIER_VERSION, certified_at=issued,
        expires_at=issued + validity,
    )
    return {
        "organization_id": organization_id, "source_id": source_id,
        "provider_profile": profile, "scope_digest": scope_digest,
        "evidence_digest": digest, "verifier_version": VERIFIER_VERSION,
        "certified_at": fields.certified_at.isoformat(),
        "expires_at": fields.expires_at.isoformat(),
        "signature": sign_certificate(fields, private_key, key_id),
    }
