"""Remote RAG route certification: decision logic, binding and signed result.

A remote (cross-host, any OS/framework) RAG route is CERTIFIED only when every
required behaviour was OBSERVED on the actual employee-facing route, with the
specific kinds of evidence that check requires. An HTTP status code on its own is
never enough. Each check has to be backed by independent observations, such as the model-context
witness, the Guard's audit records, the Gateway's signed audit log, or an
active probe. A check with missing evidence, or one marked UNOBSERVABLE,
fails, and certification fails with it.

The certificate binds the exact application, route, RAG code, client package,
framework, Gateway TLS certificate, Gateway configuration (exposure + audit
key + image), Guard configuration and source scope. ``verify_certificate``
recomputes that binding from the live deployment, and ANY change invalidates
the certificate (``INVALIDATED_CONFIGURATION_CHANGED``), as does age.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "accessproof.remote-route-certificate/v1"
MAX_AGE = timedelta(days=7)

# check code -> evidence kinds that MUST be present for a PASS to count.
REQUIRED_CHECKS: dict[str, tuple[str, ...]] = {
    "AUTHORIZED_ACCESS_RELEASED": ("witness", "guard_audit", "gateway_audit"),
    "UNAUTHORIZED_ACCESS_DENIED": ("witness", "guard_audit", "gateway_audit"),
    "REVOKED_DOCUMENT_DENIED": ("provider_change", "guard_decision", "witness", "gateway_audit"),
    "MIDREQUEST_LAYER2_BLOCKED": ("provider_change", "guard_audit", "witness", "gateway_audit"),
    "TRUSTED_PROVENANCE_VERIFIED": ("guard_audit", "gateway_audit"),
    "FORGED_CONTENT_REJECTED": ("witness", "gateway_audit"),
    "TAMPERED_OR_REPLAYED_REQUEST_REJECTED": ("witness", "gateway_audit"),
    "CACHE_REPLAY_PREVENTED": ("witness", "gateway_audit"),
    "CROSS_TENANT_ISOLATED": ("witness", "gateway_audit"),
    "DIRECT_MODEL_BYPASS_ABSENT": ("probe",),
    "ALTERNATE_ROUTES_PROTECTED": ("probe", "witness"),
    "FAIL_CLOSED_GATEWAY_UNAVAILABLE": ("probe", "witness"),
    "FAIL_CLOSED_GUARD_UNAVAILABLE": ("probe", "witness", "gateway_audit"),
    "GATEWAY_GUARD_AUDIT_MATCH": ("guard_audit", "gateway_audit"),
}

BINDING_FIELDS = (
    "tenant_id", "application_id", "route_method", "route_path", "route_url", "client_id", "framework",
    "framework_version", "client_package", "rag_code_sha256", "rag_runtime_config_sha256", "rag_platform",
    "gateway_url", "gateway_tls_cert_sha256", "gateway_exposure", "gateway_audit_public_key",
    "gateway_image", "guard_image", "guard_identity_config_sha256", "source_id", "source_scope_digest",
)


class RouteCertificationError(ValueError):
    pass


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_binding(values: Mapping[str, Any]) -> dict[str, Any]:
    missing = [f for f in BINDING_FIELDS if values.get(f) in (None, "")]
    if missing:
        # A binding that cannot be observed cannot be certified.
        raise RouteCertificationError("BINDING_UNOBSERVABLE:" + ",".join(missing))
    return {f: values[f] for f in BINDING_FIELDS}


def fingerprint(binding: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical({f: binding.get(f) for f in BINDING_FIELDS})).hexdigest()


def evaluate(checks: list[dict]) -> tuple[str, list[dict]]:
    """Return ("CERTIFIED"|"NOT_CERTIFIED", failing). Every required check must be
    present exactly once, PASS, and carry each required evidence kind."""
    failing: list[dict] = []
    by_code: dict[str, dict] = {}
    for c in checks:
        code = c.get("code")
        if code in by_code:
            failing.append({"code": code, "why": "DUPLICATE_CHECK"})
        by_code[code] = c
    for code, kinds in REQUIRED_CHECKS.items():
        c = by_code.get(code)
        if c is None:
            failing.append({"code": code, "why": "NOT_RUN"})
            continue
        if c.get("status") != "PASS":
            failing.append({"code": code, "why": c.get("status") or "NO_STATUS", "detail": c.get("detail")})
            continue
        ev = c.get("evidence") or {}
        absent = [k for k in kinds if not ev.get(k)]
        if absent:
            failing.append({"code": code, "why": "EVIDENCE_MISSING:" + ",".join(absent)})
    return ("CERTIFIED" if not failing else "NOT_CERTIFIED"), failing


def issue(binding: Mapping[str, Any], checks: list[dict], key: Ed25519PrivateKey, *, key_id: str,
          now: datetime | None = None, evidence_sha256: str = "") -> dict:
    now = now or datetime.now(timezone.utc)
    status, failing = evaluate(checks)
    cert = {"schema": SCHEMA, "status": status, "binding": dict(binding), "fingerprint": fingerprint(binding),
            "checks": [{"code": c["code"], "status": c["status"]} for c in checks],
            "failing": failing, "evidence_sha256": evidence_sha256,
            "issued_at": now.isoformat(), "expires_at": (now + MAX_AGE).isoformat(), "key_id": key_id}
    cert["signature"] = _b64(key.sign(_canonical({k: v for k, v in cert.items() if k != "signature"})))
    return cert


ATTESTATION_SCHEMA = "accessproof.remote-route-attestation/v1"
ATTESTATION_MAX_AGE = timedelta(hours=1)


def issue_attestation(cert: Mapping[str, Any], live_binding: Mapping[str, Any], key: Ed25519PrivateKey, *,
                      key_id: str, now: datetime | None = None) -> dict:
    """Signed statement of the LIVE deployment's binding, for production to
    compare with the certified binding (configuration-change invalidation)."""
    now = now or datetime.now(timezone.utc)
    live_fp = fingerprint(live_binding)
    changed = [f for f in BINDING_FIELDS if (cert.get("binding") or {}).get(f) != live_binding.get(f)]
    att = {"schema": ATTESTATION_SCHEMA, "certificate_fingerprint": cert.get("fingerprint"),
           "tenant_id": (cert.get("binding") or {}).get("tenant_id"),
           "application_id": (cert.get("binding") or {}).get("application_id"),
           "live_fingerprint": live_fp, "matches": live_fp == cert.get("fingerprint"), "changed_fields": changed,
           "observed_at": now.isoformat(), "key_id": key_id}
    att["signature"] = _b64(key.sign(_canonical({k: v for k, v in att.items() if k != "signature"})))
    return att


def verify_signed(doc: Mapping[str, Any], keys: Mapping[str, Ed25519PublicKey]) -> bool:
    key = keys.get(str(doc.get("key_id")))
    sig = doc.get("signature")
    if key is None or not isinstance(sig, str):
        return False
    try:
        key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
                   _canonical({k: v for k, v in doc.items() if k != "signature"}))
        return True
    except Exception:
        return False


def verify_certificate(cert: Mapping[str, Any], public_key: Ed25519PublicKey, current_binding: Mapping[str, Any],
                       *, now: datetime | None = None) -> tuple[bool, str, list[str]]:
    """(valid, code, changed_fields). Valid only when signed, CERTIFIED, unexpired
    and the LIVE deployment still has exactly the certified binding."""
    now = now or datetime.now(timezone.utc)
    sig = cert.get("signature")
    try:
        public_key.verify(base64.urlsafe_b64decode(str(sig) + "=" * (-len(str(sig)) % 4)),
                          _canonical({k: v for k, v in cert.items() if k != "signature"}))
    except Exception:
        return False, "SIGNATURE_INVALID", []
    if cert.get("schema") != SCHEMA:
        return False, "SCHEMA_UNSUPPORTED", []
    if cert.get("status") != "CERTIFIED":
        return False, "NOT_CERTIFIED", []
    if fingerprint(cert.get("binding") or {}) != cert.get("fingerprint"):
        return False, "FINGERPRINT_MISMATCH", []
    try:
        expires = datetime.fromisoformat(str(cert["expires_at"]))
    except (KeyError, ValueError):
        return False, "EXPIRY_INVALID", []
    if now >= expires:
        return False, "EXPIRED", []
    changed = [f for f in BINDING_FIELDS if (cert.get("binding") or {}).get(f) != current_binding.get(f)]
    if changed:
        return False, "INVALIDATED_CONFIGURATION_CHANGED", changed
    return True, "VALID", []
