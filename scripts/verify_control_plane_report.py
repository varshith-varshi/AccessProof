"""Offline verification for downloaded AccessProof control-plane reports.

Production verification pins an AccessProof signing-key bundle.  An embedded
public key proves that *someone* signed an artifact; it does not prove that an
authorized AccessProof issuer signed it.  Self-signed verification is retained
only as an explicitly-labelled diagnostic mode.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packages.crypto.signing import verify_manifest, verify_manifest_with_trust

REPORT_SCHEMA = "accessproof.control_plane_report/v1"
REPORT_TYPES = {"APPLICATION_COVERAGE", "GUARD_HEALTH", "AUTHORIZATION_ACTIVITY"}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def verify_envelope(
    envelope: Any,
    *,
    expected_organization: str | None = None,
    expected_report_type: str | None = None,
    expected_key_id: str | None = None,
    trusted_public_keys: dict[str, str] | None = None,
    revoked_key_ids: set[str] | None = None,
    allow_untrusted_self_signed: bool = False,
    allow_expired: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a downloaded ``{report, signature}`` artifact."""
    checks: dict[str, bool] = {}
    reasons: list[str] = []
    report = envelope.get("report") if isinstance(envelope, dict) else None
    signature = envelope.get("signature") if isinstance(envelope, dict) else None
    if not isinstance(report, dict) or not isinstance(signature, dict):
        return {
            "verified": False,
            "checks": {"envelope": False},
            "reasons": ["The file must contain a report object and a signature object."],
        }

    checks["envelope"] = True
    checks["schema"] = report.get("schema") == REPORT_SCHEMA
    checks["report_type"] = report.get("report_type") in REPORT_TYPES
    checks["report_id"] = isinstance(report.get("report_id"), str) and bool(report.get("report_id"))
    checks["organization"] = isinstance(report.get("organization_id"), str) and bool(report.get("organization_id"))
    # An embedded key is attacker-controlled.  It is useful for a local
    # diagnostic, but it is never enough for an enterprise authenticity claim.
    checks["signature"] = verify_manifest(report, signature)
    checks["trusted_issuer"] = (
        verify_manifest_with_trust(
            report, signature, trusted_public_keys or {}, revoked_key_ids or set(),
        )
        if trusted_public_keys is not None
        else allow_untrusted_self_signed
    )
    expires_at = _parse_timestamp(report.get("expires_at"))
    checks["expiry_present"] = expires_at is not None
    current = now or datetime.now(timezone.utc)
    checks["not_expired"] = bool(
        expires_at is not None and (allow_expired or expires_at > current)
    )
    if expected_organization is not None:
        checks["expected_organization"] = report.get("organization_id") == expected_organization
    if expected_report_type is not None:
        checks["expected_report_type"] = report.get("report_type") == expected_report_type
    if expected_key_id is not None:
        checks["expected_key_id"] = signature.get("key_id") == expected_key_id

    messages = {
        "schema": "The report schema is not recognized.",
        "report_type": "The report type is not recognized.",
        "signature": "The Ed25519 signature or payload hash is invalid; the report was modified.",
        "trusted_issuer": "No configured trusted issuer key validates this report.",
        "expiry_present": "The report does not declare an expiry.",
        "not_expired": "The report has expired; verifiable history does not imply current protection.",
        "expected_organization": "The report belongs to a different organization.",
        "expected_report_type": "The report type does not match the requested expectation.",
        "expected_key_id": "The signing key does not match the pinned key identifier.",
    }
    for name, ok in checks.items():
        if not ok:
            reasons.append(messages.get(name, f"Verification check failed: {name}."))
    return {
        "verified": all(checks.values()),
        "checks": checks,
        "reasons": reasons,
        "report_id": report.get("report_id"),
        "report_type": report.get("report_type"),
        "organization_id": report.get("organization_id"),
        "generated_at": report.get("generated_at"),
        "expires_at": report.get("expires_at"),
        "key_id": signature.get("key_id"),
        "evidence_levels": report.get("evidence_levels", {}),
        "limitations": report.get("limitations", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Downloaded report JSON file")
    parser.add_argument("--expected-organization", help="Require this organization ID")
    parser.add_argument("--expected-report-type", choices=sorted(REPORT_TYPES))
    parser.add_argument("--expected-key-id", help="Pin the signing key identifier")
    parser.add_argument(
        "--trusted-key-bundle", type=Path,
        help="JSON bundle: {\"keys\": {\"ed25519:...\": \"base64-public-key\"}, \"revoked_key_ids\": []}",
    )
    parser.add_argument(
        "--allow-untrusted-self-signed", action="store_true",
        help="Diagnostic only: report cryptographic validity without issuer trust. Never production verification.",
    )
    parser.add_argument(
        "--allow-expired",
        action="store_true",
        help="Verify the signature of an expired historical report",
    )
    arguments = parser.parse_args(argv)
    try:
        envelope = json.loads(arguments.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, indent=2))
        return 2
    trusted_keys: dict[str, str] | None = None
    revoked_key_ids: set[str] = set()
    if arguments.trusted_key_bundle:
        try:
            bundle = json.loads(arguments.trusted_key_bundle.read_text(encoding="utf-8"))
            trusted_keys = bundle.get("keys") if isinstance(bundle, dict) else None
            revoked = bundle.get("revoked_key_ids", []) if isinstance(bundle, dict) else []
            if (not isinstance(trusted_keys, dict)
                    or not all(isinstance(k, str) and isinstance(v, str) for k, v in trusted_keys.items())
                    or not isinstance(revoked, list) or not all(isinstance(v, str) for v in revoked)):
                raise ValueError("invalid trusted signing-key bundle")
            revoked_key_ids = set(revoked)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"verified": False, "error": f"invalid trusted-key bundle: {exc}"}, indent=2))
            return 2
    result = verify_envelope(
        envelope,
        expected_organization=arguments.expected_organization,
        expected_report_type=arguments.expected_report_type,
        expected_key_id=arguments.expected_key_id,
        trusted_public_keys=trusted_keys,
        revoked_key_ids=revoked_key_ids,
        allow_untrusted_self_signed=arguments.allow_untrusted_self_signed,
        allow_expired=arguments.allow_expired,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
