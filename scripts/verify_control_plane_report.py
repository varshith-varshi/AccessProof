"""Offline verification for downloaded AccessProof control-plane reports.

This verifier uses only the public key embedded in the signed envelope. It
never contacts the control plane, so it can be run on an exported JSON artifact.
An expired report can still have a valid signature; expiry is reported
separately and fails verification unless ``--allow-expired`` is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packages.crypto.signing import verify_manifest

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
    checks["signature"] = verify_manifest(report, signature)
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
    result = verify_envelope(
        envelope,
        expected_organization=arguments.expected_organization,
        expected_report_type=arguments.expected_report_type,
        expected_key_id=arguments.expected_key_id,
        allow_expired=arguments.allow_expired,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
