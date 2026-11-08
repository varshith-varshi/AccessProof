#!/usr/bin/env python3
"""Encode existing operator-observed source-certification evidence for read-only gates.

Only evidence with its colocated signed-certificate record can be supplied.
The production API still independently checks the exact current DB certificate
evidence digest and the required PASS checks; this utility cannot certify anything.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = (ROOT / "docs/evidence").resolve()
SCHEMA = "accessproof.source_certification_evidence/v1"
MAX_ENCODED = 3500
HEX64 = re.compile(r"[0-9a-f]{64}")


class EvidenceRejected(ValueError):
    pass


def encode(path: Path, *, organization_id: str) -> str:
    source = path.resolve(strict=True)
    if not source.is_relative_to(EVIDENCE_DIR) or source.name != "source-certification-evidence.json":
        raise EvidenceRejected("EVIDENCE_OUTSIDE_APPROVED_REPOSITORY_PATH")
    record_path = source.with_name("source-certificate-record.json")
    if not record_path.is_file() or record_path.is_symlink():
        raise EvidenceRejected("MATCHING_CERTIFICATE_RECORD_REQUIRED")
    evidence = json.loads(source.read_text())
    record = json.loads(record_path.read_text())
    if not isinstance(evidence, dict) or not isinstance(record, dict):
        raise EvidenceRejected("INVALID_EVIDENCE_OR_RECORD")
    if evidence.get("schema") != SCHEMA or evidence.get("organization_id") != organization_id:
        raise EvidenceRejected("EVIDENCE_SCHEMA_OR_ORGANIZATION_MISMATCH")
    fields = (
        ("organization_id", "organization_id"),
        ("source_id", "source_id"),
        ("profile", "provider_profile"),
        ("scope_digest", "scope_digest"),
    )
    if any(evidence.get(a) != record.get(b) for a, b in fields):
        raise EvidenceRejected("CERTIFICATE_EVIDENCE_SCOPE_MISMATCH")
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if record.get("evidence_digest") != digest:
        raise EvidenceRejected("CERTIFICATE_EVIDENCE_DIGEST_MISMATCH")
    if not isinstance(record.get("signature"), str) or not record["signature"].startswith("ed25519:"):
        raise EvidenceRejected("SIGNED_CERTIFICATE_RECORD_REQUIRED")
    try:
        expiry = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise EvidenceRejected("LOCAL_CERTIFICATE_RECORD_EXPIRED")
    except (ValueError, TypeError, KeyError) as exc:
        raise EvidenceRejected("CERTIFICATE_EXPIRY_INVALID") from exc
    # Validate structure but not historical 72h issuance freshness: only the
    # production verifier knows whether these exact bytes match the live cert.
    from packages.crypto.source_certificate import REQUIRED_CHECKS

    checks = evidence.get("checks")
    if not isinstance(checks, list):
        raise EvidenceRejected("CHECKS_MISSING")
    present = [x.get("code") for x in checks if isinstance(x, dict)]
    if len(checks) != len(present) or len(present) != len(set(present)):
        raise EvidenceRejected("INVALID_OR_DUPLICATE_CHECKS")
    if not all(any(x["code"] == code and x.get("status") == "PASS" and
                   isinstance(x.get("artifact_sha256"), str) and
                   HEX64.fullmatch(x["artifact_sha256"]) for x in checks) for code in REQUIRED_CHECKS):
        raise EvidenceRejected("REQUIRED_CERTIFICATION_EVIDENCE_NOT_PASSED")
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.b64encode(gzip.compress(payload, mtime=0)).decode("ascii")
    if len(encoded) > MAX_ENCODED:
        raise EvidenceRejected("EVIDENCE_TOO_LARGE_FOR_SSM_PARAMETER")
    return encoded


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--evidence", type=Path, required=True)
    ap.add_argument("--organization-id", required=True)
    args = ap.parse_args()
    try:
        print(encode(args.evidence, organization_id=args.organization_id))
    except (EvidenceRejected, OSError, json.JSONDecodeError) as exc:
        ap.exit(2, f"EVIDENCE_REFUSED:{str(exc)[:160]}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
