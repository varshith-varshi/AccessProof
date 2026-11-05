"""Check both SharePoint source certificate expiries via approved READ-ONLY SSM.

Does not issue, import, renew or print source IDs, certificates or credentials.
Requires AWS_PROFILE=accessproof-certifier and active Roles Anywhere identity.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.certifier import ssm_ops


def classify(raw: str, now: datetime) -> dict:
    try:
        record = raw.strip().splitlines()[0].split("|")
        if len(record) != 2 or record[1].lower() != "verified":
            return {"state": "INVALID_SOURCE_CERTIFICATE"}
        remaining = round((datetime.fromtimestamp(float(record[0]), tz=timezone.utc) - now).total_seconds() / 86400, 2)
        return {"state": "EXPIRED" if remaining <= 0 else "URGENT" if remaining <= 5 else "RENEWAL_DUE" if remaining <= 10 else "OK",
                "days_remaining": remaining}
    except (ValueError, IndexError, OverflowError):
        return {"state": "INVALID_SOURCE_CERTIFICATE"}


def profile_sources(repo: Path, home: Path) -> list[tuple[str, str, str]]:
    module_path = repo / "scripts/certifier/renew_source_certificate.py"
    spec = importlib.util.spec_from_file_location("cert_status_profile", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("Source renewal module unavailable")
    old = os.environ.pop("AP_PROFILE_FILE", None)
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        reference = ("reference", module.ORG, module.SOURCE)
    finally:
        if old is not None:
            os.environ["AP_PROFILE_FILE"] = old
    pilot_path = home / ".ap-id/pilot/certification-profile.json"
    if pilot_path.is_symlink() or not pilot_path.is_file():
        raise ValueError("Pilot certification profile unavailable")
    pilot = json.loads(pilot_path.read_text()).get("renew_source_certificate", {})
    if not pilot.get("ORG") or not pilot.get("SOURCE"):
        raise ValueError("Pilot certification profile missing source binding")
    return [reference, ("pilot", pilot["ORG"], pilot["SOURCE"])]


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    output = {}
    failed = False
    try:
        sources = profile_sources(repo, Path.home())
    except (OSError, ValueError, KeyError):
        print(json.dumps({"state": "SOURCE_PROFILE_MISSING", "migration_complete": False}))
        return 1
    for label, org, src in sources:
        try:
            result = classify(ssm_ops.read_only("certificate_status", organizationId=org, sourceId=src), datetime.now(timezone.utc))
            output[label] = result
            failed = failed or result["state"] in ("INVALID_SOURCE_CERTIFICATE", "EXPIRED", "URGENT")
        except Exception:  # Avoid leaking AWS errors or credential details into unit logs.
            output[label] = {"state": "READ_ONLY_STATUS_UNAVAILABLE"}
            failed = True
    print(json.dumps({"sources": output, "source_expiry_check": "LIVE_READ_ONLY", "migration_complete": False}, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
