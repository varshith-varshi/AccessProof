"""Read-only local certificate renewal watchdog.

Reports only status and time-to-expiry; does not read/print cryptographic
private key material or employee session contents, and never issues certificates.
A green result means the *local* scheduler is ready, not off-host resilience.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.certifier.check_renewal_dependencies import report as dependency_report


def aware(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timezone-aware timestamp required")
    return parsed.astimezone(timezone.utc)


def inspect_certificates(directory: Path, now: datetime) -> dict[str, dict]:
    results = {}
    for path in sorted(directory.glob("*.certificate.json")):
        name = path.name.removesuffix(".certificate.json")
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Unsafe certificate file")
            payload = json.loads(path.read_text(encoding="utf-8"))
            expiry = aware(payload["expires_at"])
            remaining = round((expiry - now).total_seconds() / 3600, 2)
            state = "EXPIRED" if remaining <= 0 else "URGENT" if remaining <= 48 else "WATCH" if remaining <= 96 else "OK"
            results[name] = {"status": state, "hours_remaining": remaining}
        except (OSError, ValueError, KeyError, TypeError):
            results[name] = {"status": "INVALID_CERTIFICATE_METADATA"}
    return results


def last_attestations(path: Path, names: set[str], now: datetime) -> dict[str, dict]:
    latest = {}
    try:
        if path.is_symlink() or path.stat().st_size > 20_000_000:
            raise ValueError("Unsafe or unexpectedly large log")
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                name = item.get("route")
                if name not in names:
                    continue
                at = aware(item["at"])
                if at > now:
                    continue
                if name not in latest or at > latest[name]["at"]:
                    latest[name] = {"at": at, "ok": item.get("ok") is True, "action": item.get("action")}
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
    except (OSError, ValueError):
        pass
    results = {}
    for name in sorted(names):
        event = latest.get(name)
        if event is None:
            results[name] = {"status": "NO_RECENT_ATTESTATION"}
        else:
            hours_ago = round((now - event["at"]).total_seconds() / 3600, 2)
            status = "ATTESTATION_FAILED" if not event["ok"] else "ATTESTATION_STALE" if hours_ago >= 24 else "OK"
            results[name] = {"status": status, "hours_since_event": hours_ago}
    return results


def check(home: Path, now: datetime, *, prerequisites: dict | None = None) -> dict:
    dependencies = prerequisites if prerequisites is not None else dependency_report(home)
    certificates = inspect_certificates(home / ".ap-id/route-certs", now)
    attestations = last_attestations(home / ".ap-id/route-attestation.log", set(certificates), now)
    warnings = []
    if not dependencies.get("local_prerequisites_present"):
        warnings.append("LOCAL_RENEWAL_DEPENDENCY_MISSING")
    if not certificates:
        warnings.append("NO_LOCAL_ROUTE_CERTIFICATES")
    for name, metadata in certificates.items():
        if metadata["status"] != "OK":
            warnings.append(f"ROUTE_CERTIFICATE_{metadata['status']}:{name}")
    for name, metadata in attestations.items():
        if metadata["status"] != "OK":
            warnings.append(f"ROUTE_{metadata['status']}:{name}")
    return {"checked_at": now.isoformat(), "status": "WARNING" if warnings else "OK",
            "renewal_host": "OWNER_LAPTOP_NOT_ALWAYS_ON", "local_dependencies_present": dependencies.get("local_prerequisites_present") is True,
            "route_certificates": certificates, "route_attestation": attestations, "warnings": warnings,
            "source_certificate_live_check": "NOT_PERFORMED", "migration_complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    args = parser.parse_args()
    result = check(args.home, datetime.now(timezone.utc))
    print(json.dumps(result, sort_keys=True), flush=True)
    return 1 if result["warnings"] else 0


if __name__ == "__main__":
    sys.exit(main())
