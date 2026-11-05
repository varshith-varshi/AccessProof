"""Synthetic fixtures for a read-only, no-credential renewal monitor."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.certifier.renewal_watchdog import check

NOW = datetime(2026, 11, 5, 16, 0, tzinfo=timezone.utc)
GOOD = {"local_prerequisites_present": True}


def fixture(home: Path, expiry: datetime, *, at: datetime = NOW, ok: bool = True) -> None:
    directory = home / ".ap-id/route-certs"
    directory.mkdir(parents=True)
    (directory / "demo.certificate.json").write_text(json.dumps({"expires_at": expiry.isoformat()}))
    (home / ".ap-id/route-attestation.log").write_text(json.dumps({
        "at": at.isoformat(), "route": "demo", "ok": ok, "action": "attest",
    }) + "\n")


def test_recent_valid_certificate_and_attestation_are_ok(tmp_path: Path) -> None:
    fixture(tmp_path, NOW + timedelta(days=6))
    assert check(tmp_path, NOW, prerequisites=GOOD)["status"] == "OK"


def test_urgent_certificate_and_failed_attestation_are_flagged(tmp_path: Path) -> None:
    fixture(tmp_path, NOW + timedelta(hours=12), ok=False)
    warnings = check(tmp_path, NOW, prerequisites=GOOD)["warnings"]
    assert any("URGENT" in warning for warning in warnings)
    assert any("ATTESTATION_FAILED" in warning for warning in warnings)


def test_stale_and_missing_dependencies_are_flagged(tmp_path: Path) -> None:
    fixture(tmp_path, NOW + timedelta(days=6), at=NOW - timedelta(hours=25))
    warnings = check(tmp_path, NOW, prerequisites={"local_prerequisites_present": False})["warnings"]
    assert "LOCAL_RENEWAL_DEPENDENCY_MISSING" in warnings
    assert any("ATTESTATION_STALE" in warning for warning in warnings)


def test_missing_certificates_cannot_pass(tmp_path: Path) -> None:
    assert "NO_LOCAL_ROUTE_CERTIFICATES" in check(tmp_path, NOW, prerequisites=GOOD)["warnings"]
