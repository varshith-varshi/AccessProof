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
    (directory / "demo.certificate.json").write_text(json.dumps({"expires_at": expiry.isoformat(), "status": "CERTIFIED", "signature": "synthetic-signature"}))
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


def test_revoked_or_unsigned_route_certificate_fails_closed(tmp_path: Path) -> None:
    fixture(tmp_path, NOW + timedelta(days=10))
    target = tmp_path / ".ap-id/route-certs/demo.certificate.json"
    payload = json.loads(target.read_text())
    payload["status"] = "INVALIDATED"
    target.write_text(json.dumps(payload))
    assert "ROUTE_CERTIFICATE_INVALID_CERTIFICATE_METADATA:demo" in check(tmp_path, NOW, prerequisites=GOOD)["warnings"]
    payload["status"] = "CERTIFIED"
    payload.pop("signature")
    target.write_text(json.dumps(payload))
    assert "ROUTE_CERTIFICATE_INVALID_CERTIFICATE_METADATA:demo" in check(tmp_path, NOW, prerequisites=GOOD)["warnings"]


# --- employee session lifetime vs. pending route recertification --------------

def _session(hours_from_now: float) -> dict:
    return {"status": "OK", "session_expires_at": (NOW + timedelta(hours=hours_from_now)).isoformat()}


def test_session_ending_before_recertification_is_flagged(tmp_path: Path) -> None:
    # 82 h left => recert starts in 34 h; a session ending in 1 h cannot do it.
    fixture(tmp_path, NOW + timedelta(hours=82))
    result = check(tmp_path, NOW, prerequisites=GOOD, sessions={"alice": _session(1), "bob": _session(60)})
    assert "EMPLOYEE_SESSION_EXPIRES_BEFORE_RECERTIFICATION:alice" in result["warnings"]
    assert not any(w.endswith(":bob") and "EMPLOYEE" in w for w in result["warnings"])
    assert result["employee_sessions_needed_until"] == (NOW + timedelta(hours=46)).isoformat()


def test_unavailable_or_legacy_sessions_never_pass_when_recert_pending(tmp_path: Path) -> None:
    fixture(tmp_path, NOW + timedelta(hours=40))
    warnings = check(tmp_path, NOW, prerequisites=GOOD,
                     sessions={"alice": {"status": "UNAVAILABLE"}, "bob": {"status": "LIFETIME_UNKNOWN"}})["warnings"]
    assert "EMPLOYEE_SESSION_UNAVAILABLE:alice" in warnings
    assert "EMPLOYEE_SESSION_LIFETIME_UNKNOWN:bob" in warnings


def test_sessions_not_required_when_no_recert_is_near(tmp_path: Path) -> None:
    fixture(tmp_path, NOW + timedelta(days=6))
    result = check(tmp_path, NOW, prerequisites=GOOD, sessions={"alice": {"status": "UNAVAILABLE"}})
    assert result["status"] == "OK" and result["employee_sessions_needed_until"] is None


def test_socket_probe_refuses_token_queries(tmp_path: Path) -> None:
    import pytest
    from scripts.certifier.renewal_watchdog import _socket_query
    for secret in ("api_token", "access_token", "id_token"):
        with pytest.raises(ValueError):
            _socket_query(tmp_path / "x.sock", secret)
