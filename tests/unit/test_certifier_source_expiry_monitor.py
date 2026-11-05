from __future__ import annotations

from datetime import datetime, timedelta, timezone
from scripts.certifier.source_expiry_monitor import classify

NOW = datetime(2026, 11, 5, 0, 0, tzinfo=timezone.utc)


def raw(days: int, status="verified") -> str:
    return f"{(NOW + timedelta(days=days)).timestamp()}|{status}"


def test_source_expiry_state_boundaries():
    assert classify(raw(20), NOW)["state"] == "OK"
    assert classify(raw(8), NOW)["state"] == "RENEWAL_DUE"
    assert classify(raw(2), NOW)["state"] == "URGENT"
    assert classify(raw(-1), NOW)["state"] == "EXPIRED"


def test_invalid_expiry_fails_closed():
    assert classify("garbage", NOW)["state"] == "INVALID_SOURCE_CERTIFICATE"
    assert classify(raw(20, "revoked"), NOW)["state"] == "INVALID_SOURCE_CERTIFICATE"
