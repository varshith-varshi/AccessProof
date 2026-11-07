from pathlib import Path
from unittest.mock import patch

from scripts.certifier import always_on_route_observer as obs


def test_gated_observer_does_not_claim_signing_or_certification():
    with patch.object(obs, "_public_ready", return_value=True), patch.object(
        obs, "_pinned_gateway_ready", return_value=True
    ):
        result = obs.check(Path("/tmp/synthetic-public-ca.pem"))
    assert result["overall"] == "UP"
    assert result["certificate_signing"] == "NOT_SUPPORTED_BY_OBSERVER"
    assert result["protect_certification"] == "NOT_VERIFIED_BY_OBSERVER"


def test_api_ready_requires_database_and_redis(monkeypatch):
    class StubResponse:
        status = 200
        def __init__(self, data): self.data = data
        def geturl(self): return obs.PUBLIC_CHECKS["api"]
        def read(self, _: int): return self.data
        def __enter__(self): return self
        def __exit__(self, *_): return False

    for message, expected in (
        (b'{"status":"ready","dependencies":{"database":"ok","redis":"ok"}}', True),
        (b'{"status":"ready","dependencies":{"database":"error","redis":"ok"}}', False),
        (b'{"status":"ok","dependencies":{"database":"ok","redis":"ok"}}', False),
    ):
        with patch.object(obs.request, "build_opener") as opener:
            opener.return_value.open.return_value = StubResponse(message)
            assert obs._public_ready(obs.PUBLIC_CHECKS["api"]) is expected


def test_tunnel_disconnect_is_not_falsely_reported_as_recovered():
    with patch.object(obs, "_public_ready", return_value=True), patch.object(
        obs, "_pinned_gateway_ready", return_value=False
    ):
        result = obs.check(Path("/tmp/synthetic-public-ca.pem"))
    assert result["overall"] == "DEGRADED"
    assert result["status"]["gateway_tunnel"] == "DOWN"


def test_pinned_tls_rejects_missing_ca_and_different_identity(tmp_path):
    assert not obs._pinned_gateway_ready(tmp_path / "missing.pem", "ap-gateway.lab.internal")
    candidate = tmp_path / "public-ca.pem"
    candidate.write_text("synthetic")
    assert not obs._pinned_gateway_ready(candidate, "untrusted.example.com")
    symlink = tmp_path / "symlink.pem"
    symlink.symlink_to(candidate)
    assert not obs._pinned_gateway_ready(symlink, "ap-gateway.lab.internal")
