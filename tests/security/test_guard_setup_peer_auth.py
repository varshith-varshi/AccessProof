"""Local-only setup endpoints must never trust a spoofed HTTP Host header."""
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app


def test_remote_peer_cannot_spoof_local_setup_host(monkeypatch):
    # A remote caller can freely choose its Host header. No network calls.
    called = []

    def should_never_enroll(**kwargs):
        called.append(kwargs)
        raise AssertionError("Remote request reached guard enrollment")

    monkeypatch.setattr(guard_app, "enroll_guard", should_never_enroll)
    with TestClient(
        guard_app.app, base_url="http://localhost",
        client=("203.0.113.42", 44123),
    ) as remote:
        for path in ("/setup", "/setup/status"):
            response = remote.get(path, headers={"Host": "localhost"})
            assert response.status_code == 403, (path, response.status_code)
        response = remote.post(
            "/setup/enroll", headers={"Host": "localhost"},
            json={"server": "http://127.0.0.1:1", "token": "synthetic"},
        )
        assert response.status_code == 403
    assert called == []


def test_real_loopback_peer_can_access_setup_status():
    with TestClient(
        guard_app.app, base_url="http://localhost",
        client=("127.0.0.1", 44444),
    ) as local:
        assert local.get("/setup/status").status_code == 200
