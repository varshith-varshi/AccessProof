from __future__ import annotations

import socket
from pathlib import Path

from scripts.certifier import check_renewal_dependencies as check


def test_renewal_report_requires_every_dependency(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(check, "unit_active", lambda _: True)
    key = tmp_path / ".config/accessproof/certifier/ap-certifier-2026-11.pem"
    route = tmp_path / ".config/accessproof/remote-routes.json"
    for path in (key, route):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic")
        path.chmod(0o600)
    sockets = []
    for name in ("alice", "bob"):
        path = tmp_path / f".ap-id/{name}.sock"
        path.parent.mkdir(parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(path))
        sockets.append(sock)
    try:
        assert check.report(tmp_path)["local_prerequisites_present"]
        key.chmod(0o644)
        result = check.report(tmp_path)
        assert not result["offline_signer_file_private"]
        assert not result["local_prerequisites_present"]
        assert "synthetic" not in str(result)
    finally:
        for sock in sockets:
            sock.close()


def test_missing_employee_session_is_reported_without_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(check, "unit_active", lambda _: False)
    result = check.report(tmp_path)
    assert not result["employee_sockets_present"]["bob"]
    assert result["migration_complete"] is False
