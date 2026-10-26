"""Synthetic Guard enrollment-secret handling tests (no customer credentials)."""
import json

import pytest

from apps.guard.accessproof_guard import app as guard_app


def test_guard_refuses_world_readable_machine_credentials(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"control_plane_url": "https://control.invalid", "guard_id": "fake", "credential": "synthetic-secret"}))
    path.chmod(0o644)
    monkeypatch.setattr(guard_app, "_credential_path", path)
    with pytest.raises(RuntimeError, match="permissions"):
        guard_app._load_machine_settings()


def test_guard_refuses_symlinked_machine_credentials(tmp_path, monkeypatch):
    actual = tmp_path / "real.json"
    actual.write_text(json.dumps({"control_plane_url": "https://control.invalid", "guard_id": "fake", "credential": "synthetic-secret"}))
    actual.chmod(0o600)
    alias = tmp_path / "credentials.json"
    alias.symlink_to(actual)
    monkeypatch.setattr(guard_app, "_credential_path", alias)
    with pytest.raises(RuntimeError, match="regular file"):
        guard_app._load_machine_settings()


def test_guard_accepts_owner_only_machine_credentials(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"control_plane_url": "https://control.invalid", "guard_id": "fake", "credential": "synthetic-secret"}))
    path.chmod(0o600)
    monkeypatch.setattr(guard_app, "_credential_path", path)
    settings = guard_app._load_machine_settings()
    assert settings["guard_id"] == "fake"
