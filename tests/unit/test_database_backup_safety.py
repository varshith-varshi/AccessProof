"""Fail-closed backup publication checks; no production DB or AWS mutations."""
from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest

from scripts import database_backup as backup


URL = "postgresql://backup_user:private-test-value@127.0.0.1:5432/accessproof"


def _commands(monkeypatch, *, fail_on: str = "", empty: bool = False):
    commands = []

    monkeypatch.setattr(backup.shutil, "which", lambda name: "/fake/" + name)

    def run(argv, **kwargs):
        commands.append((argv, kwargs))
        if argv[0] == "/fake/pg_dump":
            Path(argv[argv.index("--file") + 1]).write_bytes(
                b"" if empty else b"PGDMP fake test archive"
            )
        if fail_on and argv[0].endswith(fail_on):
            raise subprocess.CalledProcessError(1, argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(backup.subprocess, "run", run)
    return commands


def test_postgres_backup_private_validated_and_exclusive(monkeypatch, tmp_path):
    commands = _commands(monkeypatch)
    dest = tmp_path / "safe" / "backup.dump"
    manifest = backup.backup_postgres(URL, dest)
    assert manifest.size_bytes == len(b"PGDMP fake test archive")
    assert Path(manifest.artifact) == dest
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert [argv[0] for argv, _ in commands] == [
        "/fake/pg_dump", "/fake/pg_restore"
    ]
    assert commands[0][1]["env"]["PGPASSWORD"] == "private-test-value"
    assert "--list" in commands[1][0]
    assert list(dest.parent.glob("*.partial")) == []
    with pytest.raises(FileExistsError):
        backup.backup_postgres(URL, dest)


@pytest.mark.parametrize("fail_on", ["pg_dump", "pg_restore"])
def test_postgres_failed_backup_never_published(monkeypatch, tmp_path, fail_on):
    _commands(monkeypatch, fail_on=fail_on)
    dest = tmp_path / "backup.dump"
    with pytest.raises(subprocess.CalledProcessError):
        backup.backup_postgres(URL, dest)
    assert not dest.exists()
    assert not list(tmp_path.glob(".accessproof-backup-*.partial"))


def test_postgres_empty_archive_rejected(monkeypatch, tmp_path):
    _commands(monkeypatch, empty=True)
    dest = tmp_path / "backup.dump"
    with pytest.raises(RuntimeError, match="empty archive"):
        backup.backup_postgres(URL, dest)
    assert not dest.exists()
    assert not list(tmp_path.glob(".accessproof-backup-*.partial"))


def test_postgres_symlink_destination_rejected(monkeypatch, tmp_path):
    commands = _commands(monkeypatch)
    target = tmp_path / "other"
    target.write_text("untouched")
    dest = tmp_path / "backup.dump"
    dest.symlink_to(target)
    with pytest.raises(FileExistsError):
        backup.backup_postgres(URL, dest)
    assert target.read_text() == "untouched"
    assert commands == []


def test_postgres_symlink_directory_rejected(monkeypatch, tmp_path):
    commands = _commands(monkeypatch)
    target = tmp_path / "real"
    target.mkdir()
    (tmp_path / "link").symlink_to(target, target_is_directory=True)
    with pytest.raises(FileExistsError):
        backup.backup_postgres(URL, tmp_path / "link" / "backup.dump")
    assert commands == []
