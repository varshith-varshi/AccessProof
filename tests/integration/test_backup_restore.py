from __future__ import annotations

import sqlite3
from pathlib import Path

from sqlalchemy import create_engine, text

from apps.api.accessproof_api.db import Base
from scripts.database_backup import backup_database, verify_sqlite_backup


def test_sqlite_backup_is_consistent_and_restorable(tmp_path: Path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    source_url = f"sqlite:///{source}"
    engine = create_engine(source_url)
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO organizations (id, name, mutations_disabled, created_at) VALUES ('org1','Backup Org',0,CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO projects (id, organization_id, name, paused, created_at) VALUES ('p1','org1','Project',0,CURRENT_TIMESTAMP)"
            )
        )
    manifest = backup_database(source_url, backup)
    verification = verify_sqlite_backup(backup)
    assert manifest.database_kind == "sqlite"
    assert manifest.sha256 == verification["sha256"]
    assert verification["counts"]["organizations"] == 1
    assert verification["counts"]["projects"] == 1

    # A restore drill into an isolated DB is just a byte-for-byte copy of the
    # verified SQLite snapshot; production PostgreSQL uses pg_restore as
    # documented in docs/backups.md.
    restored.write_bytes(backup.read_bytes())
    with sqlite3.connect(restored) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert (
            db.execute("SELECT name FROM organizations WHERE id='org1'").fetchone()[0]
            == "Backup Org"
        )
        assert db.execute("SELECT name FROM projects WHERE id='p1'").fetchone()[0] == "Project"
