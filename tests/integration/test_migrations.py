import os
import subprocess
import sys
from pathlib import Path
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parents[2]


def test_blank_and_upgrade_migration_path(tmp_path):
    db = tmp_path / "migration.db"
    env = os.environ.copy()
    # The migration is a deliberately isolated subprocess; a parent test DB
    # override must never redirect Alembic to the suite's shared connection.
    env.pop("ACCESSPROOF_CURRENT_DATABASE_URL", None)
    env["DATABASE_URL"] = f"sqlite:///{db}"
    first = "c8a38e37eb91"
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), "upgrade", first],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    tables = inspect(create_engine(f"sqlite:///{db}")).get_table_names()
    assert "test_runs" in tables and "reports" not in tables
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), "upgrade", "head"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    tables = inspect(create_engine(f"sqlite:///{db}")).get_table_names()
    assert "reports" in tables and "evidence_items" in tables
    assert "control_plane_reports" in tables
    # The latest runner oracle must stay mandatory after upgrading a legacy
    # SQLite schema; a successful migration with a nullable oracle is unsafe.
    columns = inspect(create_engine(f"sqlite:///{db}")).get_columns("test_runs")
    oracle = next(column for column in columns if column["name"] == "oracle_canary")
    assert oracle["nullable"] is False
