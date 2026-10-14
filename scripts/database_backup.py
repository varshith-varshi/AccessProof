from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.engine import make_url


@dataclass(frozen=True)
class BackupManifest:
    created_at: str
    database_kind: str
    artifact: str
    sha256: str
    size_bytes: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sqlite_path(database_url: str) -> Path:
    url = make_url(database_url)
    if url.drivername != "sqlite":
        raise ValueError("not a SQLite database URL")
    database = url.database
    if not database or database == ":memory:":
        raise ValueError("in-memory SQLite databases cannot be backed up as artifacts")
    return Path(database).expanduser().resolve()


def backup_sqlite(database_url: str, destination: Path) -> BackupManifest:
    source = _sqlite_path(database_url)
    if not source.exists():
        raise FileNotFoundError(source)
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()
    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)
        check = dst.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise RuntimeError("SQLite backup failed integrity_check")
    return BackupManifest(
        created_at=datetime.now(timezone.utc).isoformat(),
        database_kind="sqlite",
        artifact=str(destination),
        sha256=_sha256(destination),
        size_bytes=destination.stat().st_size,
    )


def backup_postgres(database_url: str, destination: Path) -> BackupManifest:
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        raise RuntimeError("pg_dump is required for PostgreSQL backups")
    url = make_url(database_url)
    if not url.drivername.startswith("postgresql"):
        raise ValueError("not a PostgreSQL database URL")
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [
        pg_dump,
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--file",
        str(destination),
    ]
    if url.host:
        command += ["--host", url.host]
    if url.port:
        command += ["--port", str(url.port)]
    if url.username:
        command += ["--username", url.username]
    if not url.database:
        raise ValueError("PostgreSQL URL is missing database name")
    command.append(url.database)
    env = dict(os.environ)
    if url.password:
        env["PGPASSWORD"] = url.password
    subprocess.run(command, check=True, env=env, stdout=subprocess.DEVNULL)
    return BackupManifest(
        created_at=datetime.now(timezone.utc).isoformat(),
        database_kind="postgresql",
        artifact=str(destination),
        sha256=_sha256(destination),
        size_bytes=destination.stat().st_size,
    )


def backup_database(database_url: str, destination: Path) -> BackupManifest:
    driver = make_url(database_url).drivername
    if driver == "sqlite":
        return backup_sqlite(database_url, destination)
    if driver.startswith("postgresql"):
        return backup_postgres(database_url, destination)
    raise ValueError(f"Unsupported database driver for backup: {driver}")


def verify_sqlite_backup(
    path: Path,
    *,
    required_tables: tuple[str, ...] = ("organizations", "projects", "test_runs", "audit_events"),
) -> dict:
    path = path.expanduser().resolve()
    with sqlite3.connect(path) as db:
        check = db.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise RuntimeError("backup failed SQLite integrity_check")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = sorted(set(required_tables) - tables)
        if missing:
            raise RuntimeError("backup is missing required tables: " + ", ".join(missing))
        counts = {
            name: int(db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            for name in required_tables
        }
    return {
        "integrity": "ok",
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
        "counts": counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a consistent AccessProof database backup")
    parser.add_argument(
        "--database-url", default=os.getenv("DATABASE_URL", "sqlite:///./accessproof.db")
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run local SQLite integrity/table verification when applicable",
    )
    args = parser.parse_args()
    manifest = backup_database(args.database_url, args.output)
    payload = asdict(manifest)
    if args.verify and manifest.database_kind == "sqlite":
        payload["verification"] = verify_sqlite_backup(Path(manifest.artifact))
    manifest_path = args.manifest or Path(str(args.output) + ".manifest.json")
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
