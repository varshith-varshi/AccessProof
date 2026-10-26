"""Create the configured current-product PostgreSQL database if it is absent.

This utility is deliberately idempotent.  It never drops, renames, or alters
another database, which lets an existing AccessProof deployment retain its
legacy data while the current Guard product starts cleanly.
"""
from __future__ import annotations

import os
import re
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def main() -> None:
    database_url = os.getenv("ACCESSPROOF_CURRENT_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("ACCESSPROOF_CURRENT_DATABASE_URL or DATABASE_URL is required")
    target = make_url(database_url)
    if not target.drivername.startswith("postgresql"):
        return
    database = target.database or ""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", database):
        raise RuntimeError("Current database name must contain only letters, digits, and underscores")
    admin_url = target.set(database="postgres")
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            exists = connection.execute(text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": database}).scalar()
            if not exists:
                connection.execute(text(f'CREATE DATABASE "{database}"'))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
