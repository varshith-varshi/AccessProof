#!/usr/bin/env python3
"""Fail closed when an API process sees an incompatible Alembic schema.

Deployments run migrations as a separately serialized job.  This command is
safe to execute from every API replica because it only reads ``alembic_version``.
"""
from __future__ import annotations

import sys

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from apps.api.accessproof_api.config import settings


def main() -> int:
    config = Config("alembic.ini")
    expected = set(ScriptDirectory.from_config(config).get_heads())
    try:
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        with engine.connect() as connection:
            found = {str(row[0]) for row in connection.execute(text("SELECT version_num FROM alembic_version"))}
    except Exception as exc:
        print(f"schema preflight failed: {exc}", file=sys.stderr)
        return 2
    if found != expected:
        print(
            f"schema preflight failed: database revisions {sorted(found)} do not match required {sorted(expected)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
