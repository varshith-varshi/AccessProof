#!/usr/bin/env python3
"""Provision least-privilege PostgreSQL runtime roles for AccessProof (P0-01).

Run as the migration owner (the current DATABASE_URL user), AFTER
``alembic upgrade head``:

  DATABASE_URL=postgresql+psycopg://<owner>@db/accessproof \\
    python scripts/provision_database_roles.py \\
      --app-password-file /run/secrets/app_db_password \\
      --worker-password-file /run/secrets/worker_db_password

  python scripts/provision_database_roles.py --audit   # read-only check

Creates or updates ``accessproof_app`` (API) and ``accessproof_rls_admin``
(worker) as LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE roles that
own nothing, grants data privileges only, then connects AS each role to prove
it cannot bypass tenant isolation. Passwords are read from 0600 files and
never printed or passed on the command line.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apps.api.accessproof_api.db_security import (  # noqa: E402
    APP_ROLE, METRICS_ROLE, WORKER_ROLE, audit, grant_runtime_privileges,
)


def _secret(path: Path) -> str:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit(f"refusing password file with permissive mode {oct(mode)}: chmod 600 {path}")
    value = path.read_text().strip()
    if len(value) < 24:
        raise SystemExit(f"password in {path} must be at least 24 characters")
    return value


def _role_url(owner_url: str, role: str, password: str) -> str:
    return make_url(owner_url).set(username=role, password=password).render_as_string(hide_password=False)


def provision(owner_url: str, passwords: dict[str, str]) -> dict[str, object]:
    engine = create_engine(owner_url)
    with engine.begin() as conn:
        me = conn.execute(text("SELECT current_user, current_database()")).one()
        for role, password in passwords.items():
            exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar()
            verb = "ALTER" if exists else "CREATE"
            # Role names are constants; the password is passed as a literal
            # via format(%L) on the server so it is quoted safely.
            stmt = conn.execute(text(
                "SELECT format('%s ROLE %I WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD %L', CAST(:verb AS text), "
                "CAST(:role AS text), CAST(:pw AS text))"),
                {"verb": verb, "role": role, "pw": password}).scalar_one()
            conn.execute(text(stmt))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{me[1]}" TO {role}'))
        grant_runtime_privileges(conn)
    engine.dispose()
    return {"provisioned_roles": sorted(passwords), "owner": me[0], "database": me[1]}


def verify(owner_url: str, passwords: dict[str, str]) -> dict[str, object]:
    results: dict[str, object] = {}
    for role, password in passwords.items():
        engine = create_engine(_role_url(owner_url, role, password))
        with engine.begin() as conn:
            facts = audit(conn)
            # A restricted role must not be able to turn tenant isolation off.
            try:
                with conn.begin_nested():
                    conn.execute(text('ALTER TABLE "ai_applications" DISABLE ROW LEVEL SECURITY'))
                facts["can_disable_rls"] = True
            except Exception:
                facts["can_disable_rls"] = False
            if role == APP_ROLE:
                conn.execute(text("SELECT set_config('accessproof.organization_id', '', true)"))
                facts["rows_visible_without_tenant"] = conn.execute(text(
                    "SELECT count(*) FROM ai_applications")).scalar_one()
            if role == METRICS_ROLE:
                try:
                    with conn.begin_nested():
                        conn.execute(text("DELETE FROM audit_events WHERE false"))
                    facts["can_write"] = True
                except Exception:
                    facts["can_write"] = False
        engine.dispose()
        facts["ok"] = (not facts["superuser"] and not facts["bypassrls"] and not facts["owns_tables"]
                       and not facts["can_disable_rls"] and not facts["tables_missing_policy"]
                       and not facts["settable_bypass_policies"]
                       and facts.get("rows_visible_without_tenant", 0) == 0
                       and not facts.get("can_write", False))
        results[role] = facts
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app-password-file", type=Path)
    parser.add_argument("--worker-password-file", type=Path)
    parser.add_argument("--metrics-password-file", type=Path,
                        help="optional read-only role for /metrics (ACCESSPROOF_METRICS_DATABASE_URL)")
    parser.add_argument("--audit", action="store_true", help="read-only: report the CURRENT connection's facts")
    args = parser.parse_args()
    owner_url = os.environ.get("DATABASE_URL", "")
    if not owner_url.startswith("postgresql"):
        raise SystemExit("DATABASE_URL must point at PostgreSQL")
    if args.audit:
        engine = create_engine(owner_url)
        with engine.connect() as conn:
            print(json.dumps(audit(conn), indent=2))
        return 0
    if not args.app_password_file or not args.worker_password_file:
        raise SystemExit("--app-password-file and --worker-password-file are required")
    passwords = {APP_ROLE: _secret(args.app_password_file), WORKER_ROLE: _secret(args.worker_password_file)}
    if args.metrics_password_file:
        passwords[METRICS_ROLE] = _secret(args.metrics_password_file)
    report = {**provision(owner_url, passwords), "verification": verify(owner_url, passwords)}
    print(json.dumps(report, indent=2))
    return 0 if all(v["ok"] for v in report["verification"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
