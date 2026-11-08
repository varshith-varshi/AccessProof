#!/usr/bin/env python3
"""Real-PostgreSQL tenant-isolation + backup/restore drill (DISPOSABLE databases only).

    python scripts/drills/postgres_isolation_restore_drill.py \
        --owner-url postgresql+psycopg://postgres:<pw>@127.0.0.1:55432/accessproof_drill \
        --app-password-file app.pw --worker-password-file worker.pw \
        --container ap-drill-pg [--json-out result.json]

Prerequisites: ``alembic upgrade head`` and ``scripts/provision_database_roles.py``
already ran against --owner-url. The drill:

1. seeds two synthetic tenants into every tenant table it can fill generically
   (at least ``ai_applications``);
2. as the restricted runtime role proves: no tenant context -> 0 rows; tenant A
   sees only A; cross-tenant UPDATE/DELETE affect 0 rows; cross-tenant INSERT is
   rejected; the legacy ``accessproof.rls_bypass`` GUC has no effect;
3. takes a ``pg_dump --format=custom`` inside the database container, restores
   it into a NEW database, re-applies runtime grants, and repeats every check
   plus row-count, Alembic-revision and RLS-audit equality; RTO is measured.

Refuses any non-loopback host or a database name without "drill" in it, so it
can never touch a real database. Prints JSON; contains no secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from apps.api.accessproof_api.db_security import (  # noqa: E402
    APP_ROLE, TENANT_TABLES, WORKER_ROLE, audit, grant_runtime_privileges,
)

ORG_A, ORG_B = "drill-org-a-" + uuid.uuid4().hex[:8], "drill-org-b-" + uuid.uuid4().hex[:8]


def guard_disposable(url: str) -> None:
    u = make_url(url)
    if u.host not in ("127.0.0.1", "localhost", "::1") or "drill" not in (u.database or ""):
        raise SystemExit("REFUSED: drill runs only against a loopback database whose name contains 'drill'")


def _fk_targets(conn, table: str) -> dict[str, tuple[str, str]]:
    rows = conn.execute(text(
        "SELECT a.attname, cf.relname, af.attname FROM pg_constraint c "
        "JOIN pg_class cl ON cl.oid = c.conrelid JOIN pg_class cf ON cf.oid = c.confrelid "
        "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] "
        "JOIN pg_attribute af ON af.attrelid = c.confrelid AND af.attnum = c.confkey[1] "
        "WHERE c.contype = 'f' AND cl.relname = :t AND array_length(c.conkey, 1) = 1"), {"t": table}).all()
    return {r[0]: (r[1], r[2]) for r in rows}


def _filler(conn, table: str, org: str, *, require_org: bool = True) -> dict | None:
    fks = _fk_targets(conn, table)
    cols = conn.execute(text(
        "SELECT column_name, data_type, udt_name, is_nullable, column_default, character_maximum_length "
        "FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = :t"),
        {"t": table}).all()
    if require_org and not any(c[0] == "organization_id" for c in cols):
        return None
    row: dict = {}
    for name, dtype, udt, nullable, default, maxlen in cols:
        if name == "organization_id":
            row[name] = org
            continue
        if nullable == "YES" or default is not None:
            continue
        if name in fks:
            ref_table, ref_col = fks[name]
            has_org = conn.execute(text(
                "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
                "AND table_name = :t AND column_name = 'organization_id'"), {"t": ref_table}).first()
            where = ' WHERE organization_id = :o' if has_org else ''
            value = conn.execute(text(f'SELECT "{ref_col}" FROM "{ref_table}"{where} LIMIT 1'),
                                 {"o": org}).scalar()
            if value is None:
                return None
            row[name] = value
            continue
        if dtype in ("text", "character varying", "character"):
            row[name] = ("d" + uuid.uuid4().hex)[: maxlen or 33]
        elif dtype == "uuid":
            row[name] = str(uuid.uuid4())
        elif dtype in ("integer", "bigint", "smallint", "numeric", "double precision", "real"):
            row[name] = 1
        elif dtype == "boolean":
            row[name] = False
        elif dtype.startswith("timestamp") or dtype == "date":
            row[name] = datetime.now(timezone.utc)
        elif dtype in ("json", "jsonb"):
            row[name] = "{}"
        elif dtype == "USER-DEFINED":
            label = conn.execute(text(
                "SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid "
                "WHERE t.typname = :u ORDER BY e.enumsortorder LIMIT 1"), {"u": udt}).scalar()
            if label is None:
                return None
            row[name] = label
        elif dtype == "bytea":
            row[name] = b"drill"
        else:
            return None
    return row


def seed(owner_url: str) -> list[str]:
    """Insert one row per tenant per table; tables needing FK parents are skipped."""
    seeded: list[str] = []
    eng = create_engine(owner_url)
    with eng.connect() as conn:
        present = {r[0] for r in conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"))}
        for org in (ORG_A, ORG_B):
            row = _filler(conn, "organizations", org, require_org=False) or {}
            row["id"] = org
            cols = ", ".join(f'"{c}"' for c in row)
            conn.commit()  # end the autobegun read transaction
            with conn.begin():
                conn.execute(text(f'INSERT INTO organizations ({cols}) VALUES '
                                  f'({", ".join(":" + c for c in row)})'), row)
        for _pass in range(6):
            pending = [t for t in TENANT_TABLES if t in present and t not in seeded]
            progressed = _seed_pass(conn, pending, seeded)
            if not progressed:
                break
    eng.dispose()
    if "ai_applications" not in seeded:
        raise SystemExit("DRILL_INVALID: could not seed ai_applications")
    return seeded


def _seed_pass(conn, pending: list[str], seeded: list[str]) -> bool:
    progressed = False
    for table in pending:
        ok = True
        for org in (ORG_A, ORG_B):
            row = _filler(conn, table, org)
            if row is None:
                ok = False
                break
            cols = ", ".join(f'"{c}"' for c in row)
            vals = ", ".join(f":{c}" for c in row)
            try:
                conn.commit()  # end the autobegun read transaction
                with conn.begin():
                    conn.execute(text(f'INSERT INTO "{table}" ({cols}) VALUES ({vals})'), row)
            except Exception:
                ok = False
                break
        if ok:
            seeded.append(table)
            progressed = True
    return progressed


def role_url(owner_url: str, role: str, password: str) -> str:
    return make_url(owner_url).set(username=role, password=password).render_as_string(hide_password=False)


def isolation_checks(app_url: str, tables: list[str]) -> dict:
    eng = create_engine(app_url)
    out: dict = {"tables": len(tables), "violations": []}
    with eng.connect() as conn:
        for table in tables:
            def count(org: str | None, extra: str = "") -> int:
                with conn.begin():
                    conn.execute(text("SELECT set_config('accessproof.organization_id', :o, true)"),
                                 {"o": org or ""})
                    if extra:
                        conn.execute(text(extra))
                    return conn.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()

            if count(None):
                out["violations"].append(f"{table}:rows_without_tenant")
            with conn.begin():
                conn.execute(text("SELECT set_config('accessproof.organization_id', :o, true)"), {"o": ORG_A})
                orgs = {r[0] for r in conn.execute(text(f'SELECT DISTINCT organization_id FROM "{table}"'))}
                if orgs != {ORG_A}:
                    out["violations"].append(f"{table}:tenant_a_sees:{sorted(orgs)}")
                upd = conn.execute(text(f'UPDATE "{table}" SET organization_id = organization_id '
                                        "WHERE organization_id = :b"), {"b": ORG_B}).rowcount
                dele = conn.execute(text(f'DELETE FROM "{table}" WHERE organization_id = :b'),
                                    {"b": ORG_B}).rowcount
                if upd or dele:
                    out["violations"].append(f"{table}:cross_tenant_write")
            # Legacy settable bypass must be inert.
            try:
                if count(None, "SET LOCAL accessproof.rls_bypass = 'on'"):
                    out["violations"].append(f"{table}:guc_bypass")
            except Exception:
                pass  # refusing the GUC is also a pass
        # Cross-tenant INSERT (WITH CHECK) on the authorization core table.
        with conn.begin():
            conn.execute(text("SELECT set_config('accessproof.organization_id', :o, true)"), {"o": ORG_A})
            row = _filler(conn, "ai_applications", ORG_B)
        try:
            with conn.begin():
                conn.execute(text("SELECT set_config('accessproof.organization_id', :o, true)"), {"o": ORG_A})
                cols = ", ".join(f'"{c}"' for c in row)
                vals = ", ".join(f":{c}" for c in row)
                conn.execute(text(f'INSERT INTO "ai_applications" ({cols}) VALUES ({vals})'), row)
            out["violations"].append("ai_applications:cross_tenant_insert_accepted")
        except Exception as exc:
            out["cross_tenant_insert"] = "REJECTED:" + type(exc).__name__
        with conn.begin():
            out["audit"] = audit(conn)
    eng.dispose()
    out["ok"] = not out["violations"] and not out["audit"]["tables_missing_policy"] \
        and not out["audit"]["bypassrls"] and not out["audit"]["superuser"]
    return out


def snapshot(owner_url: str, tables: list[str]) -> dict:
    eng = create_engine(owner_url)
    with eng.connect() as conn:
        counts = {t: conn.execute(text(f'SELECT count(*) FROM "{t}"')).scalar_one() for t in tables}
        rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        forced = conn.execute(text(
            "SELECT count(*) FROM pg_class WHERE relrowsecurity AND relforcerowsecurity")).scalar_one()
        policies = conn.execute(text("SELECT count(*) FROM pg_policies")).scalar_one()
    eng.dispose()
    return {"row_counts": counts, "alembic_revision": rev, "forced_rls_tables": forced, "policies": policies}


def dexec(container: str, *args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", container, *args], capture_output=True, check=True, **kw)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--owner-url", required=True)
    p.add_argument("--app-password-file", required=True, type=Path)
    p.add_argument("--worker-password-file", required=True, type=Path)
    p.add_argument("--container", required=True)
    p.add_argument("--json-out", type=Path)
    a = p.parse_args()
    guard_disposable(a.owner_url)
    app_pw = a.app_password_file.read_text().strip()
    owner = make_url(a.owner_url)
    src_db, dst_db = owner.database, owner.database + "_restore"
    result: dict = {"started_at": datetime.now(timezone.utc).isoformat(), "postgres": None}

    tables = seed(a.owner_url)
    result["seeded_tables"] = len(tables)
    result["source"] = {"isolation": isolation_checks(role_url(a.owner_url, APP_ROLE, app_pw), tables),
                        "snapshot": snapshot(a.owner_url, tables)}
    result["postgres"] = dexec(a.container, "postgres", "--version", text=True).stdout.strip()

    t0 = time.monotonic()
    dump = dexec(a.container, "pg_dump", "-U", owner.username, "--format=custom", src_db).stdout
    t_dump = time.monotonic() - t0
    result["backup"] = {"sha256": hashlib.sha256(dump).hexdigest(), "size_bytes": len(dump),
                        "seconds": round(t_dump, 3)}

    t1 = time.monotonic()
    dexec(a.container, "dropdb", "-U", owner.username, "--if-exists", dst_db)
    dexec(a.container, "createdb", "-U", owner.username, dst_db)
    subprocess.run(["docker", "exec", "-i", a.container, "pg_restore", "-U", owner.username,
                    "--no-owner", "--exit-on-error", "-d", dst_db], input=dump, capture_output=True, check=True)
    restored_url = owner.set(database=dst_db).render_as_string(hide_password=False)
    # Grants are database-level objects restored by pg_dump, but re-apply them as
    # the documented post-restore step (idempotent) so the runtime roles work.
    eng = create_engine(restored_url)
    with eng.begin() as conn:
        grant_runtime_privileges(conn)
    eng.dispose()
    rto = time.monotonic() - t1
    result["restore"] = {"seconds": round(rto, 3), "database": dst_db}

    restored_snapshot = snapshot(restored_url, tables)
    result["restored"] = {"isolation": isolation_checks(role_url(restored_url, APP_ROLE, app_pw), tables),
                          "snapshot": restored_snapshot}
    result["snapshot_equal"] = restored_snapshot == result["source"]["snapshot"]
    result["ok"] = bool(result["source"]["isolation"]["ok"] and result["restored"]["isolation"]["ok"]
                        and result["snapshot_equal"])
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    for side in ("source", "restored"):
        result[side]["snapshot"]["row_counts"] = {"tables": len(tables),
                                                  "total_rows": sum(result[side]["snapshot"]["row_counts"].values())}
    payload = json.dumps(result, indent=2, default=str)
    if a.json_out:
        a.json_out.write_text(payload)
    print(payload)
    _ = WORKER_ROLE
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
