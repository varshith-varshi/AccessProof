#!/usr/bin/env python3
"""Scale benchmark for automatic identity resolution (synthetic identities only).

    DATABASE_URL=postgresql+psycopg://owner:pw@127.0.0.1:55433/bench \\
      python scripts/bench/identity_scale.py --sizes 100,1000,10000,100000 --out report.json

Runs the REAL directory sync + reconciliation + Guard envelope code against a
disposable PostgreSQL database with a mocked Microsoft Graph (no tenant calls).
Never point it at a real database: it drops and recreates the schema.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import statistics
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "127.0.0.1" not in os.environ.get("DATABASE_URL", "") and "localhost" not in os.environ.get("DATABASE_URL", ""):
    sys.exit("refusing: DATABASE_URL must be a local disposable database")

from sqlalchemy import event, func, select  # noqa: E402

from apps.api.accessproof_api import directory_sync  # noqa: E402
from apps.api.accessproof_api.db import (  # noqa: E402
    Base, GuardIdentityMapping, GuardSubject, Organization, Project, SessionLocal, SourceConnection, engine,
)
from apps.api.accessproof_api.identity_resolution import identity_version, reconcile_microsoft_bindings  # noqa: E402
from apps.guard.accessproof_guard.cache import PolicyCache  # noqa: E402
from connectors.directory import DirectoryUser  # noqa: E402

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"


class FakeEntra:
    users_data: list[DirectoryUser] = []

    def __init__(self, token: str) -> None:
        pass

    async def users(self):
        return self.users_data

    async def groups(self):
        return []

    async def members(self, group):
        return []

    async def close(self):
        pass


directory_sync.MicrosoftEntraDirectoryAdapter = FakeEntra  # mocked Graph


class Counter:
    def __init__(self):
        self.selects = self.writes = 0

    def __call__(self, conn, cursor, statement, params, context, executemany):
        head = statement.lstrip()[:6].upper()
        if head == "SELECT":
            self.selects += 1
        elif head in ("INSERT", "UPDATE", "DELETE"):
            self.writes += 1


def measured(fn):
    counter = Counter()
    event.listen(engine, "before_cursor_execute", counter)
    t0 = time.perf_counter()
    try:
        value = fn()
    finally:
        event.remove(engine, "before_cursor_execute", counter)
    return value, round(time.perf_counter() - t0, 3), counter.selects, counter.writes


def users(n: int, disabled_every: int = 0) -> list[DirectoryUser]:
    out = []
    for i in range(n):
        oid = str(uuid.UUID(int=(0x0D6A6D2E << 96) + i))
        status = "disabled" if disabled_every and i % disabled_every == 0 else "active"
        kind = "guest" if i % 50 == 49 else "member"         # 2% guests, never bound
        out.append(DirectoryUser(oid, f"Employee {i}", f"e{i}@bench.invalid", status, kind))
    return out


def run_size(n: int) -> dict:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name=f"bench-{n}")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint",
                                  name="bench", boundary="root", status="connected")
        db.add(source)
        db.commit()
        org_id, source_id = org.id, source.id
    creds = {"access_token": "synthetic", "tenant_id": TENANT}
    report: dict = {"identities": n}

    def sync(data):
        FakeEntra.users_data = data
        with SessionLocal() as db:
            src = db.get(SourceConnection, source_id)
            result = asyncio.run(directory_sync.synchronize_directory(db, src, creds))
            db.commit()
            return result

    r, secs, sel, wr = measured(lambda: sync(users(n)))
    report["initial_sync"] = {"seconds": secs, "select_statements": sel, "write_statements": wr,
                              "resolution": r["automatic_identity_resolution"]}
    r, secs, sel, wr = measured(lambda: sync(users(n)))
    report["unchanged_resync"] = {"seconds": secs, "select_statements": sel, "write_statements": wr,
                                  "created": r["automatic_identity_resolution"]["created"]}
    r, secs, sel, wr = measured(lambda: sync(users(n, disabled_every=100)))
    report["one_percent_disabled"] = {"seconds": secs, "select_statements": sel, "write_statements": wr,
                                      "suspended": r["automatic_identity_resolution"]["suspended"]}
    with SessionLocal() as db:
        lat = []
        for _ in range(50):
            t0 = time.perf_counter()
            identity_version(db, org_id)
            lat.append((time.perf_counter() - t0) * 1000)
        report["identity_version_ms"] = {"p50": round(statistics.median(lat), 2), "max": round(max(lat), 2)}
        t0 = time.perf_counter()
        rows = db.execute(select(GuardIdentityMapping.source_id, GuardIdentityMapping.oidc_issuer,
                                 GuardIdentityMapping.oidc_subject, GuardIdentityMapping.oidc_tenant_id,
                                 GuardSubject.provider_subject_id)
                          .join(GuardSubject, GuardSubject.id == GuardIdentityMapping.source_subject_id)
                          .where(GuardIdentityMapping.organization_id == org_id,
                                 GuardIdentityMapping.status == "VERIFIED", GuardSubject.status == "active")).all()
        envelope = [{"source_id": a, "issuer": b, "subject": c, "tenant_id": d or "", "source_subject_id": e}
                    for a, b, c, d, e in rows]
        body = json.dumps(envelope)
        report["full_identity_envelope"] = {"mappings": len(envelope), "build_seconds": round(time.perf_counter() - t0, 3),
                                            "json_bytes": len(body)}
        verified = int(db.scalar(select(func.count(GuardIdentityMapping.id)).where(
            GuardIdentityMapping.organization_id == org_id, GuardIdentityMapping.status == "VERIFIED")))
        dupes = int(db.scalar(select(func.count()).select_from(
            select(GuardIdentityMapping.oidc_subject).where(GuardIdentityMapping.organization_id == org_id)
            .group_by(GuardIdentityMapping.source_id, GuardIdentityMapping.oidc_subject)
            .having(func.count() > 1).subquery())))
        report["verified_bindings"], report["duplicate_bindings"] = verified, dupes
    # Guard: install the full set, then resolve with p50/p95/p99.
    with tempfile.TemporaryDirectory() as tmp:
        cache = PolicyCache(str(Path(tmp) / "g.db"))
        t0 = time.perf_counter()
        cache.set_identity_mappings(envelope)
        report["guard_install_seconds"] = round(time.perf_counter() - t0, 3)
        lat = []
        sample = envelope[:: max(1, len(envelope) // 2000)] or envelope
        for m in sample:
            t0 = time.perf_counter()
            assert cache.resolve_identity(m["source_id"], ISSUER, m["subject"], TENANT) == m["source_subject_id"]
            lat.append((time.perf_counter() - t0) * 1_000_000)
        lat.sort()
        q = lambda p: round(lat[min(len(lat) - 1, int(p * len(lat)))], 1)  # noqa: E731
        report["guard_resolve_us"] = {"samples": len(lat), "p50": q(0.50), "p95": q(0.95), "p99": q(0.99)}
        t0 = time.perf_counter()
        miss = cache.resolve_identity(source_id, ISSUER, str(uuid.uuid4()), TENANT)
        report["guard_unknown_identity"] = {"result": miss, "us": round((time.perf_counter() - t0) * 1e6, 1)}
    # Two workers reconciling the same source at once: no duplicates.
    with SessionLocal() as db:
        db.query(GuardIdentityMapping).filter(GuardIdentityMapping.organization_id == org_id).delete()
        db.commit()
    errors: list[str] = []

    def worker():
        try:
            with SessionLocal() as db:
                reconcile_microsoft_bindings(db, db.get(SourceConnection, source_id), TENANT)
                db.commit()
        except Exception as exc:  # the loser hits the unique constraint and retries next cycle
            errors.append(type(exc).__name__)
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    with SessionLocal() as db:
        retry_needed = int(db.scalar(select(func.count(GuardIdentityMapping.id)).where(
            GuardIdentityMapping.organization_id == org_id))) < verified
        if retry_needed:
            reconcile_microsoft_bindings(db, db.get(SourceConnection, source_id), TENANT)
            db.commit()
        dupes = int(db.scalar(select(func.count()).select_from(
            select(GuardIdentityMapping.oidc_subject).where(GuardIdentityMapping.organization_id == org_id)
            .group_by(GuardIdentityMapping.source_id, GuardIdentityMapping.oidc_subject)
            .having(func.count() > 1).subquery())))
        final = int(db.scalar(select(func.count(GuardIdentityMapping.id)).where(
            GuardIdentityMapping.organization_id == org_id, GuardIdentityMapping.status == "VERIFIED")))
    report["concurrent_reconcile"] = {"worker_errors": errors, "retry_needed": retry_needed,
                                      "duplicates": dupes, "verified_after": final}
    report["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sizes", default="100,1000,10000,100000")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    results = []
    for n in [int(x) for x in a.sizes.split(",")]:
        results.append(run_size(n))
        print(json.dumps(results[-1]), flush=True)
    Path(a.out).write_text(json.dumps({"schema": "accessproof.identity_scale_bench/v1",
                                       "database": "postgresql (disposable)", "results": results}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
