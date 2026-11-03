"""P0-01: database-enforced tenant isolation, proven as the restricted roles.

Runs only in PostgreSQL mode (ACCESSPROOF_TEST_PG_* set; see tests/conftest.py)
because SQLite has no roles or row-level security. Application-level filters
are deliberately bypassed here: every query is raw SQL with no WHERE clause
on organization_id, so only the database policy can stop cross-tenant access.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

OWNER = os.environ.get("ACCESSPROOF_TEST_PG_OWNER_URL", "")
APP = os.environ.get("ACCESSPROOF_TEST_PG_APP_URL", "")
WORKER = os.environ.get("ACCESSPROOF_TEST_PG_WORKER_URL", "")
METRICS = os.environ.get("ACCESSPROOF_TEST_PG_METRICS_URL", "")
pytestmark = pytest.mark.skipif(not (OWNER and APP and WORKER and METRICS),
                                reason="PostgreSQL role mode not configured")


@pytest.fixture()
def tenants():
    from apps.api.accessproof_api.db import Base, engine
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    owner = create_engine(OWNER)
    with owner.begin() as c:
        for org in ("org-a", "org-b"):
            c.execute(text("INSERT INTO organizations (id, name, mutations_disabled, created_at) "
                           "VALUES (:o, :o, false, now())"), {"o": org})
            c.execute(text("INSERT INTO ai_applications (id, organization_id, application_id, name, mode, "
                           "adapter_type, adapter_contract_version, created_at) VALUES "
                           "(:i, :o, 'rag', 'RAG', 'protect', 'accessproof-gateway', 'accessproof.rag/v1', now())"),
                      {"i": f"app-{org}", "o": org})
    owner.dispose()
    engines = {name: create_engine(url, pool_size=1, max_overflow=0)
               for name, url in (("app", APP), ("worker", WORKER), ("metrics", METRICS))}
    yield engines
    for e in engines.values():
        e.dispose()


def _as_tenant(conn, org: str | None) -> None:
    conn.execute(text("SELECT set_config('accessproof.organization_id', :o, true)"), {"o": org or ""})


def test_app_role_sees_and_writes_only_its_tenant(tenants):
    with tenants["app"].begin() as c:
        _as_tenant(c, "org-a")
        assert c.execute(text("SELECT organization_id FROM ai_applications")).scalars().all() == ["org-a"]
        assert c.execute(text("UPDATE ai_applications SET name = 'pwned'")).rowcount == 1  # own row only
    with tenants["app"].begin() as c:
        _as_tenant(c, "org-a")
        with pytest.raises(DBAPIError, match="row-level security"):
            c.execute(text("INSERT INTO ai_applications (id, organization_id, application_id, name, mode, "
                           "adapter_type, adapter_contract_version, created_at) VALUES "
                           "('x', 'org-b', 'evil', 'x', 'shadow', 'accessproof-gateway', 'accessproof.rag/v1', now())"))
    with tenants["app"].begin() as c:
        _as_tenant(c, None)
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 0
        assert c.execute(text("DELETE FROM ai_applications")).rowcount == 0


def test_former_settable_bypass_no_longer_works(tenants):
    with tenants["app"].begin() as c:
        c.execute(text("SET LOCAL accessproof.rls_bypass = 'on'"))
        _as_tenant(c, None)
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM source_connections")).scalar() == 0


def test_restricted_roles_cannot_disable_policies_or_escalate(tenants):
    for name in ("app", "worker", "metrics"):
        with tenants[name].connect() as c:
            for stmt in ('ALTER TABLE ai_applications DISABLE ROW LEVEL SECURITY',
                         'DROP POLICY accessproof_tenant_isolation ON ai_applications',
                         'SET ROLE accessproof_rls_admin' if name != "worker" else 'SET ROLE accessproof',
                         'CREATE ROLE escalation SUPERUSER'):
                with pytest.raises(DBAPIError):
                    with c.begin():
                        c.execute(text(stmt))


def test_tenant_context_never_leaks_across_pooled_connections_or_rollbacks(tenants):
    with tenants["app"].begin() as c:   # pool_size=1: the next block reuses this connection
        _as_tenant(c, "org-a")
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 1
    with tenants["app"].begin() as c:
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 0
    with tenants["app"].connect() as c:
        tx = c.begin()
        _as_tenant(c, "org-b")
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 1
        tx.rollback()
        with c.begin():
            assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 0


def test_worker_is_cross_tenant_and_metrics_is_read_only(tenants):
    with tenants["worker"].begin() as c:
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 2
    with tenants["metrics"].begin() as c:
        assert c.execute(text("SELECT count(*) FROM ai_applications")).scalar() == 2
    with tenants["metrics"].connect() as c:
        for stmt in ("UPDATE ai_applications SET name = 'x'", "DELETE FROM audit_events",
                     "INSERT INTO audit_events (id) VALUES ('x')"):
            with pytest.raises(DBAPIError, match="permission denied"):
                with c.begin():
                    c.execute(text(stmt))


def test_application_runtime_audit_reports_least_privilege(tenants):
    from apps.api.accessproof_api.db_security import audit
    with tenants["app"].connect() as c:
        facts = audit(c)
    assert facts["superuser"] is False and facts["bypassrls"] is False and facts["owns_tables"] is False
    assert facts["tables_missing_policy"] == [] and facts["settable_bypass_policies"] == 0
