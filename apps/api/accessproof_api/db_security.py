"""Canonical PostgreSQL tenant-isolation policy (P0-01).

Single source of truth used by the migration ``t4d5e6f7a8b9`` and by the
PostgreSQL test harness, so tests exercise exactly the deployed policies.

Roles
-----
* migration owner (``POSTGRES_USER``): owns tables, runs Alembic only.
* ``accessproof_app``: API runtime. NOSUPERUSER, NOBYPASSRLS, not an owner,
  so it can neither bypass nor disable policies. Sees only the tenant set by
  ``set_tenant_context`` for the current transaction.
* ``accessproof_rls_admin``: worker runtime. Same restrictions, but the
  policy grants it cross-tenant rows because the worker iterates tenants.

There is deliberately no session-settable bypass (the former
``accessproof.rls_bypass`` GUC could be switched on by any connection).
"""
from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import text
from sqlalchemy.engine import Connection

APP_ROLE = "accessproof_app"
WORKER_ROLE = "accessproof_rls_admin"
# Read-only cross-tenant aggregates for /metrics. SELECT-only policy and
# SELECT-only grants: it can never write or change tenant data.
METRICS_ROLE = "accessproof_metrics"
METRICS_POLICY = "accessproof_metrics_read"
POLICY = "accessproof_tenant_isolation"
PREDICATE = (
    "(organization_id = current_setting('accessproof.organization_id', true) "
    f"OR current_user = '{WORKER_ROLE}')"
)

# Every table holding tenant data that is only accessed after the tenant is
# known (session/API key/machine credential authenticated first).
LEGACY_RLS_TABLES: tuple[str, ...] = (
    # previously protected with a session-settable bypass
    "ai_targets", "alert_records", "api_keys", "audit_events", "cleanup_tasks", "entitlements",
    "evidence_items", "mutation_journal", "oidc_configurations", "oidc_identities", "projects",
    "rag_route_challenges", "releases", "reports", "retention_policies", "run_state_transitions",
    "runner_checkpoints", "scim_group_members", "scim_groups", "scim_identities",
    "source_connections", "synthetic_resources", "test_runs", "test_suites", "usage_records",
    "webhook_deliveries", "webhook_endpoints",
    # previously protected with the fixed worker role
    "ai_application_source_bindings", "authorization_revision_sequences", "authorization_revisions",
    "control_plane_reports", "gateway_installations", "guard_presence_leases",
    "verification_approvals", "verification_events", "verification_evidence",
    "verification_outbox", "verification_runs", "verification_steps",
)
NEWLY_PROTECTED_TABLES: tuple[str, ...] = (
    # previously UNPROTECTED authorization core
    "ai_applications", "guard_audit_events", "guard_effective_access", "guard_group_memberships",
    "guard_groups", "guard_identity_mappings", "guard_permission_events", "guard_permission_grants",
    "guard_permission_snapshots", "guard_policies", "guard_policy_distributions",
    "guard_policy_sequences", "guard_protection_decisions", "guard_resources", "guard_subjects",
    "protection_activation_runs", "provider_sync_cursors", "source_effective_certifications",
    "test_identities",
)
# Added after t4d5e6f7a8b9 (each by its own migration, same canonical policy).
LATER_PROTECTED_TABLES: tuple[str, ...] = ("remote_route_certificates",)
TENANT_TABLES: tuple[str, ...] = LEGACY_RLS_TABLES + NEWLY_PROTECTED_TABLES + LATER_PROTECTED_TABLES

# Tenant tables that must be read BEFORE the tenant is known (credential or
# state lookups). Isolation for these is enforced by the application: the
# lookup is by an unguessable secret hash or state token, and the tenant is
# then derived from the matched row, never from the caller.
BOOTSTRAP_TABLES: dict[str, str] = {
    "memberships": "login resolves a user's workspaces before a tenant is chosen",
    "invitations": "acceptance looks up the invitation by token hash",
    "guard_registrations": "machine authentication resolves the Guard by id + credential hash",
    "guard_enrollments": "one-time enrollment token lookup",
    "oidc_login_states": "OIDC callback state lookup",
    "microsoft_consent_states": "Microsoft admin-consent callback state lookup",
    "google_source_oauth_states": "Google OAuth callback state lookup",
    "email_outbox": "delivered by the worker across tenants",
    "runner_registrations": "legacy runner machine authentication",
    "runners": "legacy runner machine authentication",
    "scim_configurations": "SCIM bearer token lookup",
    "provider_event_journal": "provider webhooks are matched to a tenant by subscription secret",
    "provider_event_subscriptions": "provider webhooks are matched to a tenant by subscription secret",
}


def apply_tenant_policies(connection: Connection, tables: Iterable[str] = TENANT_TABLES) -> list[str]:
    """(Re)create the canonical policy on every existing tenant table."""
    existing = {row[0] for row in connection.execute(text(
        "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"))}
    applied = []
    for table in tables:
        if table not in existing:
            continue
        connection.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        connection.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        connection.execute(text(f'DROP POLICY IF EXISTS {POLICY} ON "{table}"'))
        connection.execute(text(
            f'CREATE POLICY {POLICY} ON "{table}" USING ({PREDICATE}) WITH CHECK ({PREDICATE})'))
        connection.execute(text(f'DROP POLICY IF EXISTS {METRICS_POLICY} ON "{table}"'))
        connection.execute(text(
            f'CREATE POLICY {METRICS_POLICY} ON "{table}" FOR SELECT '
            f"USING (current_user = '{METRICS_ROLE}')"))
        applied.append(table)
    return applied


def grant_runtime_privileges(connection: Connection) -> None:
    """Data privileges only; roles never own tables, so cannot alter policies."""
    for role in (APP_ROLE, WORKER_ROLE):
        exists = connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar()
        if not exists:
            continue
        connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        connection.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}"))
        connection.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"))
        connection.execute(text(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"))
        connection.execute(text(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}"))
    if connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": METRICS_ROLE}).scalar():
        connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {METRICS_ROLE}"))
        connection.execute(text(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {METRICS_ROLE}"))
        connection.execute(text(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {METRICS_ROLE}"))


def audit(connection: Connection) -> dict[str, object]:
    """Read-only facts used by the production security gate."""
    current = connection.execute(text(
        "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")).one()
    policies = {row[0]: row[1] for row in connection.execute(text(
        "SELECT tablename, qual FROM pg_policies WHERE policyname = :p"), {"p": POLICY})}
    all_quals = [row[0] or "" for row in connection.execute(text("SELECT qual FROM pg_policies"))]
    forced = {row[0] for row in connection.execute(text(
        "SELECT relname FROM pg_class WHERE relrowsecurity AND relforcerowsecurity"))}
    owners = {row[0] for row in connection.execute(text(
        "SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = current_schema()"))}
    present = {row[0] for row in connection.execute(text(
        "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"))}
    expected = [t for t in TENANT_TABLES if t in present]
    return {
        "current_user": current[0], "superuser": bool(current[1]), "bypassrls": bool(current[2]),
        "owns_tables": current[0] in owners,
        "tables_missing_policy": sorted(t for t in expected if t not in policies or t not in forced),
        "settable_bypass_policies": sum("rls_bypass" in q for q in all_quals),
        "tenant_tables_checked": len(expected),
    }
