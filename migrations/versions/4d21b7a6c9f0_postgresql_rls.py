"""PostgreSQL row-level security defense in depth

Revision ID: 4d21b7a6c9f0
Revises: 0f4e8a2d1c77
"""

from alembic import op

revision = "4d21b7a6c9f0"
down_revision = "0f4e8a2d1c77"
branch_labels = None
depends_on = None

TABLES = (
    "projects",
    "source_connections",
    "ai_targets",
    "test_suites",
    "releases",
    "test_runs",
    "reports",
    "evidence_items",
    "run_state_transitions",
    "synthetic_resources",
    "runner_checkpoints",
    "mutation_journal",
    "cleanup_tasks",
    "webhook_endpoints",
    "webhook_deliveries",
    "usage_records",
    "entitlements",
    "alert_records",
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    predicate = "(current_setting('accessproof.rls_bypass', true) = 'on' OR organization_id = current_setting('accessproof.organization_id', true))"
    for table in TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS accessproof_tenant_isolation ON "{table}"')
        op.execute(
            f'CREATE POLICY accessproof_tenant_isolation ON "{table}" USING ({predicate}) WITH CHECK ({predicate})'
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in reversed(TABLES):
        op.execute(f'DROP POLICY IF EXISTS accessproof_tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
