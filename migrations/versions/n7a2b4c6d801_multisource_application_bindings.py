"""Store explicit multi-source application bindings without removing legacy source_id.

Revision ID: n7a2b4c6d801
Revises: m6f1a9c2d318
"""
from alembic import op
import sqlalchemy as sa

revision = "n7a2b4c6d801"
down_revision = "m6f1a9c2d318"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_application_source_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(36), sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "application_row_id", "source_id"),
    )
    for name in ("organization_id", "application_row_id", "source_id"):
        op.create_index(f"ix_ai_application_source_bindings_{name}", "ai_application_source_bindings", [name])
    # Preserve existing registrations and make every old source binding explicit.
    bind = op.get_bind()
    rows = bind.execute(sa.text(
        "SELECT a.id, a.organization_id, a.source_id FROM ai_applications a "
        "JOIN source_connections s ON s.id=a.source_id AND s.organization_id=a.organization_id "
        "WHERE a.source_id IS NOT NULL"
    )).fetchall()
    from datetime import datetime, timezone
    from uuid import uuid4
    for application_id, org_id, source_id in rows:
        bind.execute(sa.text(
            "INSERT INTO ai_application_source_bindings "
            "(id, organization_id, application_row_id, source_id, created_at) "
            "VALUES (:id, :org, :app, :src, :at)"
        ), {"id": str(uuid4()), "org": org_id, "app": application_id, "src": source_id, "at": datetime.now(timezone.utc)})
    if bind.dialect.name == "postgresql":
        predicate = "(organization_id = current_setting('accessproof.organization_id', true) OR current_user = 'accessproof_rls_admin')"
        op.execute('ALTER TABLE ai_application_source_bindings ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE ai_application_source_bindings FORCE ROW LEVEL SECURITY')
        op.execute('CREATE POLICY accessproof_tenant_isolation ON ai_application_source_bindings '
                   f'USING ({predicate}) WITH CHECK ({predicate})')


def downgrade() -> None:
    # Rollback is only safe if no application now has multiple bindings.
    bind = op.get_bind()
    count = bind.execute(sa.text(
        "SELECT count(*) FROM (SELECT application_row_id FROM ai_application_source_bindings "
        "GROUP BY application_row_id HAVING count(*) > 1) sub"
    )).scalar()
    if count:
        raise RuntimeError("MULTISOURCE_DOWNGRADE_REQUIRES_DATA_MIGRATION")
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS accessproof_tenant_isolation ON ai_application_source_bindings")
        op.execute("ALTER TABLE ai_application_source_bindings NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ai_application_source_bindings DISABLE ROW LEVEL SECURITY")
    for name in ("source_id", "application_row_id", "organization_id"):
        op.drop_index(f"ix_ai_application_source_bindings_{name}", table_name="ai_application_source_bindings")
    op.drop_table("ai_application_source_bindings")
