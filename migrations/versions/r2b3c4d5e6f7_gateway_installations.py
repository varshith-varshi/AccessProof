"""Durable Gateway installation identity and authenticated heartbeat (D-02).

Revision ID: r2b3c4d5e6f7
Revises: q1a2b3c4d5e6
"""
from alembic import op
import sqlalchemy as sa

revision = "r2b3c4d5e6f7"
down_revision = "q1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gateway_installations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(36),
                  sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_hash", sa.String(128), nullable=False),
        sa.Column("guard_id", sa.String(36), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("deployment_sha256", sa.String(64), nullable=False),
        sa.Column("route_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sequence", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("last_reported_ready", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("last_readiness_code", sa.String(80), nullable=True),
        sa.Column("gateway_version", sa.String(64), nullable=True),
        sa.UniqueConstraint("application_row_id"),
    )
    op.create_index("ix_gateway_installations_organization_id", "gateway_installations", ["organization_id"])
    op.create_index("ix_gateway_installations_application_row_id", "gateway_installations", ["application_row_id"])
    if op.get_bind().dialect.name == "postgresql":
        predicate = ("(organization_id = current_setting('accessproof.organization_id', true) "
                     "OR current_user = 'accessproof_rls_admin')")
        op.execute('ALTER TABLE "gateway_installations" ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "gateway_installations" FORCE ROW LEVEL SECURITY')
        op.execute('CREATE POLICY accessproof_tenant_isolation ON "gateway_installations" '
                   f'USING ({predicate}) WITH CHECK ({predicate})')


def downgrade() -> None:
    op.drop_table("gateway_installations")
