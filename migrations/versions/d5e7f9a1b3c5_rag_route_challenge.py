"""Enrolled Guard verified RAG route challenge evidence (tenant scoped)."""
from alembic import op
import sqlalchemy as sa

revision = "d5e7f9a1b3c5"
down_revision = "c4d6e8f0a215"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rag_route_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(36), sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("guard_id", sa.String(36), sa.ForeignKey("guard_registrations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("nonce_digest", sa.String(64), nullable=False),
        sa.Column("configuration_fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("deployment_sha256", sa.String(64), nullable=False),
        sa.Column("route_sha256", sa.String(64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cutover_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("organization_id", "application_row_id", "nonce_digest"),
        sa.UniqueConstraint("nonce_digest"),
    )
    for col in ("organization_id", "application_row_id", "guard_id"):
        op.create_index(f"ix_rag_route_challenges_{col}", "rag_route_challenges", [col])
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute('ALTER TABLE "rag_route_challenges" ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "rag_route_challenges" FORCE ROW LEVEL SECURITY')
        predicate = ("current_setting('accessproof.rls_bypass', true) = 'on' "
                     "OR organization_id::text = current_setting('accessproof.organization_id', true)")
        op.execute('CREATE POLICY accessproof_tenant_isolation ON "rag_route_challenges" '
                   f'USING ({predicate}) WITH CHECK ({predicate})')


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute('DROP POLICY IF EXISTS accessproof_tenant_isolation ON "rag_route_challenges"')
        op.execute('ALTER TABLE "rag_route_challenges" NO FORCE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "rag_route_challenges" DISABLE ROW LEVEL SECURITY')
    for col in ("guard_id", "application_row_id", "organization_id"):
        op.drop_index(f"ix_rag_route_challenges_{col}", table_name="rag_route_challenges")
    op.drop_table("rag_route_challenges")
