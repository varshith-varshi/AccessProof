"""Store exact, signed and expiring provider-specific effective ACL coverage."""
from alembic import op
import sqlalchemy as sa

revision = "c4d6e8f0a215"
down_revision = "b3c5d7e9f103"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("source_effective_certifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider_profile", sa.String(80), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("verifier_version", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("certified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.UniqueConstraint("organization_id", "source_id"),
    )
    op.create_index("ix_source_effective_certifications_organization_id", "source_effective_certifications", ["organization_id"])
    op.create_index("ix_source_effective_certifications_source_id", "source_effective_certifications", ["source_id"])


def downgrade() -> None:
    op.drop_index("ix_source_effective_certifications_source_id", table_name="source_effective_certifications")
    op.drop_index("ix_source_effective_certifications_organization_id", table_name="source_effective_certifications")
    op.drop_table("source_effective_certifications")
