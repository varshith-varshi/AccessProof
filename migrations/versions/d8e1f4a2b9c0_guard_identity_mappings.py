"""Add OIDC principal to source identity mappings for Guard enforcement.

Revision ID: d8e1f4a2b9c0
Revises: c2d4e6f8a0b1
"""

from alembic import op
import sqlalchemy as sa


revision = "d8e1f4a2b9c0"
down_revision = "c2d4e6f8a0b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guard_identity_mappings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("oidc_issuer", sa.String(1000), nullable=False),
        sa.Column("oidc_subject", sa.String(500), nullable=False),
        sa.Column("oidc_tenant_id", sa.String(255), nullable=True, server_default=""),
        sa.Column("source_subject_id", sa.String(36), sa.ForeignKey("guard_subjects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="VERIFIED"),
        sa.Column("method", sa.String(50), nullable=False, server_default="admin_verified"),
        sa.Column("verified_by_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "source_id", "oidc_issuer", "oidc_subject", "oidc_tenant_id", name="uq_guard_identity_mapping_principal"),
    )
    for name, columns in (
        ("ix_guard_identity_mappings_organization_id", ["organization_id"]),
        ("ix_guard_identity_mappings_source_id", ["source_id"]),
        ("ix_guard_identity_mappings_oidc_issuer", ["oidc_issuer"]),
        ("ix_guard_identity_mappings_oidc_subject", ["oidc_subject"]),
        ("ix_guard_identity_mappings_source_subject_id", ["source_subject_id"]),
        ("ix_guard_identity_mappings_status", ["status"]),
    ):
        op.create_index(name, "guard_identity_mappings", columns)


def downgrade() -> None:
    op.drop_table("guard_identity_mappings")
