"""SCIM provisioning configuration and identities

Revision ID: 73c9d4e812ab
Revises: 4d21b7a6c9f0
"""

from alembic import op
import sqlalchemy as sa

revision = "73c9d4e812ab"
down_revision = "4d21b7a6c9f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scim_configurations",
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("default_role", sa.String(length=20), nullable=False, server_default="VIEWER"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_scim_configurations_token_hash", "scim_configurations", ["token_hash"], unique=True
    )
    op.create_table(
        "scim_identities",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_name", sa.String(length=320), nullable=False),
        sa.Column("external_id", sa.String(length=500), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_scim_identity_user"),
        sa.UniqueConstraint("organization_id", "user_name", name="uq_scim_identity_username"),
    )
    op.create_index("ix_scim_identities_organization_id", "scim_identities", ["organization_id"])
    op.create_index("ix_scim_identities_user_id", "scim_identities", ["user_id"])
    op.create_index("ix_scim_identities_user_name", "scim_identities", ["user_name"])
    op.create_index("ix_scim_identities_external_id", "scim_identities", ["external_id"])


def downgrade() -> None:
    op.drop_table("scim_identities")
    op.drop_table("scim_configurations")
