"""Track single-use Microsoft 365 source administrator consent states."""

from alembic import op
import sqlalchemy as sa

revision = "f13a2c4e5d68"
down_revision = "d8e1f4a2b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "microsoft_consent_states",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36),
                  sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("initiated_by_user_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("config_fingerprint", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for name in ("organization_id", "source_id", "state_hash"):
        op.create_index(
            f"ix_microsoft_consent_states_{name}", "microsoft_consent_states", [name]
        )


def downgrade() -> None:
    op.drop_table("microsoft_consent_states")
