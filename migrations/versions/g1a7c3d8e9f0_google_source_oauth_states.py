"""Add one-time Google source authorization-code and PKCE state."""
from alembic import op
import sqlalchemy as sa

revision = "g1a7c3d8e9f0"
down_revision = "f7a9c2d4e6b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("google_source_oauth_states",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("initiated_by_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("encrypted_verifier", sa.Text(), nullable=False),
        sa.Column("config_fingerprint", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for field in ("organization_id", "source_id", "state_hash"):
        op.create_index(f"ix_google_source_oauth_states_{field}", "google_source_oauth_states", [field])


def downgrade() -> None:
    op.drop_table("google_source_oauth_states")
