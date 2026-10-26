"""Add encrypted reusable test identities and bind runs to them.

Revision ID: b91e2ac7d4f1
Revises: af42d9c7310e
"""
from alembic import op
import sqlalchemy as sa

revision = "b91e2ac7d4f1"
down_revision = "af42d9c7310e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "test_identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("provider_type", sa.String(50), nullable=False), sa.Column("provider_name", sa.String(200)),
        sa.Column("subject_id", sa.String(320), nullable=False), sa.Column("email", sa.String(320)),
        sa.Column("tenant_id", sa.String(320)), sa.Column("issuer", sa.Text()), sa.Column("audience", sa.String(500)),
        sa.Column("required_scopes_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("encrypted_credentials", sa.Text()), sa.Column("status", sa.String(40), nullable=False, server_default="configured"),
        sa.Column("last_validated_at", sa.DateTime(timezone=True)), sa.Column("last_error", sa.Text()),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "provider_type", "subject_id", name="uq_test_identity_subject"),
    )
    op.add_column("test_runs", sa.Column("allowed_identity_id", sa.String(36), nullable=True))
    op.add_column("test_runs", sa.Column("denied_identity_id", sa.String(36), nullable=True))
    op.create_index("ix_test_runs_allowed_identity_id", "test_runs", ["allowed_identity_id"])
    op.create_index("ix_test_runs_denied_identity_id", "test_runs", ["denied_identity_id"])


def downgrade() -> None:
    op.drop_index("ix_test_runs_denied_identity_id", table_name="test_runs")
    op.drop_index("ix_test_runs_allowed_identity_id", table_name="test_runs")
    op.drop_column("test_runs", "denied_identity_id")
    op.drop_column("test_runs", "allowed_identity_id")
    op.drop_table("test_identities")
