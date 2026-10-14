"""Persist Guard effective-access and protection decision state."""
from alembic import op
import sqlalchemy as sa

revision = "f6c8d2e4b5a6"
down_revision = "e5b7c1d2a3f4"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("guard_effective_access", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("source_id", sa.String(36), nullable=False), sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("resource_id", sa.String(36), nullable=False), sa.Column("scope", sa.String(100), nullable=False), sa.Column("decision", sa.String(20), nullable=False), sa.Column("source_revision", sa.Integer, nullable=False), sa.Column("state_version", sa.Integer, nullable=False), sa.Column("reason", sa.String(255), nullable=False), sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "source_id", "subject_id", "resource_id", "scope"))
    op.create_index("ix_guard_effective_access_organization_id", "guard_effective_access", ["organization_id"])
    op.create_table("guard_protection_decisions", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("guard_id", sa.String(36)), sa.Column("application_id", sa.String(36), nullable=False), sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("request_id", sa.String(255), nullable=False), sa.Column("policy_version", sa.Integer, nullable=False), sa.Column("mode", sa.String(20), nullable=False), sa.Column("result", sa.String(30), nullable=False), sa.Column("reason", sa.String(255), nullable=False), sa.Column("resources_json", sa.Text, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_guard_protection_decisions_organization_id", "guard_protection_decisions", ["organization_id"])

def downgrade() -> None:
    op.drop_table("guard_protection_decisions")
    op.drop_table("guard_effective_access")
