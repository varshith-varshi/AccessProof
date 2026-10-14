"""Persist the first Guard control-plane security model."""
from alembic import op
import sqlalchemy as sa

revision = "e5b7c1d2a3f4"
down_revision = "d4a1e8f90b21"
branch_labels = None
depends_on = None

def upgrade() -> None:
    org = lambda: sa.ForeignKey("organizations.id", ondelete="CASCADE")
    op.create_table("guard_subjects", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), org(), nullable=False), sa.Column("provider", sa.String(50), nullable=False), sa.Column("provider_subject_id", sa.String(255), nullable=False), sa.Column("display_name", sa.String(255)), sa.Column("primary_email", sa.String(320)), sa.Column("status", sa.String(20), nullable=False, server_default="active"), sa.Column("last_synced_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "provider", "provider_subject_id"))
    op.create_index("ix_guard_subjects_organization_id", "guard_subjects", ["organization_id"])
    op.create_table("guard_resources", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), org(), nullable=False), sa.Column("source_id", sa.String(36), nullable=False), sa.Column("provider_resource_id", sa.String(512), nullable=False), sa.Column("parent_resource_id", sa.String(36)), sa.Column("resource_type", sa.String(50), nullable=False), sa.Column("scope", sa.String(100), nullable=False), sa.Column("metadata_json", sa.Text, nullable=False, server_default="{}"), sa.Column("last_synced_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("organization_id", "source_id", "provider_resource_id"))
    op.create_index("ix_guard_resources_organization_id", "guard_resources", ["organization_id"])
    op.create_table("guard_permission_events", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), org(), nullable=False), sa.Column("source_id", sa.String(36), nullable=False), sa.Column("provider", sa.String(50), nullable=False), sa.Column("provider_revision", sa.Integer, nullable=False, server_default="0"), sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("resource_id", sa.String(36), nullable=False), sa.Column("change_type", sa.String(30), nullable=False), sa.Column("dedupe_key", sa.String(128), nullable=False), sa.Column("processing_status", sa.String(30), nullable=False, server_default="received"), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.Column("received_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "dedupe_key"))
    op.create_index("ix_guard_permission_events_organization_id", "guard_permission_events", ["organization_id"])
    op.create_table("guard_policies", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), org(), nullable=False), sa.Column("policy_key", sa.String(255), nullable=False), sa.Column("version", sa.Integer, nullable=False), sa.Column("mode", sa.String(20), nullable=False), sa.Column("decision", sa.String(20), nullable=False), sa.Column("subject_id", sa.String(36), nullable=False), sa.Column("resource_id", sa.String(36), nullable=False), sa.Column("reason", sa.String(255), nullable=False), sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "policy_key", "version"))
    op.create_index("ix_guard_policies_organization_id", "guard_policies", ["organization_id"])
    op.create_table("guard_registrations", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), org(), nullable=False), sa.Column("name", sa.String(200), nullable=False), sa.Column("environment", sa.String(50), nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("version", sa.String(50), nullable=False), sa.Column("active_policy_version", sa.Integer, nullable=False, server_default="0"), sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)), sa.Column("credential_hash", sa.String(128)), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_guard_registrations_organization_id", "guard_registrations", ["organization_id"])

def downgrade() -> None:
    for table in ("guard_registrations", "guard_policies", "guard_permission_events", "guard_resources", "guard_subjects"):
        op.drop_table(table)
