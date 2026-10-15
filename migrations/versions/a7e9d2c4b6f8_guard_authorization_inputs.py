"""Persist Guard authorization inputs and delivery outbox."""
from alembic import op
import sqlalchemy as sa

revision = "a7e9d2c4b6f8"
down_revision = "f6c8d2e4b5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guard_permission_events", sa.Column("mutation_json", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("guard_permission_events", sa.Column("error_code", sa.String(100), nullable=True))
    op.add_column("guard_permission_events", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("guard_permission_events", sa.Column("policy_id", sa.String(36), nullable=True))
    op.create_index("ix_guard_permission_events_policy_id", "guard_permission_events", ["policy_id"])
    op.add_column("guard_policies", sa.Column("source_id", sa.String(36), nullable=True))
    op.add_column("guard_policies", sa.Column("scope", sa.String(100), nullable=False, server_default="read"))
    op.add_column("guard_policies", sa.Column("source_revision", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("guard_policies", sa.Column("effective_state_version", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("guard_policies", sa.Column("supersedes_policy_id", sa.String(36), nullable=True))
    op.create_index("ix_guard_policies_source_id", "guard_policies", ["source_id"])
    op.create_table("guard_policy_sequences", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("next_version", sa.Integer(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id"))
    op.create_index("ix_guard_policy_sequences_organization_id", "guard_policy_sequences", ["organization_id"])
    op.create_table("guard_groups", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("provider", sa.String(50), nullable=False), sa.Column("provider_group_id", sa.String(255), nullable=False), sa.Column("display_name", sa.String(255)), sa.Column("status", sa.String(20), nullable=False), sa.Column("last_synced_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("organization_id", "provider", "provider_group_id"))
    op.create_index("ix_guard_groups_organization_id", "guard_groups", ["organization_id"])
    op.create_table("guard_group_memberships", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("group_id", sa.String(36), sa.ForeignKey("guard_groups.id", ondelete="CASCADE"), nullable=False), sa.Column("subject_id", sa.String(36), sa.ForeignKey("guard_subjects.id", ondelete="CASCADE"), nullable=False), sa.Column("active", sa.Boolean(), nullable=False), sa.Column("provider_revision", sa.Integer(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "group_id", "subject_id"))
    op.create_index("ix_guard_group_memberships_organization_id", "guard_group_memberships", ["organization_id"])
    op.create_index("ix_guard_group_memberships_group_id", "guard_group_memberships", ["group_id"])
    op.create_index("ix_guard_group_memberships_subject_id", "guard_group_memberships", ["subject_id"])
    op.create_table("guard_permission_grants", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("source_id", sa.String(36), nullable=False), sa.Column("resource_id", sa.String(36), sa.ForeignKey("guard_resources.id", ondelete="CASCADE"), nullable=False), sa.Column("grant_key", sa.String(255), nullable=False), sa.Column("principal_type", sa.String(30), nullable=False), sa.Column("principal_id", sa.String(36), nullable=False), sa.Column("effect", sa.String(10), nullable=False), sa.Column("scope", sa.String(100), nullable=False), sa.Column("inherited_from_resource_id", sa.String(36)), sa.Column("access_path", sa.String(255)), sa.Column("active", sa.Boolean(), nullable=False), sa.Column("provider_revision", sa.Integer(), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("organization_id", "source_id", "grant_key"))
    for column in ("organization_id", "source_id", "resource_id", "principal_id"):
        op.create_index(f"ix_guard_permission_grants_{column}", "guard_permission_grants", [column])
    op.create_table("guard_permission_snapshots", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("effective_access_id", sa.String(36), sa.ForeignKey("guard_effective_access.id", ondelete="CASCADE"), nullable=False), sa.Column("permission_event_id", sa.String(36), sa.ForeignKey("guard_permission_events.id", ondelete="CASCADE"), nullable=False), sa.Column("state_version", sa.Integer(), nullable=False), sa.Column("source_revision", sa.Integer(), nullable=False), sa.Column("decision", sa.String(20), nullable=False), sa.Column("reason", sa.String(255), nullable=False), sa.Column("grant_keys_json", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("effective_access_id", "state_version"))
    for column in ("organization_id", "effective_access_id", "permission_event_id"):
        op.create_index(f"ix_guard_permission_snapshots_{column}", "guard_permission_snapshots", [column])
    op.create_table("guard_policy_distributions", sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False), sa.Column("policy_id", sa.String(36), sa.ForeignKey("guard_policies.id", ondelete="CASCADE"), nullable=False), sa.Column("guard_id", sa.String(36), sa.ForeignKey("guard_registrations.id", ondelete="CASCADE")), sa.Column("status", sa.String(30), nullable=False), sa.Column("attempts", sa.Integer(), nullable=False), sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_error", sa.String(500)), sa.Column("delivered_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("policy_id", "guard_id"))
    for column in ("organization_id", "policy_id", "guard_id", "status", "next_attempt_at"):
        op.create_index(f"ix_guard_policy_distributions_{column}", "guard_policy_distributions", [column])


def downgrade() -> None:
    op.drop_table("guard_policy_distributions")
    op.drop_table("guard_permission_snapshots")
    op.drop_table("guard_permission_grants")
    op.drop_table("guard_group_memberships")
    op.drop_table("guard_groups")
    op.drop_table("guard_policy_sequences")
    op.drop_index("ix_guard_policies_source_id", table_name="guard_policies")
    for column in ("supersedes_policy_id", "effective_state_version", "source_revision", "scope", "source_id"):
        op.drop_column("guard_policies", column)
    op.drop_index("ix_guard_permission_events_policy_id", table_name="guard_permission_events")
    for column in ("policy_id", "completed_at", "error_code", "mutation_json"):
        op.drop_column("guard_permission_events", column)
