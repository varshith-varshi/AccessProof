"""OIDC SSO configuration and login identity state

Revision ID: 0f4e8a2d1c77
Revises: ba54d7f90c13
Create Date: 2026-09-30 19:20:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0f4e8a2d1c77"
down_revision = "ba54d7f90c13"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "sessions",
        sa.Column("auth_method", sa.String(length=20), nullable=False, server_default="password"),
    )
    op.add_column(
        "sessions", sa.Column("auth_organization_id", sa.String(length=36), nullable=True)
    )
    op.create_index("ix_sessions_auth_organization_id", "sessions", ["auth_organization_id"])
    op.create_table(
        "oidc_configurations",
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("issuer_url", sa.String(length=1000), nullable=False),
        sa.Column("client_id", sa.String(length=500), nullable=False),
        sa.Column("encrypted_client_secret", sa.Text(), nullable=False),
        sa.Column("allowed_domains_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("email_claim", sa.String(length=100), nullable=False, server_default="email"),
        sa.Column("subject_claim", sa.String(length=100), nullable=False, server_default="sub"),
        sa.Column("role_claim", sa.String(length=100), nullable=True),
        sa.Column("role_mapping_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("default_role", sa.String(length=20), nullable=False, server_default="VIEWER"),
        sa.Column("enforced", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("discovery_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "oidc_login_states",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("state_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("encrypted_nonce", sa.Text(), nullable=False),
        sa.Column("encrypted_code_verifier", sa.Text(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=1000), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_oidc_login_states_organization_id", "oidc_login_states", ["organization_id"]
    )
    op.create_index(
        "ix_oidc_login_states_state_hash", "oidc_login_states", ["state_hash"], unique=True
    )
    op.create_index("ix_oidc_login_states_expires_at", "oidc_login_states", ["expires_at"])
    op.create_table(
        "oidc_identities",
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
        sa.Column("issuer", sa.String(length=1000), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id", "issuer", "subject", name="uq_oidc_identity_subject"
        ),
    )
    op.create_index("ix_oidc_identities_organization_id", "oidc_identities", ["organization_id"])
    op.create_index("ix_oidc_identities_user_id", "oidc_identities", ["user_id"])
    op.create_index("ix_oidc_identities_issuer", "oidc_identities", ["issuer"])
    op.create_index("ix_oidc_identities_subject", "oidc_identities", ["subject"])


def downgrade():
    op.drop_table("oidc_identities")
    op.drop_table("oidc_login_states")
    op.drop_table("oidc_configurations")
    op.drop_index("ix_sessions_auth_organization_id", table_name="sessions")
    op.drop_column("sessions", "auth_organization_id")
    op.drop_column("sessions", "auth_method")
