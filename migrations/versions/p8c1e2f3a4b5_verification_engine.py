"""Durable post-install verification with tenant RLS and replay-safe Guard presence.

Revision ID: p8c1e2f3a4b5
Revises: n7a2b4c6d801
"""
from alembic import op
import sqlalchemy as sa

revision = "p8c1e2f3a4b5"
down_revision = "n7a2b4c6d801"
branch_labels = None
depends_on = None

C = sa.Column
S = sa.String
T = sa.DateTime
FK = sa.ForeignKey
TABLES = (
    "verification_runs", "verification_steps", "verification_evidence",
    "verification_events", "verification_outbox", "verification_approvals",
    "guard_presence_leases",
)


def _org() -> sa.Column:
    return C("organization_id", S(36), FK("organizations.id", ondelete="CASCADE"), nullable=False)


def _id() -> sa.Column:
    return C("id", S(36), primary_key=True)


def _run() -> sa.Column:
    return C("run_id", S(36), FK("verification_runs.id", ondelete="CASCADE"), nullable=False)


def _time(name: str, nullable: bool = False) -> sa.Column:
    return C(name, T(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table("verification_runs", _id(), _org(),
                    C("application_row_id", S(36), FK("ai_applications.id", ondelete="CASCADE"), nullable=False),
                    C("guard_id", S(36), nullable=False), C("source_id", S(36), nullable=False),
                    C("deployment_sha256", S(64), nullable=False), C("route_sha256", S(64), nullable=False),
                    C("fingerprint", S(64), nullable=False), C("state", S(48), nullable=False),
                    C("generation", sa.Integer, nullable=False), _time("next_check_at"), _time("created_at"),
                    _time("updated_at"), _time("completed_at", True), _time("superseded_at", True),
                    sa.UniqueConstraint("organization_id", "application_row_id", "fingerprint"))
    op.create_table("verification_steps", _id(), _org(), _run(),
                    C("code", S(100), nullable=False), C("state", S(40), nullable=False),
                    C("reason", S(400)), C("attempt", sa.Integer, nullable=False),
                    _time("next_retry_at", True), C("evidence_id", S(36)), _time("checked_at", True),
                    sa.UniqueConstraint("run_id", "code"))
    op.create_table("verification_evidence", _id(), _org(), _run(),
                    C("step_code", S(100), nullable=False), C("verifier", S(100), nullable=False),
                    C("evidence_digest", S(64), nullable=False), C("evidence_ref", S(200)),
                    _time("expires_at"), _time("created_at"))
    op.create_table("verification_events", _id(), _org(), _run(),
                    C("code", S(100), nullable=False), C("state", S(48), nullable=False),
                    C("detail", S(400)), _time("created_at"))
    op.create_table("verification_outbox", _id(), _org(), _run(),
                    C("generation", sa.Integer, nullable=False), C("state", S(32), nullable=False),
                    _time("available_at"), C("attempts", sa.Integer, nullable=False),
                    sa.UniqueConstraint("run_id", "generation"))
    op.create_table("verification_approvals", _id(), _org(), _run(),
                    C("approval_type", S(60), nullable=False), C("generation", sa.Integer, nullable=False),
                    C("actor_id", S(36), FK("users.id", ondelete="CASCADE"), nullable=False),
                    C("scope_digest", S(64), nullable=False), _time("approved_at"), _time("expires_at"),
                    _time("consumed_at", True), sa.UniqueConstraint("run_id", "approval_type", "generation"))
    op.create_table("guard_presence_leases",
                    C("guard_id", S(36), FK("guard_registrations.id", ondelete="CASCADE"), primary_key=True),
                    _org(), C("session_nonce", S(64), nullable=False), C("sequence", sa.BigInteger, nullable=False),
                    _time("received_at"), _time("expires_at"))
    for table in TABLES:
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])
        if table not in {"verification_runs", "guard_presence_leases"}:
            op.create_index(f"ix_{table}_run_id", table, ["run_id"])
    op.create_index("ix_verification_runs_application_row_id", "verification_runs", ["application_row_id"])
    if op.get_bind().dialect.name == "postgresql":
        predicate = ("(organization_id = current_setting('accessproof.organization_id', true) "
                     "OR current_user = 'accessproof_rls_admin')")
        for table in TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'CREATE POLICY accessproof_tenant_isolation ON "{table}" '
                       f'USING ({predicate}) WITH CHECK ({predicate})')


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)
