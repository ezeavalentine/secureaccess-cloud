"""Explicit access grants, recovery codes, and durable notification delivery."""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("entitlements",
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("aws_account_id", sa.String(12), primary_key=True),
        sa.Column("iam_role", sa.String(100), primary_key=True),
        sa.Column("max_duration_minutes", sa.Integer(), nullable=False),
        sa.CheckConstraint("max_duration_minutes BETWEEN 15 AND 480", name="valid_entitlement_duration"))
    op.add_column("users", sa.Column("recovery_codes_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("users", sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("approvals", sa.Column("approver_version", sa.Integer(), nullable=False, server_default="-1"))
    op.add_column("notifications", sa.Column("email_sent", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("notifications", sa.Column("email_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("notifications", sa.Column("email_next_attempt", sa.DateTime()))


def downgrade():
    raise RuntimeError("Restore a verified backup instead of destructive downgrade")
