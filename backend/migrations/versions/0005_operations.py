"""Shared worker readiness and cross-process rate limits."""
from alembic import op
import sqlalchemy as sa
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("worker_state", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("status", sa.String(40), nullable=False), sa.Column("heartbeat", sa.DateTime()),
        sa.Column("lease_until", sa.DateTime()), sa.Column("owner", sa.String(36)))
    op.execute("INSERT INTO worker_state (id, status) VALUES (1, 'STARTING')")
    op.create_table("rate_buckets", sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("timestamps_json", sa.Text(), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False))
    op.create_index("ix_rate_buckets_updated_at", "rate_buckets", ["updated_at"])


def downgrade():
    raise RuntimeError("Restore a verified backup instead of destructive downgrade")
