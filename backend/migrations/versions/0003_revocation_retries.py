"""Durable account revocation intent."""
from alembic import op
import sqlalchemy as sa
revision="0003"
down_revision="0002"
branch_labels=None
depends_on=None
def upgrade():
    op.add_column("users", sa.Column("sessions_revocation_pending", sa.Boolean(), nullable=False, server_default=sa.false()))
def downgrade(): raise RuntimeError("Restore a verified backup instead")
