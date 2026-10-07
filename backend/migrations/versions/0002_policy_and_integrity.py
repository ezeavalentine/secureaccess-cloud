"""Editable restrictive policies and additional referential/audit protection."""
from alembic import op
import sqlalchemy as sa
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
def upgrade():
    op.create_table("role_policies", sa.Column("role_name", sa.String(100), primary_key=True), sa.Column("max_duration_minutes", sa.Integer(), nullable=False), sa.Column("base_risk", sa.Integer(), nullable=False), sa.Column("allowed_environments_json", sa.Text(), nullable=False), sa.CheckConstraint("max_duration_minutes BETWEEN 15 AND 480", name="valid_policy_duration"), sa.CheckConstraint("base_risk BETWEEN 15 AND 100", name="valid_policy_risk"))
    with op.batch_alter_table("notifications") as batch:
        batch.create_foreign_key("fk_notification_user", "users", ["user_id"], ["id"])
    with op.batch_alter_table("audit_exports") as batch:
        batch.create_foreign_key("fk_export_audit", "audit_logs", ["event_id"], ["id"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE FUNCTION deny_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Audit records are append-only'; END; $$")
        op.execute("CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION deny_audit_mutation()")
def downgrade(): raise RuntimeError("Restore a verified backup instead of destructive downgrade")
