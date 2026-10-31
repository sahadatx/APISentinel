"""Add finding triage concurrency and link audit events to findings."""
import sqlalchemy as sa
from alembic import op

revision = "0007_finding_triage_audit"
down_revision = "0006_test_registry_outcomes"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("triage_version", sa.Integer(), nullable=False, server_default="1"))
    with op.batch_alter_table("execution_audit_events") as batch_op:
        batch_op.add_column(sa.Column("finding_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_execution_audit_events_finding_id_findings", "findings", ["finding_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_execution_audit_events_finding_id", "execution_audit_events", ["finding_id"])


def downgrade():
    op.drop_index("ix_execution_audit_events_finding_id", table_name="execution_audit_events")
    with op.batch_alter_table("execution_audit_events") as batch_op:
        batch_op.drop_constraint("fk_execution_audit_events_finding_id_findings", type_="foreignkey")
        batch_op.drop_column("finding_id")
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("triage_version")
