"""Persist explicit endpoint approval and bounded HTTP execution records."""
import sqlalchemy as sa
from alembic import op

revision = "0004_http_execution_audit"
down_revision = "0003_analyst_sessions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "uq_test_runs_running_endpoint", "test_runs", ["assessment_id", "endpoint_id"],
        unique=True,
        sqlite_where=sa.text("status = 'RUNNING' AND endpoint_id IS NOT NULL"),
        postgresql_where=sa.text("status = 'RUNNING' AND endpoint_id IS NOT NULL"),
    )
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.add_column(sa.Column("execution_approved", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("execution_approved_by", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("execution_approved_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_foreign_key("fk_endpoints_execution_approved_by_analysts", "analysts", ["execution_approved_by"], ["id"], ondelete="SET NULL")

    with op.batch_alter_table("test_runs") as batch_op:
        batch_op.add_column(sa.Column("analyst_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("execution_mode", sa.String(40), nullable=False, server_default="LEGACY"))
        batch_op.add_column(sa.Column("method", sa.String(12), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("execution_metadata", sa.JSON(), nullable=False, server_default="{}"))
        batch_op.create_foreign_key("fk_test_runs_analyst_id_analysts", "analysts", ["analyst_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_test_runs_analyst_id", "test_runs", ["analyst_id"])

    op.create_table(
        "execution_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("clients.id", ondelete="SET NULL"), nullable=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("test_run_id", sa.Integer(), sa.ForeignKey("test_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("outcome", sa.String(40), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("actor_id", "client_id", "assessment_id", "test_run_id", "created_at"):
        op.create_index(f"ix_execution_audit_events_{column}", "execution_audit_events", [column])


def downgrade():
    for column in ("created_at", "test_run_id", "assessment_id", "client_id", "actor_id"):
        op.drop_index(f"ix_execution_audit_events_{column}", table_name="execution_audit_events")
    op.drop_table("execution_audit_events")
    op.drop_index("uq_test_runs_running_endpoint", table_name="test_runs")
    op.drop_index("ix_test_runs_analyst_id", table_name="test_runs")
    with op.batch_alter_table("test_runs") as batch_op:
        batch_op.drop_constraint("fk_test_runs_analyst_id_analysts", type_="foreignkey")
        for column in ("execution_metadata", "completed_at", "started_at", "method", "execution_mode", "analyst_id"):
            batch_op.drop_column(column)
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.drop_constraint("fk_endpoints_execution_approved_by_analysts", type_="foreignkey")
        for column in ("execution_approved_at", "execution_approved_by", "execution_approved"):
            batch_op.drop_column(column)
