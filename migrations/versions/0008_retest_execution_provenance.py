"""Add nullable execution provenance to retest records.

Existing retests intentionally remain unlinked: the migration cannot infer
which execution, if any, supported a historical decision.
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_retest_execution_provenance"
down_revision = "0007_finding_triage_audit"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("retests") as batch_op:
        batch_op.add_column(sa.Column("assessment_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("test_run_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("endpoint_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("analyst_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("test_id", sa.String(length=120), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("test_version", sa.String(length=40), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("endpoint_definition_hash", sa.String(length=64), nullable=False, server_default=""))
        batch_op.create_foreign_key("fk_retests_assessment_id_assessments", "assessments", ["assessment_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_retests_test_run_id_test_runs", "test_runs", ["test_run_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_retests_endpoint_id_endpoints", "endpoints", ["endpoint_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_retests_analyst_id_analysts", "analysts", ["analyst_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_retests_assessment_id", "retests", ["assessment_id"])
    op.create_index("uq_retests_test_run_id", "retests", ["test_run_id"], unique=True)


def downgrade():
    op.drop_index("uq_retests_test_run_id", table_name="retests")
    op.drop_index("ix_retests_assessment_id", table_name="retests")
    with op.batch_alter_table("retests") as batch_op:
        batch_op.drop_constraint("fk_retests_analyst_id_analysts", type_="foreignkey")
        batch_op.drop_constraint("fk_retests_endpoint_id_endpoints", type_="foreignkey")
        batch_op.drop_constraint("fk_retests_test_run_id_test_runs", type_="foreignkey")
        batch_op.drop_constraint("fk_retests_assessment_id_assessments", type_="foreignkey")
        batch_op.drop_column("endpoint_definition_hash")
        batch_op.drop_column("test_version")
        batch_op.drop_column("test_id")
        batch_op.drop_column("analyst_id")
        batch_op.drop_column("endpoint_id")
        batch_op.drop_column("test_run_id")
        batch_op.drop_column("assessment_id")
