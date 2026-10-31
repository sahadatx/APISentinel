"""Associate test runs with an endpoint for accurate coverage."""
import sqlalchemy as sa
from alembic import op

revision = "0002_test_run_endpoint"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("test_runs") as batch_op:
        batch_op.add_column(sa.Column("endpoint_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_test_runs_endpoint_id_endpoints",
            "endpoints",
            ["endpoint_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_index("ix_test_runs_endpoint_id", "test_runs", ["endpoint_id"])


def downgrade():
    op.drop_index("ix_test_runs_endpoint_id", table_name="test_runs")
    with op.batch_alter_table("test_runs") as batch_op:
        batch_op.drop_constraint("fk_test_runs_endpoint_id_endpoints", type_="foreignkey")
        batch_op.drop_column("endpoint_id")
