"""Persist registered security test identity, separate outcomes, and finding references."""
import sqlalchemy as sa
from alembic import op

revision = "0006_test_registry_outcomes"
down_revision = "0005_openapi_inventory_review"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("test_runs") as batch_op:
        batch_op.add_column(sa.Column("test_id", sa.String(120), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("test_version", sa.String(40), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("security_outcome", sa.String(40), nullable=False, server_default="NOT_RUN"))
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("endpoint_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("test_run_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_findings_endpoint_id_endpoints", "endpoints", ["endpoint_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_findings_test_run_id_test_runs", "test_runs", ["test_run_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_findings_endpoint_id", "findings", ["endpoint_id"])
    op.create_index("ix_findings_test_run_id", "findings", ["test_run_id"])


def downgrade():
    op.drop_index("ix_findings_test_run_id", table_name="findings")
    op.drop_index("ix_findings_endpoint_id", table_name="findings")
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_constraint("fk_findings_test_run_id_test_runs", type_="foreignkey")
        batch_op.drop_constraint("fk_findings_endpoint_id_endpoints", type_="foreignkey")
        batch_op.drop_column("test_run_id")
        batch_op.drop_column("endpoint_id")
    with op.batch_alter_table("test_runs") as batch_op:
        batch_op.drop_column("security_outcome")
        batch_op.drop_column("test_version")
        batch_op.drop_column("test_id")
