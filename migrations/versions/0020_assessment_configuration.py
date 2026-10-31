"""Add versioned assessment description and per-platform target configuration."""
import sqlalchemy as sa
from alembic import op

revision = "0020_assessment_configuration"
down_revision = "0019_encrypted_http_request_parameters"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assessments", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("assessments", sa.Column("target_configs", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("assessments", sa.Column("configuration_version", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("assessments", sa.Column("created_by_id", sa.Integer(), nullable=True))
    op.add_column("assessments", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE assessments SET updated_at = created_at")
    with op.batch_alter_table("assessments") as batch:
        batch.alter_column("updated_at", nullable=False)
        batch.create_foreign_key("fk_assessments_created_by_id_analysts", "analysts",
                                 ["created_by_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    op.drop_column("assessments", "updated_at")
    with op.batch_alter_table("assessments") as batch:
        batch.drop_constraint("fk_assessments_created_by_id_analysts", type_="foreignkey")
    op.drop_column("assessments", "created_by_id")
    op.drop_column("assessments", "configuration_version")
    op.drop_column("assessments", "target_configs")
    op.drop_column("assessments", "description")
