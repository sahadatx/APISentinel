"""Add OpenAPI import provenance and reviewed endpoint inventory state."""
import sqlalchemy as sa
from alembic import op

revision = "0005_openapi_inventory_review"
down_revision = "0004_http_execution_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "openapi_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("imported_by", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source", sa.String(200), nullable=False, server_default="inline_json"),
        sa.Column("openapi_version", sa.String(40), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("server_declarations", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("issues", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("endpoint_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("change_summary", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_openapi_documents_assessment_id", "openapi_documents", ["assessment_id"])
    op.create_index("ix_openapi_documents_imported_by", "openapi_documents", ["imported_by"])
    op.create_index("ix_openapi_documents_content_hash", "openapi_documents", ["content_hash"])

    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.add_column(sa.Column("import_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("definition_hash", sa.String(64), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("inventory_current", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column("review_state", sa.String(30), nullable=False, server_default="NEEDS_REVIEW"))
        batch_op.add_column(sa.Column("review_reason", sa.Text(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("request_body", sa.JSON(), nullable=False, server_default="{}"))
        batch_op.add_column(sa.Column("security_requirements", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("server_base_path", sa.String(1000), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("server_review_issues", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.create_foreign_key("fk_endpoints_import_id_openapi_documents", "openapi_documents", ["import_id"], ["id"], ondelete="SET NULL")
    for column in ("import_id", "definition_hash", "inventory_current", "review_state"):
        op.create_index(f"ix_endpoints_{column}", "endpoints", [column])


def downgrade():
    for column in ("review_state", "inventory_current", "definition_hash", "import_id"):
        op.drop_index(f"ix_endpoints_{column}", table_name="endpoints")
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.drop_constraint("fk_endpoints_import_id_openapi_documents", type_="foreignkey")
        for column in ("server_review_issues", "server_base_path", "security_requirements", "request_body", "tags", "review_reason", "review_state", "inventory_current", "definition_hash", "import_id"):
            batch_op.drop_column(column)
    for index in ("ix_openapi_documents_content_hash", "ix_openapi_documents_imported_by", "ix_openapi_documents_assessment_id"):
        op.drop_index(index, table_name="openapi_documents")
    op.drop_table("openapi_documents")
