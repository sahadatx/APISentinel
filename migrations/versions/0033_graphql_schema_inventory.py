"""Persist sanitized GraphQL introspection inventory metadata."""
import sqlalchemy as sa
from alembic import op

revision = "0033_graphql_schema_inventory"
down_revision = "0032_manual_security_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "graphql_schema_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("imported_by", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("schema_summary", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_graphql_schema_documents_assessment_id", "graphql_schema_documents", ["assessment_id"])
    op.create_index("ix_graphql_schema_documents_imported_by", "graphql_schema_documents", ["imported_by"])
    op.create_index("ix_graphql_schema_documents_content_hash", "graphql_schema_documents", ["content_hash"])


def downgrade() -> None:
    op.drop_index("ix_graphql_schema_documents_content_hash", table_name="graphql_schema_documents")
    op.drop_index("ix_graphql_schema_documents_imported_by", table_name="graphql_schema_documents")
    op.drop_index("ix_graphql_schema_documents_assessment_id", table_name="graphql_schema_documents")
    op.drop_table("graphql_schema_documents")
