"""Initial APISentinel schema."""
import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("clients", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(200), nullable=False), sa.Column("organization", sa.String(200), nullable=False), sa.Column("contact_email", sa.String(320), nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_clients_name", "clients", ["name"])
    op.create_table("assessments", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("client_id", sa.Integer(), sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False), sa.Column("name", sa.String(200), nullable=False), sa.Column("environment", sa.String(80), nullable=False), sa.Column("status", sa.String(40), nullable=False), sa.Column("authorization_reference", sa.String(500), nullable=False), sa.Column("authorization_confirmed", sa.Boolean(), nullable=False), sa.Column("allowed_hosts", sa.JSON(), nullable=False), sa.Column("allowed_paths", sa.JSON(), nullable=False), sa.Column("excluded_paths", sa.JSON(), nullable=False), sa.Column("max_requests_per_minute", sa.Integer(), nullable=False), sa.Column("testing_window_start", sa.String(40), nullable=False), sa.Column("testing_window_end", sa.String(40), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_assessments_client_id", "assessments", ["client_id"])
    op.create_table("endpoints", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False), sa.Column("method", sa.String(12), nullable=False), sa.Column("path", sa.String(1000), nullable=False), sa.Column("summary", sa.String(500), nullable=False), sa.Column("operation_id", sa.String(200), nullable=False), sa.Column("parameters", sa.JSON(), nullable=False), sa.Column("auth_required", sa.Boolean(), nullable=False), sa.Column("source", sa.String(80), nullable=False))
    op.create_index("ix_endpoints_assessment_id", "endpoints", ["assessment_id"])
    op.create_table("test_runs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False), sa.Column("category", sa.String(80), nullable=False), sa.Column("status", sa.String(40), nullable=False), sa.Column("summary", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_test_runs_assessment_id", "test_runs", ["assessment_id"])
    op.create_table("findings", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False), sa.Column("title", sa.String(300), nullable=False), sa.Column("severity", sa.String(30), nullable=False), sa.Column("status", sa.String(40), nullable=False), sa.Column("endpoint", sa.String(1000), nullable=False), sa.Column("description", sa.Text(), nullable=False), sa.Column("impact", sa.Text(), nullable=False), sa.Column("evidence", sa.JSON(), nullable=False), sa.Column("remediation", sa.Text(), nullable=False), sa.Column("history", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_findings_assessment_id", "findings", ["assessment_id"])
    op.create_table("reports", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False), sa.Column("version", sa.Integer(), nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("format", sa.String(20), nullable=False), sa.Column("content", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_reports_assessment_id", "reports", ["assessment_id"])
    op.create_table("retests", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False), sa.Column("outcome", sa.String(40), nullable=False), sa.Column("evidence", sa.JSON(), nullable=False), sa.Column("notes", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_retests_finding_id", "retests", ["finding_id"])


def downgrade():
    for table in ["retests", "reports", "findings", "test_runs", "endpoints", "assessments", "clients"]:
        op.drop_table(table)
