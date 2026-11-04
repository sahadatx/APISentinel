"""Add explainable finding validation, confidence and priority fields."""
import sqlalchemy as sa
from alembic import op

revision = "0023_phase6_finding_risk_validation"
down_revision = "0022_phase4_api_title"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("vulnerability_category", sa.String(80), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("owasp_categories", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("findings", sa.Column("taxonomy_version", sa.String(100), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("validation_state", sa.String(30), nullable=False, server_default="PENDING_VALIDATION"))
    op.add_column("findings", sa.Column("validation_rationale", sa.Text(), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("remediation_status", sa.String(24), nullable=False, server_default="OPEN"))
    op.add_column("findings", sa.Column("remediation_guidance_type", sa.String(24), nullable=False, server_default="UNAVAILABLE"))
    op.add_column("findings", sa.Column("confidence", sa.String(20), nullable=False, server_default="UNASSESSED"))
    op.add_column("findings", sa.Column("confidence_rationale", sa.Text(), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("priority", sa.String(4), nullable=False, server_default="P3"))
    op.add_column("findings", sa.Column("priority_rationale", sa.Text(), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("risk_analysis", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("findings", sa.Column("correlation_key", sa.String(64), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE findings SET first_detected_at = created_at, last_observed_at = created_at")
    op.execute("UPDATE findings SET validation_state = CASE status "
               "WHEN 'Confirmed' THEN 'VALIDATED' WHEN 'False Positive' THEN 'REJECTED' "
               "WHEN 'Resolved' THEN 'VALIDATED' WHEN 'Fixed' THEN 'VALIDATED' "
               "ELSE 'PENDING_VALIDATION' END")
    op.execute("UPDATE findings SET remediation_status = CASE status "
               "WHEN 'Resolved' THEN 'RESOLVED' WHEN 'Fixed' THEN 'RESOLVED' "
               "WHEN 'Retest Required' THEN 'PENDING_RETEST' "
               "WHEN 'Remediation In Progress' THEN 'IN_PROGRESS' ELSE 'OPEN' END")
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("first_detected_at", nullable=False, server_default=sa.func.current_timestamp())
        batch.alter_column("last_observed_at", nullable=False, server_default=sa.func.current_timestamp())
    op.create_index("ix_findings_validation_state", "findings", ["validation_state"])
    op.create_index("ix_findings_confidence", "findings", ["confidence"])
    op.create_index("ix_findings_priority", "findings", ["priority"])
    op.create_index("ix_findings_correlation_key", "findings", ["assessment_id", "correlation_key"])


def downgrade() -> None:
    op.drop_index("ix_findings_correlation_key", table_name="findings")
    op.drop_index("ix_findings_priority", table_name="findings")
    op.drop_index("ix_findings_confidence", table_name="findings")
    op.drop_index("ix_findings_validation_state", table_name="findings")
    for column in ("last_observed_at", "first_detected_at", "correlation_key", "risk_analysis",
                   "priority_rationale", "priority", "confidence_rationale", "confidence",
                   "remediation_guidance_type", "remediation_status", "validation_rationale", "validation_state", "taxonomy_version",
                   "owasp_categories", "vulnerability_category"):
        op.drop_column("findings", column)
