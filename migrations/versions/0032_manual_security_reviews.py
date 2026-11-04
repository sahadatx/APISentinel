"""Add persisted, version-pinned manual security review records."""
import sqlalchemy as sa
from alembic import op

revision = "0032_manual_security_reviews"
down_revision = "0031_test_identity_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "manual_security_reviews",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework_id", sa.String(40), nullable=False),
        sa.Column("control_id", sa.String(40), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="NOT_REVIEWED"),
        sa.Column("review_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("linked_finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewed_by_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint("assessment_id", "framework_id", "control_id",
                            name="uq_manual_review_assessment_control"),
        sa.CheckConstraint("status IN ('NOT_REVIEWED', 'NO_ISSUE_OBSERVED', 'ISSUE_FOUND', 'NOT_APPLICABLE', 'BLOCKED')",
                           name="ck_manual_security_review_status"),
    )
    op.create_index("ix_manual_security_reviews_assessment_id", "manual_security_reviews", ["assessment_id"])
    op.create_index("ix_manual_security_reviews_linked_finding_id", "manual_security_reviews", ["linked_finding_id"])


def downgrade() -> None:
    op.drop_index("ix_manual_security_reviews_linked_finding_id", table_name="manual_security_reviews")
    op.drop_index("ix_manual_security_reviews_assessment_id", table_name="manual_security_reviews")
    op.drop_table("manual_security_reviews")
