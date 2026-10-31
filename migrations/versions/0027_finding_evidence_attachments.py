"""Add private sanitized image evidence to findings."""
import sqlalchemy as sa
from alembic import op

revision = "0027_finding_evidence_attachments"
down_revision = "0026_assessment_engagement_details"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_evidence_attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("uploaded_by_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("filename", sa.String(200), nullable=False),
        sa.Column("mime_type", sa.String(40), nullable=False),
        sa.Column("caption", sa.String(500), nullable=False, server_default=""),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("image_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("height", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_finding_evidence_finding_created", "finding_evidence_attachments", ["finding_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_finding_evidence_finding_created", table_name="finding_evidence_attachments")
    op.drop_table("finding_evidence_attachments")
