"""Persist sanitized metadata from client-provided iOS IPA artifacts."""
import sqlalchemy as sa
from alembic import op

revision = "0028_ios_ipa_metadata"
down_revision = "0027_finding_evidence_attachments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ios_applications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("bundle_id", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("version_name", sa.String(100), nullable=False, server_default=""),
        sa.Column("build_number", sa.String(40), nullable=False, server_default=""),
        sa.Column("minimum_os_version", sa.String(40), nullable=False, server_default=""),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint("assessment_id", "bundle_id", name="uq_ios_app_assessment_bundle"),
    )
    op.create_index("ix_ios_applications_assessment_id", "ios_applications", ["assessment_id"])


def downgrade() -> None:
    op.drop_index("ix_ios_applications_assessment_id", table_name="ios_applications")
    op.drop_table("ios_applications")
