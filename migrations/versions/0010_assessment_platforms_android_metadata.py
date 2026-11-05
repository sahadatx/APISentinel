"""Add assessment platform types and sanitized Android app metadata."""
import sqlalchemy as sa
from alembic import op

revision = "0010_assessment_platforms_android_metadata"
down_revision = "0009_assessment_authorization_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("assessments", sa.Column("assessment_type", sa.String(20), nullable=False,
                                            server_default="WEB_API"))
    op.create_table(
        "android_applications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("version_name", sa.String(100), nullable=False, server_default=""),
        sa.Column("version_code", sa.String(40), nullable=False, server_default=""),
        sa.Column("artifact_sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("api_level", sa.Integer(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("assessment_id", "package_name", name="uq_android_app_assessment_package"),
    )
    op.create_index("ix_android_applications_assessment_id", "android_applications", ["assessment_id"])


def downgrade():
    bind = op.get_bind()
    app_count = bind.execute(sa.text("SELECT COUNT(*) FROM android_applications")).scalar_one()
    non_web_count = bind.execute(sa.text("SELECT COUNT(*) FROM assessments WHERE assessment_type != 'WEB_API'")).scalar_one()
    if app_count or non_web_count:
        raise RuntimeError("Refusing downgrade: Android metadata or non-WEB_API assessments would be lost")
    op.drop_index("ix_android_applications_assessment_id", table_name="android_applications")
    op.drop_table("android_applications")
    with op.batch_alter_table("assessments") as batch:
        batch.drop_column("assessment_type")
