"""Store encrypted disposable identities for read-only authorization checks."""
import sqlalchemy as sa
from alembic import op

revision = "0031_test_identity_profiles"
down_revision = "0030_inventory_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "test_identity_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("role", sa.String(80), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint("assessment_id", "label", name="uq_test_identity_assessment_label"),
    )
    op.create_index("ix_test_identity_profiles_assessment_id", "test_identity_profiles", ["assessment_id"])


def downgrade() -> None:
    op.drop_index("ix_test_identity_profiles_assessment_id", table_name="test_identity_profiles")
    op.drop_table("test_identity_profiles")
