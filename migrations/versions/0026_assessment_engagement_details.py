"""Persist marketplace engagement, scheduling, delivery and assignment details."""
import sqlalchemy as sa
from alembic import op

revision = "0026_assessment_engagement_details"
down_revision = "0025_client_engagement_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assessments",
        sa.Column("engagement_details", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )


def downgrade() -> None:
    op.drop_column("assessments", "engagement_details")
