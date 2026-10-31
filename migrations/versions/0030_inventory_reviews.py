"""Persist passive API inventory review snapshots."""
import sqlalchemy as sa
from alembic import op

revision = "0030_inventory_reviews"
down_revision = "0029_login_throttling"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "inventory_reviews",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("inventory_digest", sa.String(64), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_inventory_reviews_assessment_id", "inventory_reviews", ["assessment_id"])
    op.create_index("ix_inventory_reviews_inventory_digest", "inventory_reviews", ["inventory_digest"])
    op.create_index("ix_inventory_reviews_created_at", "inventory_reviews", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_inventory_reviews_created_at", table_name="inventory_reviews")
    op.drop_index("ix_inventory_reviews_inventory_digest", table_name="inventory_reviews")
    op.drop_index("ix_inventory_reviews_assessment_id", table_name="inventory_reviews")
    op.drop_table("inventory_reviews")
