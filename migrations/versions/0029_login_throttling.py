"""Persist short-lived login throttling state per analyst account."""
import sqlalchemy as sa
from alembic import op

revision = "0029_login_throttling"
down_revision = "0028_ios_ipa_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analysts", sa.Column("login_failure_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("analysts", sa.Column("login_failure_window_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("analysts", sa.Column("login_locked_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("analysts", "login_locked_until")
    op.drop_column("analysts", "login_failure_window_started_at")
    op.drop_column("analysts", "login_failure_count")
