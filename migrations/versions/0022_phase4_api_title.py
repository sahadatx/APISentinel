"""Retain sanitized OpenAPI API title on endpoint inventory records."""
import sqlalchemy as sa
from alembic import op

revision = "0022_phase4_api_title"
down_revision = "0021_phase4_endpoint_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("api_title", sa.String(300), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("endpoints", "api_title")
