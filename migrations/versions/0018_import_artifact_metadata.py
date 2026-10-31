"""Retain safe browser and Android import attribution."""
import sqlalchemy as sa
from alembic import op

revision = "0018_import_artifact_metadata"
down_revision = "0017_durable_http_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("openapi_documents", sa.Column("artifact_metadata", sa.JSON(), nullable=False,
                                                   server_default="{}"))


def downgrade() -> None:
    op.drop_column("openapi_documents", "artifact_metadata")
