"""Store caller supplied queued request parameters encrypted at rest."""
import sqlalchemy as sa
from alembic import op

revision = "0019_encrypted_http_request_parameters"
down_revision = "0018_import_artifact_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_runs", sa.Column("encrypted_request_parameters", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("test_runs", "encrypted_request_parameters")
