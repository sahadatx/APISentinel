"""Retain source import provenance on normalized endpoints."""
import sqlalchemy as sa
from alembic import op

revision = "0016_discovery_provenance"
down_revision = "0015_authorization_evidence_fingerprint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("source_provenance", sa.JSON(), nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("endpoints", "source_provenance")
