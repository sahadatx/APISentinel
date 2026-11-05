"""Add marketplace and contact details to client workspaces."""
import sqlalchemy as sa
from alembic import op

revision = "0025_client_engagement_intake"
down_revision = "0024_phase7_remediation_workflow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("clients", sa.Column("contact_person", sa.String(200), nullable=False, server_default=""))
    op.add_column("clients", sa.Column("source", sa.String(20), nullable=False, server_default="UNKNOWN"))
    op.add_column("clients", sa.Column("source_url", sa.String(2048), nullable=False, server_default=""))
    op.add_column("clients", sa.Column("engagement_notes", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("clients", "engagement_notes")
    op.drop_column("clients", "source_url")
    op.drop_column("clients", "source")
    op.drop_column("clients", "contact_person")
