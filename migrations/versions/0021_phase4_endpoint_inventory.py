"""Add explicit Phase 4 scope and endpoint contract metadata."""
import sqlalchemy as sa
from alembic import op

revision = "0021_phase4_endpoint_inventory"
down_revision = "0020_assessment_configuration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("server_origin", sa.String(1000), nullable=False, server_default=""))
    op.add_column("endpoints", sa.Column("scope_status", sa.String(24), nullable=False, server_default="UNRESOLVED"))
    op.add_column("endpoints", sa.Column("scope_reason", sa.Text(), nullable=False, server_default="Legacy inventory requires scope revalidation"))
    op.add_column("endpoints", sa.Column("api_version", sa.String(100), nullable=False, server_default=""))
    op.add_column("endpoints", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("endpoints", sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("endpoints", sa.Column("content_types", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("endpoints", sa.Column("response_schemas", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("endpoints", sa.Column("last_discovered_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE endpoints SET last_discovered_at = CURRENT_TIMESTAMP")
    with op.batch_alter_table("endpoints") as batch:
        batch.alter_column("last_discovered_at", nullable=False)
        batch.create_index("ix_endpoints_scope_status", ["scope_status"])


def downgrade() -> None:
    with op.batch_alter_table("endpoints") as batch:
        batch.drop_index("ix_endpoints_scope_status")
    for name in ("last_discovered_at", "response_schemas", "content_types", "deprecated", "description",
                 "api_version", "scope_reason", "scope_status", "server_origin"):
        op.drop_column("endpoints", name)
