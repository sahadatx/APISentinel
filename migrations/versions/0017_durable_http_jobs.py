"""Add idempotency and lease metadata for durable HTTP execution jobs."""
import sqlalchemy as sa
from alembic import op

revision = "0017_durable_http_jobs"
down_revision = "0016_discovery_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_runs", sa.Column("idempotency_key", sa.String(64), nullable=True))
    op.add_column("test_runs", sa.Column("worker_lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("test_runs", sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
    op.create_index(
        "uq_test_runs_idempotency", "test_runs",
        ["assessment_id", "analyst_id", "idempotency_key"], unique=True,
        sqlite_where=sa.text("idempotency_key IS NOT NULL"),
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_test_runs_idempotency", table_name="test_runs")
    op.drop_column("test_runs", "attempt_count")
    op.drop_column("test_runs", "worker_lease_expires_at")
    op.drop_column("test_runs", "idempotency_key")
