"""Add analyst identities, revocable sessions, and optional client ownership."""
import sqlalchemy as sa
from alembic import op

revision = "0003_analyst_sessions"
down_revision = "0002_test_run_endpoint"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "analysts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("login_normalized", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(500), nullable=False),
        sa.Column("role", sa.String(30), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("login_normalized", name="uq_analysts_login_normalized"),
    )
    op.add_column("clients", sa.Column("owner_user_id", sa.Integer(), nullable=True))
    with op.batch_alter_table("clients") as batch_op:
        batch_op.create_foreign_key(
            "fk_clients_owner_user_id_analysts",
            "analysts",
            ["owner_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_index("ix_clients_owner_user_id", "clients", ["owner_user_id"])
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
    )
    op.create_index("ix_auth_sessions_analyst_id", "auth_sessions", ["analyst_id"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])


def downgrade():
    op.drop_index("ix_auth_sessions_expires_at", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_analyst_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_clients_owner_user_id", table_name="clients")
    with op.batch_alter_table("clients") as batch_op:
        batch_op.drop_constraint("fk_clients_owner_user_id_analysts", type_="foreignkey")
        batch_op.drop_column("owner_user_id")
    op.drop_table("analysts")
