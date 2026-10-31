"""Add owner-managed client memberships and bounded workspace roles."""
import sqlalchemy as sa
from alembic import op

revision = "0013_client_memberships"
down_revision = "0012_analyst_totp_mfa"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "client_memberships",
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("granted_by_id", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('viewer', 'analyst', 'reviewer')", name="ck_client_membership_role"),
    )
    op.create_index("ix_client_memberships_analyst_id", "client_memberships", ["analyst_id"])


def downgrade():
    bind = op.get_bind()
    memberships = bind.execute(sa.text("SELECT COUNT(*) FROM client_memberships")).scalar_one()
    if memberships:
        raise RuntimeError("Refusing downgrade while client memberships exist")
    op.drop_index("ix_client_memberships_analyst_id", table_name="client_memberships")
    op.drop_table("client_memberships")
