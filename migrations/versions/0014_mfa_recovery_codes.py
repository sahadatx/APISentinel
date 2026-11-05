"""Store one-way hashes of single-use analyst MFA recovery codes."""
import sqlalchemy as sa
from alembic import op

revision = "0014_mfa_recovery_codes"
down_revision = "0013_client_memberships"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("analysts", sa.Column("mfa_recovery_hashes", sa.JSON(), nullable=False,
                                         server_default=sa.text("'[]'")))


def downgrade():
    bind = op.get_bind()
    enabled = bind.execute(sa.text("SELECT COUNT(*) FROM analysts WHERE mfa_enabled = 1")).scalar_one()
    if enabled:
        raise RuntimeError("Refusing downgrade while MFA is enabled")
    op.drop_column("analysts", "mfa_recovery_hashes")
