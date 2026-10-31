"""Add encrypted TOTP enrollment to analyst accounts."""
import sqlalchemy as sa
from alembic import op

revision = "0012_analyst_totp_mfa"
down_revision = "0011_encrypted_credentials_shared_limits"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("analysts", sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True))
    op.add_column("analysts", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("analysts", sa.Column("mfa_last_counter", sa.Integer(), nullable=True))


def downgrade():
    bind = op.get_bind()
    enrolled = bind.execute(sa.text("SELECT COUNT(*) FROM analysts WHERE mfa_secret_encrypted IS NOT NULL OR mfa_enabled = 1")).scalar_one()
    if enrolled:
        raise RuntimeError("Refusing downgrade while analyst MFA enrollment data exists")
    op.drop_column("analysts", "mfa_enabled")
    op.drop_column("analysts", "mfa_last_counter")
    op.drop_column("analysts", "mfa_secret_encrypted")
