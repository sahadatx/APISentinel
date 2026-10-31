"""Record authorization document fingerprint without retaining uploaded files."""
import sqlalchemy as sa
from alembic import op

revision = "0015_authorization_evidence_fingerprint"
down_revision = "0014_mfa_recovery_codes"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("assessments", sa.Column("authorization_evidence_sha256", sa.String(64), nullable=False, server_default=""))
    op.add_column("assessments", sa.Column("authorization_evidence_name", sa.String(200), nullable=False, server_default=""))
    op.add_column("assessments", sa.Column("authorization_evidence_size", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    count = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM assessments WHERE authorization_evidence_sha256 != ''"
    )).scalar_one()
    if count:
        raise RuntimeError("Refusing downgrade while authorization evidence fingerprints exist")
    op.drop_column("assessments", "authorization_evidence_size")
    op.drop_column("assessments", "authorization_evidence_name")
    op.drop_column("assessments", "authorization_evidence_sha256")
