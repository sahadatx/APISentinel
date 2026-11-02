"""Add encrypted bearer profiles and database-coordinated execution reservations."""
import sqlalchemy as sa
from alembic import op

revision = "0011_encrypted_credentials_shared_limits"
down_revision = "0010_assessment_platforms_android_metadata"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "credential_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("auth_type", sa.String(30), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_credential_profiles_assessment_id", "credential_profiles", ["assessment_id"], unique=True)
    op.create_table(
        "execution_limiter_states",
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("touched_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "execution_reservations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_execution_reservations_assessment_id", "execution_reservations", ["assessment_id"])
    op.create_index("ix_execution_reservations_requested_at", "execution_reservations", ["requested_at"])
    op.create_index("ix_execution_reservations_expires_at", "execution_reservations", ["expires_at"])


def downgrade():
    bind = op.get_bind()
    credentials = bind.execute(sa.text("SELECT COUNT(*) FROM credential_profiles")).scalar_one()
    reservations = bind.execute(sa.text("SELECT COUNT(*) FROM execution_reservations")).scalar_one()
    if credentials or reservations:
        raise RuntimeError("Refusing downgrade while credential or execution reservation data exists")
    op.drop_index("ix_execution_reservations_expires_at", table_name="execution_reservations")
    op.drop_index("ix_execution_reservations_requested_at", table_name="execution_reservations")
    op.drop_index("ix_execution_reservations_assessment_id", table_name="execution_reservations")
    op.drop_table("execution_reservations")
    op.drop_table("execution_limiter_states")
    op.drop_index("ix_credential_profiles_assessment_id", table_name="credential_profiles")
    op.drop_table("credential_profiles")
