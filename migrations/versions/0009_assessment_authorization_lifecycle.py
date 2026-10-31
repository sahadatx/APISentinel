"""Add an explicit, scope-bound authorization lifecycle to assessments.

Legacy confirmation fields are preserved; every existing assessment starts in
REVIEW_REQUIRED because its historic authorization cannot be independently
reconstructed from those fields.
"""
import sqlalchemy as sa
from alembic import op

revision = "0009_assessment_authorization_lifecycle"
down_revision = "0008_retest_execution_provenance"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("assessments", sa.Column("authorization_status", sa.String(30), nullable=False, server_default="REVIEW_REQUIRED"))
    op.add_column("assessments", sa.Column("authorization_scope_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("assessments", sa.Column("authorization_scope_snapshot", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    op.add_column("assessments", sa.Column("authorization_methods", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
    op.add_column("assessments", sa.Column("authorization_valid_from", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assessments", sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assessments", sa.Column("authorization_party", sa.String(200), nullable=False, server_default=""))
    op.add_column("assessments", sa.Column("authorization_recorded_by_id", sa.Integer(), nullable=True))
    op.add_column("assessments", sa.Column("authorization_recorded_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assessments", sa.Column("authorization_reviewed_by_id", sa.Integer(), nullable=True))
    op.add_column("assessments", sa.Column("authorization_reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assessments", sa.Column("authorization_revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assessments", sa.Column("authorization_reason", sa.Text(), nullable=False, server_default=""))
    op.add_column("assessments", sa.Column("authorization_version", sa.Integer(), nullable=False, server_default="1"))
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.create_foreign_key("fk_assessments_authorization_recorded_by_analysts", "analysts", ["authorization_recorded_by_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_assessments_authorization_reviewed_by_analysts", "analysts", ["authorization_reviewed_by_id"], ["id"], ondelete="SET NULL")
        for name in ("authorization_status", "authorization_scope_hash", "authorization_scope_snapshot", "authorization_methods", "authorization_party", "authorization_reason", "authorization_version"):
            batch_op.alter_column(name, server_default=None)


def downgrade():
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.drop_constraint("fk_assessments_authorization_reviewed_by_analysts", type_="foreignkey")
        batch_op.drop_constraint("fk_assessments_authorization_recorded_by_analysts", type_="foreignkey")
        for name in ("authorization_version", "authorization_reason", "authorization_revoked_at", "authorization_reviewed_at", "authorization_reviewed_by_id", "authorization_recorded_at", "authorization_recorded_by_id", "authorization_party", "authorization_expires_at", "authorization_valid_from", "authorization_methods", "authorization_scope_snapshot", "authorization_scope_hash", "authorization_status"):
            batch_op.drop_column(name)
