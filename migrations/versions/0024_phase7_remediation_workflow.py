"""Add remediation ownership, notes and target date to canonical findings."""
import sqlalchemy as sa
from alembic import op

revision = "0024_phase7_remediation_workflow"
down_revision = "0023_phase6_finding_risk_validation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("assigned_owner_id", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("remediation_target_date", sa.Date(), nullable=True))
    op.add_column("findings", sa.Column("remediation_notes", sa.Text(), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("proposed_fix", sa.Text(), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("linked_change_reference", sa.String(500), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("remediation_reviewer_notes", sa.Text(), nullable=False, server_default=""))
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("remediation_status", type_=sa.String(40), existing_type=sa.String(24), nullable=False)
        batch.create_foreign_key("fk_findings_assigned_owner_id_analysts", "analysts",
                                 ["assigned_owner_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_findings_assigned_owner_id", "findings", ["assigned_owner_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_assigned_owner_id", table_name="findings")
    with op.batch_alter_table("findings") as batch:
        batch.drop_constraint("fk_findings_assigned_owner_id_analysts", type_="foreignkey")
        batch.alter_column("remediation_status", type_=sa.String(24), existing_type=sa.String(40), nullable=False)
    for column in ("remediation_reviewer_notes", "linked_change_reference", "proposed_fix",
                   "remediation_notes", "remediation_target_date", "assigned_owner_id"):
        op.drop_column("findings", column)
