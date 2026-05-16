from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "pivot_queue",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("pivot_type", sa.Text(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("parent_entity_id", sa.Uuid(), nullable=True),
        sa.Column("discovery_session_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("skip_reason", sa.Text(), nullable=True),
    )
    op.create_index("idx_pq_org", "pivot_queue", ["org_id"])
    op.create_index(
        "idx_pq_status", "pivot_queue", ["status"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "idx_pq_entity", "pivot_queue", ["org_id", "entity_type", "entity_value"]
    )
    op.create_index(
        "idx_pq_cooldown", "pivot_queue",
        ["org_id", "entity_type", "entity_value", "pivot_type", "completed_at"],
    )

    op.execute(
        "INSERT INTO organizations (id, name) "
        "SELECT DISTINCT org_id, org_id FROM raw_events WHERE org_id NOT IN (SELECT id FROM organizations)"
    )
    op.execute(
        "INSERT INTO organizations (id, name) "
        "SELECT DISTINCT org_id, org_id FROM runs WHERE org_id NOT IN (SELECT id FROM organizations)"
    )

    op.create_foreign_key(
        "fk_raw_events_org", "raw_events", "organizations",
        ["org_id"], ["id"],
    )
    op.create_foreign_key(
        "fk_runs_org", "runs", "organizations",
        ["org_id"], ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_runs_org", "runs", type_="foreignkey")
    op.drop_constraint("fk_raw_events_org", "raw_events", type_="foreignkey")
    op.drop_index("idx_pq_cooldown", table_name="pivot_queue")
    op.drop_index("idx_pq_entity", table_name="pivot_queue")
    op.drop_index("idx_pq_status", table_name="pivot_queue")
    op.drop_index("idx_pq_org", table_name="pivot_queue")
    op.drop_table("pivot_queue")
