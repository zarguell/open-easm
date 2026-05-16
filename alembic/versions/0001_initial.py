"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "raw_events",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("raw", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("event_hash", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.UniqueConstraint("event_hash", name="uq_raw_events_event_hash"),
    )
    op.create_index("idx_raw_events_target_id", "raw_events", ["target_id"])
    op.create_index("idx_raw_events_source", "raw_events", ["source"])
    op.create_index("idx_raw_events_collected_at", "raw_events", ["collected_at"])
    op.create_index("idx_raw_events_run_id", "raw_events", ["run_id"])
    op.create_index("idx_raw_events_raw_gin", "raw_events", ["raw"], postgresql_using="gin")

    op.create_table(
        "runs",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("trigger_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("inserted_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("deduped_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("idx_runs_target_id", "runs", ["target_id"])
    op.create_index("idx_runs_source", "runs", ["source"])
    op.create_index("idx_runs_started_at", "runs", ["started_at"])
    op.create_index("idx_runs_status", "runs", ["status"])

    op.create_table(
        "config_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("config_hash", sa.Text(), nullable=False),
        sa.Column("raw_config", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("config_hash", name="uq_config_snapshots_config_hash"),
    )


def downgrade() -> None:
    op.drop_table("config_snapshots")
    op.drop_table("runs")
    op.drop_table("raw_events")
