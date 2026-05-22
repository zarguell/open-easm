"""Task queue for runner execution

Revision ID: 0007
Revises: 20260518_0002
Create Date: 2026-05-19

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: str | Sequence[str] | None = ("0006", "20260518_0002")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "task_queue",
        sa.Column(
            "id", sa.Uuid(), primary_key=True,
            server_default=sa.text("uuidv7()"),
        ),
        sa.Column("task_type", sa.Text(), nullable=False),
        sa.Column(
            "payload", sa.dialects.postgresql.JSONB(), nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "status", sa.Text(), nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "priority", sa.Integer(), nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "enqueued_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_id", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "retry_count", sa.Integer(), nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "max_retries", sa.Integer(), nullable=False,
            server_default=sa.text("3"),
        ),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column(
            "org_id", sa.Text(), nullable=False,
            server_default=sa.text("'default'"),
        ),
    )
    op.create_index("idx_task_queue_status", "task_queue", ["status"])
    op.create_index(
        "idx_task_queue_type_status", "task_queue", ["task_type", "status"],
    )
    op.create_index(
        "idx_task_queue_scheduled_for", "task_queue", ["scheduled_for"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index("idx_task_queue_target_id", "task_queue", ["target_id"])


def downgrade() -> None:
    op.drop_table("task_queue")
