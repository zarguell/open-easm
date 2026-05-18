"""add asset change events ledger

Revision ID: 20260518_0002
Revises: 0006
Create Date: 2026-05-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260518_0002"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_change_events",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("org_id", sa.Text(), nullable=False, server_default="default"),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("change_type", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column(
            "before_state",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "after_state",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "evidence",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("idx_asset_change_events_org_id", "asset_change_events", ["org_id"])
    op.create_index(
        "idx_asset_change_events_org_target",
        "asset_change_events",
        ["org_id", "target_id"],
    )
    op.create_index("idx_asset_change_events_target_id", "asset_change_events", ["target_id"])
    op.create_index("idx_asset_change_events_entity_id", "asset_change_events", ["entity_id"])
    op.create_index("idx_asset_change_events_change_type", "asset_change_events", ["change_type"])
    op.create_index("idx_asset_change_events_observed_at", "asset_change_events", ["observed_at"])


def downgrade() -> None:
    op.drop_table("asset_change_events")
