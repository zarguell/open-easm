"""add parent_entity_id to entities for provenance tracking

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-20

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("entities", sa.Column("parent_entity_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_entities_parent",
        "entities",
        "entities",
        ["parent_entity_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("idx_entities_parent", "entities", ["parent_entity_id"])


def downgrade() -> None:
    op.drop_index("idx_entities_parent", table_name="entities")
    op.drop_constraint("fk_entities_parent", "entities", type_="foreignkey")
    op.drop_column("entities", "parent_entity_id")
