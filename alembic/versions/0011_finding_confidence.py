"""add confidence_score and confidence_level to findings

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-20

"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_score REAL")
    op.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_level VARCHAR(16)")


def downgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS confidence_level")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS confidence_score")
