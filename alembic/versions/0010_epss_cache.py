"""add epss_score and epss_percentile columns to cve_cache

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-20

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE cve_cache ADD COLUMN IF NOT EXISTS epss_score REAL DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE cve_cache ADD COLUMN IF NOT EXISTS epss_percentile REAL DEFAULT 0"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_cve_cache_epss ON cve_cache(epss_percentile DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_cve_cache_epss")
    op.execute("ALTER TABLE cve_cache DROP COLUMN IF EXISTS epss_percentile")
    op.execute("ALTER TABLE cve_cache DROP COLUMN IF EXISTS epss_score")
