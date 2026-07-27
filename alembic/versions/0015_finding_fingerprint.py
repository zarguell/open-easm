"""add fingerprint column to findings for deduplication

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-21

Adds a deterministic ``fingerprint`` column (sha256 hex, 64 chars) to the
``findings`` table so that ``INSERT ... ON CONFLICT (fingerprint)`` can
deduplicate identical findings across pivot cycles instead of re-inserting
them. A partial unique index is used so existing NULL rows (and any future
rows that fail to compute a fingerprint) do not collide.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE findings "
        "ADD COLUMN IF NOT EXISTS fingerprint CHAR(64)"
    )
    # Unique constraint for ON CONFLICT (fingerprint) target. Plain UNIQUE
    # allows multiple NULLs in PostgreSQL, so pre-migration rows are safe.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_fingerprint "
        "ON findings (fingerprint)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_findings_fingerprint")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint")
