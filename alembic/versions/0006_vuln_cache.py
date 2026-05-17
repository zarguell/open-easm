"""add cve_cache table for local NVD/KEV caching

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-17

"""
from typing import Sequence, Union

from alembic import op


revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id          TEXT PRIMARY KEY,
            description     TEXT,
            cvss_score      REAL,
            cvss_severity   TEXT,
            cpe_matches     JSONB DEFAULT '[]'::jsonb,
            kev_included    BOOLEAN DEFAULT FALSE,
            kev_date_added  DATE,
            kev_due_date    DATE,
            kev_vendor      TEXT,
            kev_product     TEXT,
            kev_notes       TEXT,
            last_refreshed  TIMESTAMPTZ DEFAULT now()
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_cve_cache_kev ON cve_cache(kev_included)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_cve_cache_severity ON cve_cache(cvss_severity)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS cve_cache;")
