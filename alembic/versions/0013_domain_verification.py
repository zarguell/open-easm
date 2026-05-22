"""add verified_domains table

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-21

"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0013"
down_revision: str | Sequence[str] | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "verified_domains",
        sa.Column("domain", sa.String(255), primary_key=True),
        sa.Column("token", sa.String(255), nullable=False),
        sa.Column("status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("method", sa.String(40), nullable=False, server_default="dns_txt"),
        sa.Column("verification_name", sa.String(255), nullable=False),
        sa.Column("expected_value", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("verified_domains")
