"""add legal_acceptances table

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-21

"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "legal_acceptances",
        sa.Column("token", sa.String(64), primary_key=True),
        sa.Column("terms_version", sa.String(80), nullable=False, index=True),
        sa.Column("terms_hash", sa.String(128), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("client_ip", sa.String(128), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("legal_acceptances")
