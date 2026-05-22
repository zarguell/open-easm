"""add users and api_keys tables

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-22

"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", sa.Text(), nullable=False, server_default="default"),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("role", sa.Text(), nullable=False, server_default="admin"),
        sa.Column("sso_provider", sa.Text(), nullable=True),
        sa.Column("sso_provider_id", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.UniqueConstraint("org_id", "username", name="uq_users_org_username"),
        sa.CheckConstraint(
            "role IN ('admin', 'viewer')",
            name="ck_users_role",
        ),
    )
    op.create_index("idx_users_org_id", "users", ["org_id"])
    op.create_index("idx_users_sso", "users", ["sso_provider", "sso_provider_id"], unique=True)

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users(id)", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False, server_default="default"),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("key_prefix", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
    )
    op.create_index("idx_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("idx_api_keys_key_hash", "api_keys", ["key_hash"])
    op.create_index(
        "idx_api_keys_expires_at",
        "api_keys",
        ["expires_at"],
        postgresql_where=sa.text("expires_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("users")
