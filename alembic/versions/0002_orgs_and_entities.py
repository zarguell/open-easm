"""add organizations, entities, relationships

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.execute("INSERT INTO organizations (id, name) VALUES ('default', 'Default Organization')")

    op.add_column("raw_events", sa.Column("org_id", sa.Text(), nullable=False, server_default="default"))
    op.add_column("raw_events", sa.Column("parsed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("raw_events", sa.Column("parsed_by", sa.Text(), nullable=True))
    op.add_column("raw_events", sa.Column("parse_error", sa.Text(), nullable=True))
    op.create_index(
        "idx_raw_events_unparsed", "raw_events", ["source", "parsed_at"],
        postgresql_where=sa.text("parsed_at IS NULL"),
    )
    op.create_index("idx_raw_events_org", "raw_events", ["org_id"])

    op.add_column("runs", sa.Column("org_id", sa.Text(), nullable=False, server_default="default"))
    op.add_column("runs", sa.Column("new_entity_count", sa.Integer(), nullable=False, server_default=sa.text("0")))
    op.add_column("runs", sa.Column("total_entity_count", sa.Integer(), nullable=False, server_default=sa.text("0")))
    op.add_column("runs", sa.Column("discovery_session_id", sa.Uuid(), nullable=True))
    op.create_index("idx_runs_org", "runs", ["org_id"])

    op.create_table(
        "entities",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("attributes", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("is_first_discovery", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column("discovery_session_id", sa.Uuid(), nullable=True),
        sa.Column("discovery_run_id", sa.Uuid(), nullable=True),
        sa.Column("discovery_pivot_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["discovery_run_id"], ["runs.id"]),
        sa.UniqueConstraint("org_id", "target_id", "entity_type", "entity_value",
                            name="uq_entities_org_target_type_value"),
    )
    op.create_index("idx_entities_org", "entities", ["org_id"])
    op.create_index("idx_entities_target", "entities", ["target_id"])
    op.create_index("idx_entities_type", "entities", ["entity_type"])
    op.create_index("idx_entities_first_seen", "entities", ["first_seen_at"])
    op.create_index("idx_entities_last_seen", "entities", ["last_seen_at"])
    op.create_index("idx_entities_attrs", "entities", ["attributes"], postgresql_using="gin")

    op.create_table(
        "entity_relationships",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("source_entity_id", sa.Uuid(), nullable=False),
        sa.Column("target_entity_id", sa.Uuid(), nullable=False),
        sa.Column("relationship_type", sa.Text(), nullable=False),
        sa.Column("relationship_source", sa.Text(), nullable=False),
        sa.Column("evidence_raw_event_id", sa.Uuid(), nullable=True),
        sa.Column("runner", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["source_entity_id"], ["entities.id"]),
        sa.ForeignKeyConstraint(["target_entity_id"], ["entities.id"]),
        sa.UniqueConstraint("org_id", "source_entity_id", "target_entity_id", "relationship_type",
                            name="uq_er_org_source_target_type"),
    )
    op.create_index("idx_er_org", "entity_relationships", ["org_id"])
    op.create_index("idx_er_source", "entity_relationships", ["source_entity_id"])
    op.create_index("idx_er_target", "entity_relationships", ["target_entity_id"])
    op.create_index("idx_er_type", "entity_relationships", ["relationship_type"])

    op.create_table(
        "entity_raw_event_links",
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("raw_event_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["raw_event_id"], ["raw_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("entity_id", "raw_event_id"),
    )


def downgrade() -> None:
    op.drop_table("entity_raw_event_links")
    op.drop_table("entity_relationships")
    op.drop_table("entities")
    op.drop_index("idx_runs_org", table_name="runs")
    op.drop_column("runs", "discovery_session_id")
    op.drop_column("runs", "total_entity_count")
    op.drop_column("runs", "new_entity_count")
    op.drop_column("runs", "org_id")
    op.drop_index("idx_raw_events_unparsed", table_name="raw_events")
    op.drop_index("idx_raw_events_org", table_name="raw_events")
    op.drop_column("raw_events", "parse_error")
    op.drop_column("raw_events", "parsed_by")
    op.drop_column("raw_events", "parsed_at")
    op.drop_column("raw_events", "org_id")
    op.drop_table("organizations")
