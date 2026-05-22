"""Install procrastinate schema and custom indexes

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-19

"""
from __future__ import annotations

from alembic import op


revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    import os
    import pathlib

    import procrastinate

    schema_path = (
        pathlib.Path(procrastinate.__file__).parent / "sql" / "schema.sql"
    )
    schema_sql = schema_path.read_text()

    # asyncpg (used by Alembic's async env.py) cannot execute multi-statement
    # strings, so we bypass it and use psycopg directly for schema setup.
    dsn = (
        os.environ.get("EASM_TEST_DATABASE_DSN")
        or os.environ.get("EASM_DATABASE_DSN")
        or ""
    )

    import psycopg

    with psycopg.connect(dsn) as conn:
        try:
            conn.execute(schema_sql)
        except psycopg.errors.DuplicateObject:
            # Schema already exists from a previous run
            pass

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_pivot_jobs_cooldown
            ON procrastinate_jobs (
                (args->>'org_id'),
                (args->>'entity_type'),
                (args->>'entity_value'),
                (args->>'pivot_type')
            ) WHERE task_name = 'easm.tasks.pivot.execute_pivot'
              AND status IN ('succeeded', 'doing');
        """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pivot_jobs_cooldown")
    for table in (
        "procrastinate_events",
        "procrastinate_jobs",
        "procrastinate_periodic_defers",
        "procrastinate_version",
        "procrastinate_workers",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP TYPE IF EXISTS procrastinate_job_status")
    op.execute("DROP TYPE IF EXISTS procrastinate_job_event_type")
