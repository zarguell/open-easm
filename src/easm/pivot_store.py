from __future__ import annotations

import uuid
from typing import Any

import asyncpg


async def enqueue_pivot_job(
    pool: asyncpg.Pool,
    org_id: str,
    target_id: str,
    entity_type: str,
    entity_value: str,
    entity_id: uuid.UUID,
    pivot_type: str,
    depth: int,
    parent_entity_id: uuid.UUID | None = None,
    discovery_session_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
) -> uuid.UUID:
    row = await pool.fetchrow("""
        INSERT INTO pivot_queue (org_id, target_id, entity_type, entity_value, entity_id,
                                  pivot_type, depth, parent_entity_id, discovery_session_id, run_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id
    """, org_id, target_id, entity_type, entity_value, entity_id,
        pivot_type, depth, parent_entity_id, discovery_session_id, run_id)
    return row["id"]


async def dequeue_pivot_job(pool: asyncpg.Pool) -> dict[str, Any] | None:
    row = await pool.fetchrow("""
        SELECT * FROM pivot_queue
        WHERE status = 'pending'
        ORDER BY enqueued_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    """)
    if not row:
        return None
    await pool.execute(
        "UPDATE pivot_queue SET status='running', started_at=NOW() WHERE id=$1", row["id"],
    )
    return dict(row)


async def mark_pivot_completed(pool: asyncpg.Pool, job_id: uuid.UUID) -> None:
    await pool.execute(
        "UPDATE pivot_queue SET status='completed', completed_at=NOW() WHERE id=$1", job_id,
    )


async def mark_pivot_failed(pool: asyncpg.Pool, job_id: uuid.UUID, error: str) -> None:
    await pool.execute(
        "UPDATE pivot_queue SET status='failed', completed_at=NOW(), error_message=$2 WHERE id=$1",
        job_id, error,
    )


async def reset_orphaned_pivot_jobs(pool: asyncpg.Pool) -> None:
    await pool.execute(
        "UPDATE pivot_queue SET status='pending' WHERE status='running'",
    )
