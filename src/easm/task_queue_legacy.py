"""Postgres-backed task queue using FOR UPDATE SKIP LOCKED.

Provides a reliable, Redis-free task queue built entirely on Postgres.
Workers dequeue tasks atomically via SELECT ... FOR UPDATE SKIP LOCKED,
which prevents duplicate processing across concurrent workers.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)


class TaskQueue:
    """Postgres-backed task queue."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def enqueue(
        self,
        *,
        task_type: str,
        payload: dict[str, Any],
        target_id: str | None = None,
        org_id: str = "default",
        priority: int = 0,
        scheduled_for: datetime | None = None,
        max_retries: int = 3,
    ) -> uuid.UUID:
        """Enqueue a task. Returns the task ID."""
        row = await self.pool.fetchrow(
            """
            INSERT INTO task_queue
                (task_type, payload, target_id, org_id, priority, scheduled_for, max_retries)
            VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7)
            RETURNING id
            """,
            task_type,
            json.dumps(payload),
            target_id,
            org_id,
            priority,
            scheduled_for,
            max_retries,
        )
        assert row is not None
        return row["id"]

    async def dequeue(
        self,
        *,
        worker_id: str,
        task_types: list[str] | None = None,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        """Dequeue up to `limit` pending tasks atomically.

        Uses FOR UPDATE SKIP LOCKED to prevent duplicate processing.
        Optionally filter by task_type.
        """
        type_filter = ""
        params: list[Any] = [worker_id, limit]
        idx = 2

        if task_types:
            placeholders = ", ".join(f"${idx + i + 1}" for i in range(len(task_types)))
            type_filter = f"AND task_type IN ({placeholders})"
            params.extend(task_types)
            idx += len(task_types)

        query = f"""
            WITH picked AS (
                SELECT id
                FROM task_queue
                WHERE status = 'pending'
                  AND (scheduled_for IS NULL OR scheduled_for <= NOW())
                  {type_filter}
                ORDER BY priority ASC, enqueued_at ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            UPDATE task_queue tq
            SET status = 'running',
                started_at = NOW(),
                worker_id = $1
            FROM picked
            WHERE tq.id = picked.id
            RETURNING tq.*
        """
        rows = await self.pool.fetch(query, *params)
        return [_task_to_dict(row) for row in rows]

    async def mark_completed(self, task_id: uuid.UUID) -> None:
        await self.pool.execute(
            "UPDATE task_queue SET status='completed', completed_at=NOW() WHERE id=$1",
            task_id,
        )

    async def mark_failed(
        self,
        task_id: uuid.UUID,
        error: str,
        *,
        retry: bool = True,
    ) -> None:
        if retry:
            row = await self.pool.fetchrow(
                "SELECT retry_count, max_retries FROM task_queue WHERE id=$1",
                task_id,
            )
            if row and row["retry_count"] < row["max_retries"]:
                await self.pool.execute(
                    """
                    UPDATE task_queue
                    SET status = 'pending',
                        retry_count = retry_count + 1,
                        started_at = NULL,
                        worker_id = NULL,
                        error_message = $2,
                        scheduled_for = NOW() + (interval '30 seconds' * (retry_count + 1))
                    WHERE id = $1
                    """,
                    task_id,
                    error,
                )
                return

        await self.pool.execute(
            "UPDATE task_queue SET status='failed', completed_at=NOW(), "
            "error_message=$2 WHERE id=$1",
            task_id,
            error,
        )

    async def count_tasks(
        self,
        status: str | None = None,
        task_type: str | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        if status:
            conditions.append(f"status = ${len(params) + 1}")
            params.append(status)
        if task_type:
            conditions.append(f"task_type = ${len(params) + 1}")
            params.append(task_type)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self.pool.fetchval(f"SELECT COUNT(*) FROM task_queue {where}", *params) or 0

    async def cleanup_completed(self, older_than_hours: int = 24) -> int:
        """Delete completed/failed tasks older than N hours. Returns count deleted."""
        result = await self.pool.execute(
            """
            DELETE FROM task_queue
            WHERE status IN ('completed', 'failed')
              AND completed_at < NOW() - ($1 * interval '1 hour')
            """,
            older_than_hours,
        )
        parts = result.split()
        return int(parts[1]) if len(parts) >= 2 else 0


def _task_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return {
        "id": str(row["id"]),
        "task_type": row["task_type"],
        "payload": payload or {},
        "status": row["status"],
        "priority": row["priority"],
        "enqueued_at": row["enqueued_at"].isoformat() if row["enqueued_at"] else None,
        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
        "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
        "worker_id": row["worker_id"],
        "error_message": row["error_message"],
        "retry_count": row["retry_count"],
        "max_retries": row["max_retries"],
        "scheduled_for": row["scheduled_for"].isoformat() if row["scheduled_for"] else None,
        "target_id": row["target_id"],
        "org_id": row["org_id"],
    }
