"""Run lifecycle persistence (``runs`` table)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

import asyncpg

from easm._compat import uuid7
from easm.stores import BaseStore


def _row_to_run_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    return {
        "id": str(row["id"]),
        "target_id": row["target_id"],
        "source": row["source"],
        "trigger_type": row["trigger_type"],
        "status": row["status"],
        "scheduled_for": _fmt(row["scheduled_for"]),
        "started_at": _fmt(row["started_at"]),
        "finished_at": _fmt(row["finished_at"]),
        "duration_ms": row["duration_ms"],
        "inserted_count": row["inserted_count"],
        "deduped_count": row["deduped_count"],
        "error_count": row["error_count"],
        "error_message": row["error_message"],
        "discovery_session_id": (
            str(row["discovery_session_id"]) if row["discovery_session_id"] else None
        ),
        "new_entity_count": row["new_entity_count"],
        "total_entity_count": row["total_entity_count"],
        "metadata": (
            json.loads(row["metadata"])
            if isinstance(row["metadata"], str)
            else row["metadata"]
        ),
        "logs": row["logs"],
    }


class RunStore(BaseStore):
    """Persistence for discovery/scheduler runs and their lifecycle counters."""

    async def create_run(
        self,
        target_id: str,
        source: str,
        trigger_type: str,
        scheduled_for: datetime | None = None,
        org_id: str = "default",
    ) -> uuid.UUID:
        discovery_session_id = uuid7()
        row = await self._pool.fetchrow(
            """
            INSERT INTO runs (org_id, target_id, source, trigger_type, status,
                              scheduled_for, discovery_session_id)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            RETURNING id
            """,
            org_id, target_id, source, trigger_type, scheduled_for, discovery_session_id,
        )
        assert row is not None
        return row["id"]

    async def mark_run_started(self, run_id: uuid.UUID, started_at: datetime) -> None:
        await self._pool.execute(
            "UPDATE runs SET status = 'running', started_at = $1 WHERE id = $2",
            started_at, run_id,
        )

    async def mark_run_finished(
        self,
        run_id: uuid.UUID,
        status: str,
        finished_at: datetime,
        duration_ms: int,
        inserted_count: int,
        deduped_count: int,
        error_count: int,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
        logs: str | None = None,
    ) -> None:
        meta = json.dumps(metadata or {})
        await self._pool.execute(
            """
            UPDATE runs
            SET status = $1,
                finished_at = $2,
                duration_ms = $3,
                inserted_count = $4,
                deduped_count = $5,
                error_count = $6,
                error_message = $7,
                metadata = $8::jsonb,
                logs = $9
            WHERE id = $10
            """,
            status, finished_at, duration_ms, inserted_count, deduped_count,
            error_count, error_message, meta, logs, run_id,
        )

    async def count_active_runs(self, target_id: str, source_name: str) -> int:
        """Count runs that are still in progress for a given target and source."""
        return await self._pool.fetchval(
            """
            SELECT COUNT(*) FROM runs
            WHERE target_id = $1 AND source = $2 AND status = 'running'
            """,
            target_id, source_name,
        ) or 0

    async def list_runs(
        self,
        org_id: str = "default",
        target_id: str | None = None,
        source: str | None = None,
        status: str | None = None,
        trigger_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = ["org_id = $1"]
        params: list[Any] = [org_id]
        idx = 1

        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if trigger_type:
            idx += 1
            conditions.append(f"trigger_type = ${idx}")
            params.append(trigger_type)
        if start:
            idx += 1
            conditions.append(f"started_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"started_at <= ${idx}")
            params.append(end)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        idx += 1
        query = f"""
            SELECT id, target_id, source, trigger_type, status, scheduled_for,
                   started_at, finished_at, duration_ms, inserted_count,
                   deduped_count, error_count, error_message, metadata,
                   discovery_session_id, new_entity_count, total_entity_count, logs
            FROM runs
            {where}
            ORDER BY started_at DESC NULLS LAST
            LIMIT ${idx - 1} OFFSET ${idx}
        """
        params.extend([limit, offset])
        rows = await self._pool.fetch(query, *params)
        return [_row_to_run_dict(r) for r in rows]

    async def get_run(self, run_id: uuid.UUID) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            """
            SELECT id, target_id, source, trigger_type, status, scheduled_for,
                   started_at, finished_at, duration_ms, inserted_count,
                   deduped_count, error_count, error_message, metadata,
                   discovery_session_id, new_entity_count, total_entity_count, logs
            FROM runs WHERE id = $1
            """,
            run_id,
        )
        if row is None:
            return None
        return _row_to_run_dict(row)

    async def count_runs(
        self,
        target_id: str | None = None,
        source: str | None = None,
        status: str | None = None,
        trigger_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if trigger_type:
            idx += 1
            conditions.append(f"trigger_type = ${idx}")
            params.append(trigger_type)
        if start:
            idx += 1
            conditions.append(f"started_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"started_at <= ${idx}")
            params.append(end)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self._pool.fetchval(
            f"SELECT COUNT(*) FROM runs {where}", *params,
        ) or 0
