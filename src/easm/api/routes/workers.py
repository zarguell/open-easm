from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/workers", tags=["workers"])

_STATUS_MAP = {
    "todo": "pending",
    "doing": "running",
    "succeeded": "completed",
    "failed": "failed",
}


@router.get("/queue")
async def get_queue_status(request: Request) -> dict[str, Any]:
    store = request.app.state.store
    pool = store.pool

    rows = await pool.fetch(
        "SELECT status, task_name, COUNT(*) as count "
        "FROM procrastinate_jobs "
        "GROUP BY status, task_name "
        "ORDER BY task_name, status"
    )

    by_status: dict[str, int] = {}
    by_type: dict[str, dict[str, int]] = {}
    for row in rows:
        status = _STATUS_MAP.get(row["status"], row["status"])
        task_name = row["task_name"]
        count = row["count"]

        by_status[status] = by_status.get(status, 0) + count
        by_type.setdefault(task_name, {})[status] = count

    return {
        "by_status": by_status,
        "by_type": by_type,
        "workers": await _get_active_workers(pool),
    }


async def _get_active_workers(pool: Any) -> list[dict[str, Any]]:
    rows = await pool.fetch(
        "SELECT COUNT(*) as running_tasks, MIN(id) as earliest_job_id "
        "FROM procrastinate_jobs WHERE status = 'doing'"
    )
    if not rows or rows[0]["running_tasks"] == 0:
        return []
    return [
        {
            "worker_id": "procrastinate-worker",
            "running_tasks": rows[0]["running_tasks"],
            "earliest_task": None,
        }
    ]
