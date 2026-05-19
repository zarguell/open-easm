from __future__ import annotations

import logging

import procrastinate

from easm.queue import app

logger = logging.getLogger(__name__)


@app.task(
    queue="janitor",
    queueing_lock="janitor-cleanup",
)
async def execute_janitor(
    *,
    org_id: str = "default",
    delete_completed_older_than_hours: int = 24,
) -> dict:
    from easm.worker_context import get_pool

    pool = get_pool()
    deleted_runs = await pool.fetchval(
        """
        DELETE FROM runs
        WHERE status = 'completed'
          AND ended_at < NOW() - ($1 * interval '1 hour')
        """,
        delete_completed_older_than_hours,
    ) or 0

    logger.info(
        "janitor cleanup complete",
        extra={"deleted_runs": deleted_runs},
    )
    return {"deleted_runs": deleted_runs}
