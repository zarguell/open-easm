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

    run_ids = await pool.fetch(
        """
        SELECT id FROM runs
        WHERE status = 'completed'
          AND finished_at < NOW() - ($1 * interval '1 hour')
        """,
        delete_completed_older_than_hours,
    )
    if not run_ids:
        logger.info("janitor cleanup complete", extra={"deleted_runs": 0})
        return {"deleted_runs": 0}

    ids = [r["id"] for r in run_ids]
    await pool.execute(
        "UPDATE entities SET discovery_run_id = NULL WHERE discovery_run_id = ANY($1)",
        ids,
    )
    deleted_runs = await pool.fetchval(
        "DELETE FROM runs WHERE id = ANY($1) RETURNING id",
        ids,
    ) or 0

    logger.info(
        "janitor cleanup complete",
        extra={"deleted_runs": deleted_runs},
    )
    return {"deleted_runs": deleted_runs}
