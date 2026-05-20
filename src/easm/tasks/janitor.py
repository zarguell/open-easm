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

    # ── Completed runs cleanup (>24h) ──────────────────────────────────
    run_ids = await pool.fetch(
        """
        SELECT id FROM runs
        WHERE status = 'completed'
          AND finished_at < NOW() - ($1 * interval '1 hour')
        """,
        delete_completed_older_than_hours,
    )
    deleted_completed = 0
    if run_ids:
        ids = [r["id"] for r in run_ids]
        await pool.execute(
            "UPDATE entities SET discovery_run_id = NULL WHERE discovery_run_id = ANY($1)",
            ids,
        )
        deleted_completed = (
            await pool.fetchval(
                "DELETE FROM runs WHERE id = ANY($1) RETURNING id",
                ids,
            )
            or 0
        )

    # ── Stale runs cleanup (>2h running / >4h pending) ──────────────────
    stale_runs = await pool.fetch(
        """
        UPDATE runs SET
          status = 'failed',
          error_message = 'janitor: run exceeded timeout (stale)',
          finished_at = NOW()
        WHERE (
          (status = 'running' AND started_at < NOW() - interval '2 hours')
          OR
          (status = 'pending' AND scheduled_for < NOW() - interval '4 hours')
        )
        AND org_id = $1
        RETURNING id
        """,
        org_id,
    )
    stale_count = len(stale_runs)
    if stale_count:
        logger.info(
            "marked stale runs as failed",
            extra={"stale_count": stale_count},
        )

    # ── Old failed runs cleanup (>72h) ─────────────────────────────────
    failed_ids_result = await pool.fetch(
        """
        SELECT id FROM runs
        WHERE status = 'failed'
          AND finished_at < NOW() - interval '72 hours'
        """,
    )
    deleted_failed = 0
    if failed_ids_result:
        failed_ids = [r["id"] for r in failed_ids_result]
        await pool.execute(
            "UPDATE entities SET discovery_run_id = NULL WHERE discovery_run_id = ANY($1)",
            failed_ids,
        )
        deleted_failed = (
            await pool.fetchval(
                "DELETE FROM runs WHERE id = ANY($1) RETURNING id",
                failed_ids,
            )
            or 0
        )
        if deleted_failed:
            logger.info(
                "deleted old failed runs",
                extra={"deleted_failed": deleted_failed},
            )

    # ── Summary ────────────────────────────────────────────────────────
    logger.info(
        "janitor cleanup complete",
        extra={
            "deleted_completed_runs": deleted_completed,
            "stale_runs_marked_failed": stale_count,
            "deleted_failed_runs": deleted_failed,
        },
    )
    return {
        "deleted_completed_runs": deleted_completed,
        "stale_runs_marked_failed": stale_count,
        "deleted_failed_runs": deleted_failed,
    }
