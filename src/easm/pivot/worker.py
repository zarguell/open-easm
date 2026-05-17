from __future__ import annotations

import asyncio
import json
import logging

from easm.pivot import PIVOT_HANDLER_REGISTRY

logger = logging.getLogger(__name__)
from easm.pivot_store import (
    dequeue_pivot_job,
    mark_pivot_completed,
    mark_pivot_failed,
    reset_orphaned_pivot_jobs,
)
from easm.store import _compute_event_hash


async def pivot_worker_pool(pool, n: int = 3, batch_interval_ms: int = 200):
    await reset_orphaned_pivot_jobs(pool)

    async def worker_loop():
        while True:
            job = await dequeue_pivot_job(pool)
            if job:
                try:
                    handler_cls = PIVOT_HANDLER_REGISTRY.get(job["pivot_type"])
                    if not handler_cls:
                        await mark_pivot_failed(pool, job["id"], "no handler for pivot type")
                        continue

                    handler = handler_cls()
                    results = await handler.execute(job, pool)

                    for raw_result in results:
                        meta = {
                            "_meta": {
                                "session_id": str(job["discovery_session_id"]) if job["discovery_session_id"] else None,
                                "pivot_job_id": str(job["id"]),
                            },
                            **raw_result,
                        }
                        event_hash = _compute_event_hash(
                            job["org_id"], job["target_id"], handler.source_name, meta,
                        )
                        raw_json = json.dumps(meta)
                        await pool.execute(
                            """INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
                               VALUES ($1, $2, $3, $4::jsonb, $5, $6)""",
                            job["org_id"], job["target_id"], handler.source_name,
                            raw_json, event_hash, job["run_id"],
                        )
                    await mark_pivot_completed(pool, job["id"])
                except Exception:
                    logger.exception(
                        "pivot job failed: job_id=%s pivot_type=%s entity_value=%s",
                        str(job["id"]), job["pivot_type"], job["entity_value"],
                    )
                    await mark_pivot_failed(pool, job["id"], "see logs")
            else:
                await asyncio.sleep(batch_interval_ms / 1000)

    async with asyncio.TaskGroup() as tg:
        for _ in range(n):
            tg.create_task(worker_loop())
