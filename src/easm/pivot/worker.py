from __future__ import annotations

import asyncio
import inspect
import json
import logging
from pathlib import Path

import httpx

from easm.correlation.engine import CorrelationEngine
from easm.correlation.loader import load_rules_from_dir
from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY, PIVOT_SOURCE_NAMES
from easm.rate_limiter import get_default_limiters
from easm.store import Store, _compute_event_hash

logger = logging.getLogger(__name__)

CORRELATIONS_DIR = Path(__file__).parent.parent.parent / "correlations"

MAX_TRANSIENT_RETRIES = 3


async def _run_correlation(store: Store, org_id: str, target_id: str) -> None:
    try:
        if not CORRELATIONS_DIR.exists():
            return
        rules = load_rules_from_dir(CORRELATIONS_DIR)
        if not rules:
            return
        engine = CorrelationEngine(store.pool)
        findings = await engine.evaluate_rules(rules, org_id, target_id)
        if not findings:
            return
        for f in findings:
            try:
                await store.create_finding(f)
            except Exception:
                logger.exception("failed to save finding", extra={"rule_id": f.rule_id})
    except Exception:
        logger.exception("correlation engine failed")


async def pivot_worker_pool(pool, n: int = 3, batch_interval_ms: int = 200):
    store = Store(pool)
    await store.reset_orphaned_pivot_jobs()

    shared_http = httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
    )

    limiters = get_default_limiters()

    async def worker_loop():
        while True:
            jobs = await store.dequeue_pivot_jobs_batch(limit=20)
            if jobs:
                for job in jobs:
                    try:
                        handler_fn = PIVOT_HANDLER_REGISTRY.get(job["pivot_type"])
                        if not handler_fn:
                            await store.mark_pivot_failed(job["id"], "no handler for pivot type")
                            continue

                        sig = inspect.signature(handler_fn)
                        kwargs: dict = {}
                        if "http_client" in sig.parameters:
                            kwargs["http_client"] = shared_http
                        if "limiters" in sig.parameters:
                            kwargs["limiters"] = limiters
                        results = await handler_fn(job, pool, **kwargs)
                        source_name = PIVOT_SOURCE_NAMES.get(job["pivot_type"], job["pivot_type"])

                        run_id = job["run_id"]
                        if not run_id:
                            run_id = await store.create_run(
                                job["target_id"], f"pivot:{job['pivot_type']}",
                                "pivot", org_id=job["org_id"],
                            )

                        for raw_result in results:
                            meta = {
                                "_meta": {
                                    "session_id": (
                                        str(job["discovery_session_id"])
                                        if job["discovery_session_id"]
                                        else None
                                    ),
                                    "pivot_job_id": str(job["id"]),
                                },
                                **raw_result,
                            }
                            event_hash = _compute_event_hash(
                                job["org_id"], job["target_id"], source_name, meta,
                            )
                            raw_json = json.dumps(meta)
                            await pool.execute(
                                """INSERT INTO raw_events
                                   (org_id, target_id, source, raw, event_hash, run_id)
                                   VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                                   ON CONFLICT (event_hash) DO NOTHING""",
                                job["org_id"], job["target_id"], source_name,
                                raw_json, event_hash, run_id,
                            )
                        await store.mark_pivot_completed(job["id"])
                    except httpx.TransportError:
                        logger.exception(
                            "pivot transient error, will retry: "
                            "job_id=%s pivot_type=%s entity_value=%s",
                            str(job["id"]), job["pivot_type"], job["entity_value"],
                        )
                        err = job.get("error_message") or ""
                        retry_count = 0
                        if err.startswith("transient_error|"):
                            try:
                                retry_count = int(err.split("|")[1])
                            except (ValueError, IndexError):
                                retry_count = 0
                        if retry_count < MAX_TRANSIENT_RETRIES:
                            await pool.execute(
                                "UPDATE pivot_queue SET status='pending', enqueued_at=NOW(), "
                                "error_message=$2 WHERE id=$1",
                                job["id"], f"transient_error|{retry_count + 1}",
                            )
                        else:
                            await store.mark_pivot_failed(
                                job["id"],
                                f"permanent: transport error after {retry_count} retries",
                            )
                    except Exception:
                        logger.exception(
                            "pivot job failed: job_id=%s pivot_type=%s entity_value=%s",
                            str(job["id"]), job["pivot_type"], job["entity_value"],
                        )
                        await store.mark_pivot_failed(job["id"], "see logs")

                first = jobs[0]
                await _run_correlation(store, first["org_id"], first["target_id"])
            else:
                await asyncio.sleep(batch_interval_ms / 1000)

    try:
        async with asyncio.TaskGroup() as tg:
            for _ in range(n):
                tg.create_task(worker_loop())
    finally:
        await shared_http.aclose()
