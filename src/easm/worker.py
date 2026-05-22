from __future__ import annotations

import asyncio
import logging
import os

from easm.config import load_config
from easm.db import close_pool, create_pool
from easm.pivot.handlers import configure_enrichment_keys
from easm.queue import app as procrastinate_app
from easm.store import Store
from easm.worker_context import set_context

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_worker() -> None:
    dsn = os.environ.get("EASM_DATABASE_DSN")
    if not dsn:
        raise RuntimeError("EASM_DATABASE_DSN is required")

    config = load_config("config.yaml")
    configure_enrichment_keys(config)
    pool = await create_pool(dsn)
    store = Store(pool)

    logger.info("waiting for procrastinate schema")
    for attempt in range(60):
        try:
            exists = await pool.fetchval(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
                "WHERE table_name = 'procrastinate_jobs')"
            )
            if exists:
                logger.info("procrastinate schema found")
                break
        except Exception as e:
            logger.warning("schema check failed", attempt=attempt, error=str(e))
        await asyncio.sleep(2)
    else:
        raise RuntimeError("procrastinate schema not found after 120s")

    set_context(pool, store, config)

    async with procrastinate_app.open_async():
        logger.info("procrastinate worker starting")
        await procrastinate_app.run_worker_async(
            queues=["runner", "pivot", "janitor"],
            concurrency=3,
            install_signal_handlers=True,
        )

    await close_pool(pool)


if __name__ == "__main__":
    asyncio.run(run_worker())
