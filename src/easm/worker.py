from __future__ import annotations

import asyncio
import logging
import os

from easm.config import load_config
from easm.db import close_pool, create_pool
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
    pool = await create_pool(dsn)
    store = Store(pool)
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
