import asyncio
import logging
from datetime import datetime, timedelta, timezone

import asyncpg

logger = logging.getLogger(__name__)

DEFAULT_RAW_EVENTS_DAYS = 90
DEFAULT_RUNS_DAYS = 365
CHECK_INTERVAL_HOURS = 24


async def gc_worker(pool: asyncpg.Pool, raw_events_days: int = DEFAULT_RAW_EVENTS_DAYS, runs_days: int = DEFAULT_RUNS_DAYS):
    while True:
        logger.info("running garbage collection")
        try:
            raw_cutoff = datetime.now(timezone.utc) - timedelta(days=raw_events_days)
            result = await pool.execute(
                "DELETE FROM raw_events WHERE collected_at < $1",
                raw_cutoff,
            )
            logger.info("gc raw_events deleted", extra={"result": result})

            runs_cutoff = datetime.now(timezone.utc) - timedelta(days=runs_days)
            result2 = await pool.execute(
                "DELETE FROM runs WHERE finished_at < $1 AND status IN ('completed', 'failed')",
                runs_cutoff,
            )
            logger.info("gc runs deleted", extra={"result": result2})

            result3 = await pool.execute("""
                DELETE FROM entities e
                WHERE NOT EXISTS (
                    SELECT 1 FROM entity_raw_event_links erl WHERE erl.entity_id = e.id
                ) AND e.is_first_discovery = FALSE
            """)
            logger.info("gc orphaned entities deleted", extra={"result": result3})

        except Exception as e:
            logger.exception("gc error", extra={"error": str(e)})

        await asyncio.sleep(CHECK_INTERVAL_HOURS * 3600)
