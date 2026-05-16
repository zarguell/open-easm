from __future__ import annotations

import asyncio
import logging

import asyncpg

logger = logging.getLogger(__name__)


async def create_pool(
    dsn: str,
    *,
    max_retries: int = 10,
    retry_delay: float = 2.0,
) -> asyncpg.Pool:
    for attempt in range(max_retries):
        try:
            pool = await asyncpg.create_pool(
                dsn=dsn,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )
            await pool.fetchval("SELECT 1")
            logger.info("database pool created successfully")
            return pool
        except Exception as e:
            logger.warning(
                "database connection attempt %d/%d failed: %s",
                attempt + 1,
                max_retries,
                e,
            )
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                raise


async def close_pool(pool: asyncpg.Pool) -> None:
    await pool.close()
    logger.info("database pool closed")
