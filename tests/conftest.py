import asyncio
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio


@pytest.fixture
def configs_dir():
    return Path(__file__).parent / "fixtures" / "configs"


_test_dsn = "postgresql://easm:easm@localhost:5432/easm"


@pytest_asyncio.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_pool():
    pool = await asyncpg.create_pool(dsn=_test_dsn, min_size=1, max_size=5)
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def scheduler():
    from easm.scheduler import Scheduler

    s = Scheduler()
    yield s
    if s.running:
        await s.shutdown()


@pytest_asyncio.fixture(autouse=True)
async def clean_db(db_pool):
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM entity_raw_event_links")
        await conn.execute("DELETE FROM entity_relationships")
        await conn.execute("DELETE FROM entities")
        await conn.execute("DELETE FROM raw_events")
        await conn.execute("DELETE FROM runs")
        await conn.execute("DELETE FROM config_snapshots")
    yield
