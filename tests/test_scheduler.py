import asyncio

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from easm.scheduler import Scheduler


@pytest.mark.asyncio
async def test_scheduler_starts_stopped():
    s = Scheduler()
    assert s.running is False


@pytest.mark.asyncio
async def test_scheduler_start():
    s = Scheduler()
    s.start()
    assert s.running is True
    await s.shutdown()


@pytest.mark.asyncio
async def test_scheduler_shutdown():
    s = Scheduler()
    s.start()
    await s.shutdown()
    await asyncio.sleep(0)
    assert s.running is False


@pytest.mark.asyncio
async def test_scheduler_get_running_jobs_empty():
    s = Scheduler()
    s.start()
    jobs = s.get_running_jobs()
    assert len(jobs) == 0
    await s.shutdown()


class TestCountActiveRuns:
    @pytest_asyncio.fixture(autouse=True)
    async def clean_db(self):
        yield

    @pytest.mark.asyncio
    async def test_returns_zero_when_none(self):
        from easm.store import Store

        mock_pool = AsyncMock()
        mock_pool.fetchval.return_value = 0
        store = Store(mock_pool)

        count = await store.count_active_runs("target-1", "subfinder")
        assert count == 0

    @pytest.mark.asyncio
    async def test_returns_count_when_active(self):
        from easm.store import Store

        mock_pool = AsyncMock()
        mock_pool.fetchval.return_value = 2
        store = Store(mock_pool)

        count = await store.count_active_runs("target-1", "subfinder")
        assert count == 2
