import asyncio

import pytest
from easm.scheduler import Scheduler


@pytest.mark.asyncio
async def test_scheduler_starts_stopped():
    s = Scheduler()
    assert s.running is False


@pytest.mark.asyncio
async def test_scheduler_register_runner():
    s = Scheduler()
    s.register_runner("subfinder", type("X", (), {}))
    assert "subfinder" in s._runner_registry


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
