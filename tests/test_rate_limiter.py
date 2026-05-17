import asyncio

import pytest
import pytest_asyncio

from easm.rate_limiter import ApiRateLimiters, get_default_limiters


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    yield


def test_default_limiters_created():
    limiters = get_default_limiters()
    assert limiters.crtsh._value == 5
    assert limiters.shodan._value == 5
    assert limiters.censys._value == 2
    assert limiters.greynoise._value == 10


@pytest.mark.asyncio
async def test_semaphore_limits_concurrency():
    limiter = asyncio.Semaphore(2)
    running = 0
    max_running = 0

    async def worker():
        nonlocal running, max_running
        await limiter.acquire()
        try:
            running += 1
            max_running = max(max_running, running)
            await asyncio.sleep(0.01)
            running -= 1
        finally:
            limiter.release()

    tasks = [asyncio.create_task(worker()) for _ in range(10)]
    await asyncio.gather(*tasks)
    assert max_running <= 2


def test_get_default_limiters_returns_dataclass():
    limiters = get_default_limiters()
    assert isinstance(limiters, ApiRateLimiters)
