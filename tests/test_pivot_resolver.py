import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from easm.pivot.resolver import PivotResolver


@pytest_asyncio.fixture
async def db_pool():
    pool = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=AsyncMock())
    ctx.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = ctx
    return pool


@pytest_asyncio.fixture
async def clean_db(db_pool):
    yield


@pytest.mark.asyncio
async def test_skips_enqueue_when_queue_full():
    mock_pool = AsyncMock()
    mock_pool.fetchval.side_effect = [None, 10000]
    mock_pool.fetchrow.return_value = None

    resolver = PivotResolver(mock_pool)
    resolver.store.enqueue_pivot_job = AsyncMock()
    mock_target = MagicMock()
    mock_target.pivot.enabled = True
    mock_target.pivot.max_depth = 3
    mock_target.pivot.max_queue_depth = 5000
    mock_target.pivot.scope_mode = "strict"
    pivot_rule = MagicMock()
    pivot_rule.from_ = "domain"
    pivot_rule.via = "crtsh_search"
    pivot_rule.cooldown_hours = 0
    pivot_rule.coverage = None
    mock_target.pivot.allowed_pivots = [pivot_rule]
    mock_target.org_id = "test-org"
    mock_target.id = "target-1"
    mock_target.match_rules.domains = ["example.com"]

    await resolver.check_and_enqueue(
        mock_target, "domain", "example.com", uuid.uuid4(),
    )

    resolver.store.enqueue_pivot_job.assert_not_called()


@pytest.mark.asyncio
async def test_enqueues_when_queue_not_full():
    mock_pool = AsyncMock()
    mock_pool.fetchval.side_effect = [None, 100]
    mock_pool.fetchrow.return_value = None

    resolver = PivotResolver(mock_pool)
    resolver.store.enqueue_pivot_job = AsyncMock()
    mock_target = MagicMock()
    mock_target.pivot.enabled = True
    mock_target.pivot.max_depth = 3
    mock_target.pivot.max_queue_depth = 5000
    mock_target.pivot.scope_mode = "strict"
    pivot_rule = MagicMock()
    pivot_rule.from_ = "domain"
    pivot_rule.via = "crtsh_search"
    pivot_rule.cooldown_hours = 0
    pivot_rule.coverage = None
    mock_target.pivot.allowed_pivots = [pivot_rule]
    mock_target.org_id = "test-org"
    mock_target.id = "target-1"
    mock_target.match_rules.domains = ["example.com"]

    await resolver.check_and_enqueue(
        mock_target, "domain", "example.com", uuid.uuid4(),
    )

    resolver.store.enqueue_pivot_job.assert_called()
