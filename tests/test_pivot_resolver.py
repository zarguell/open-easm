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


@pytest.mark.asyncio
async def test_check_cooldown_returns_fetchval_row():
    mock_pool = AsyncMock()
    mock_pool.fetchval.return_value = 1
    resolver = PivotResolver(mock_pool)

    result = await resolver._check_cooldown(
        "test-org", "domain", "example.com", "crtsh_search", 24,
    )

    assert result == 1


@pytest.mark.asyncio
async def test_check_apex_coverage_returns_fetchval_row():
    mock_pool = AsyncMock()
    mock_pool.fetchval.return_value = 1
    resolver = PivotResolver(mock_pool)

    result = await resolver._check_apex_coverage(
        "test-org", "example.com", "crtsh_search", 24,
    )

    assert result == 1


@pytest.mark.asyncio
async def test_insert_skipped_includes_required_entity_id():
    mock_pool = AsyncMock()
    resolver = PivotResolver(mock_pool)
    entity_id = uuid.uuid4()

    await resolver._insert_skipped(
        "test-org", "target-1", "domain", "www.example.com", entity_id,
        "crtsh_search", "covered_by_apex:example.com",
    )

    sql = mock_pool.execute.call_args.args[0]
    assert "entity_id" in sql
    mock_pool.execute.assert_awaited_once_with(
        sql, "test-org", "target-1", "domain", "www.example.com", entity_id,
        "crtsh_search", "covered_by_apex:example.com",
    )
