from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.config import TargetConfig
from easm.keyword_engine import KeywordMatch


@pytest.mark.asyncio
async def test_gist_monitor_runner_returns_tuple_of_ints():
    from easm.runners.gist_monitor_runner import GistMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: []
    mock_client.get = AsyncMock(return_value=mock_resp)

    store = MagicMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.pool = AsyncMock()

    runner = GistMonitorRunner(store, http_client=mock_client)
    target = TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={"gist_monitor": {"enabled": True, "schedule": "*/30 * * * *", "args": {"timeout_seconds": 60}}},
    )
    inserted, deduped, errors = await runner.run_once(target, "scheduled", uuid.uuid7())
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)


@pytest.mark.asyncio
async def test_gist_monitor_runner_source_name():
    from easm.runners.gist_monitor_runner import GistMonitorRunner

    assert GistMonitorRunner.source_name == "gist_monitor"


@pytest.mark.asyncio
async def test_gist_monitor_runner_class_attributes():
    from easm.runners.gist_monitor_runner import GistMonitorRunner

    assert GistMonitorRunner.supports_schedule is True
    assert GistMonitorRunner.supports_manual_trigger is True
    assert GistMonitorRunner.is_continuous is False
