from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.config import TargetConfig


@pytest.mark.asyncio
async def test_stackoverflow_runner_returns_tuple_of_ints():
    from easm.runners.stackoverflow_monitor_runner import StackOverflowMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {"items": []}
    mock_client.get = AsyncMock(return_value=mock_resp)

    store = MagicMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.pool = AsyncMock()

    runner = StackOverflowMonitorRunner(store, http_client=mock_client)
    target = TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={"stackoverflow_monitor": {"enabled": True, "schedule": "0 */2 * * *", "args": {"timeout_seconds": 60}}},
    )
    inserted, deduped, errors = await runner.run_once(target, "scheduled", uuid.uuid4())
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)


@pytest.mark.asyncio
async def test_stackoverflow_runner_source_name():
    from easm.runners.stackoverflow_monitor_runner import StackOverflowMonitorRunner

    assert StackOverflowMonitorRunner.source_name == "stackoverflow_monitor"


@pytest.mark.asyncio
async def test_stackoverflow_runner_class_attributes():
    from easm.runners.stackoverflow_monitor_runner import StackOverflowMonitorRunner

    assert StackOverflowMonitorRunner.supports_schedule is True
    assert StackOverflowMonitorRunner.supports_manual_trigger is True
    assert StackOverflowMonitorRunner.is_continuous is False
