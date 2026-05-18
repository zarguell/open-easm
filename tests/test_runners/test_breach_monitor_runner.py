from __future__ import annotations

import uuid
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.config import TargetConfig


@pytest.mark.asyncio
async def test_breach_monitor_class_attributes():
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    assert BreachMonitorRunner.source_name == "breach_monitor"
    assert BreachMonitorRunner.supports_schedule is True
    assert BreachMonitorRunner.supports_manual_trigger is True
    assert BreachMonitorRunner.is_continuous is False


@pytest.fixture
def target():
    return TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={
            "breach_monitor": {
                "enabled": True,
                "schedule": "0 6 * * *",
                "sources": ["hibp"],
            }
        },
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.pool = AsyncMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.create_run = AsyncMock(return_value=uuid.uuid7())
    store.mark_run_started = AsyncMock()
    store.mark_run_finished = AsyncMock()
    store.get_run = AsyncMock(return_value={"discovery_session_id": str(uuid.uuid7())})
    return store


@pytest.mark.asyncio
async def test_breach_monitor_hibp_check(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: [
        {"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Emails", "Passwords"]},
    ]
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_hibp_no_breaches(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_hibp_rate_limited(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_dehashed_check(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    target.runners["breach_monitor"].sources = ["dehashed"]
    target.runners["breach_monitor"].dehashed_api_key = "fake-key"
    target.runners["breach_monitor"].dehashed_email = "test@example.com"

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "entries": [
            {
                "id": 1,
                "email": "admin@example.com",
                "password": "s3cret",
                "database_name": "ExampleCorp",
            }
        ]
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_runner_closes_http_client(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    await runner.close()
    mock_client.aclose.assert_awaited_once()
