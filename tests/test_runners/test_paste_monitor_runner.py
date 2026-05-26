from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.config import TargetConfig
from easm.keyword_engine import KeywordMatch


@pytest.mark.asyncio
async def test_paste_monitor_class_attributes():
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    assert PasteMonitorRunner.source_name == "paste_monitor"
    assert PasteMonitorRunner.supports_schedule is True
    assert PasteMonitorRunner.supports_manual_trigger is True
    assert PasteMonitorRunner.is_continuous is False


@pytest.fixture
def target():
    return TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={
            "paste_monitor": {
                "enabled": True,
                "schedule": "*/5 * * * *",
                "sources": ["pastebin"],
            }
        },
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.pool = AsyncMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.create_run = AsyncMock(return_value=uuid.uuid4())
    store.mark_run_started = AsyncMock()
    store.mark_run_finished = AsyncMock()
    store.get_run = AsyncMock(return_value={"discovery_session_id": str(uuid.uuid4())})
    return store


@pytest.fixture
def mock_pastebin_response():
    return [
        {
            "id": "abc123",
            "title": "config dump",
            "user": "anon",
            "date": "2024-01-15 10:30:00",
            "content": "internal acme corp password: s3cret!",
            "size": 1024,
            "expire": "N",
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=abc123",
        }
    ]


@pytest.mark.asyncio
async def test_paste_monitor_run_once_polls_pastebin(target, mock_store, mock_pastebin_response):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json = lambda: mock_pastebin_response

    content_resp = MagicMock()
    content_resp.status_code = 200
    content_resp.text = "internal acme corp password: s3cret!"

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=[list_resp, content_resp])

    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid4()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_paste_monitor_run_once_handles_api_error(target, mock_store):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 429
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid4()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_paste_monitor_run_once_no_matches_stores_zero(target, mock_store):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json = lambda: [
        {"id": "x1", "content": "no keywords here", "scrape_url": "http://x"}
    ]

    content_resp = MagicMock()
    content_resp.status_code = 200
    content_resp.text = "no keywords here"

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=[list_resp, content_resp])

    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid4()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert deduped == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_paste_monitor_runner_closes_http_client(target, mock_store):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    await runner.close()
    mock_client.aclose.assert_awaited_once()
