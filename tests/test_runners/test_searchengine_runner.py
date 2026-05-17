import uuid
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.runners.searchengine_runner import SearchEngineRunner


@pytest.mark.asyncio
async def test_searchengine_runner_class_attributes():
    assert SearchEngineRunner.source_name == "searchengine"
    assert SearchEngineRunner.supports_schedule is True
    assert SearchEngineRunner.supports_manual_trigger is True
    assert SearchEngineRunner.is_continuous is False
    assert SearchEngineRunner.is_api_runner is True


@pytest.mark.asyncio
async def test_searchengine_runner_run_once_returns_counts():
    mock_store = MagicMock()
    mock_store.pool = AsyncMock()
    mock_store.pool.execute = AsyncMock(return_value="INSERT 0 1")

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]

    ddg_html = '<html><a href="https://sub.example.com/page">link</a></html>'

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ddg_html
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {}
    mock_http.get = AsyncMock(return_value=mock_resp)

    runner = SearchEngineRunner(store=mock_store, http_client=mock_http)
    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)
