import uuid
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.runners.commoncrawl_runner import CommonCrawlRunner, _derive_cc_urls


def test_derive_cc_urls():
    urls = _derive_cc_urls("example.com")
    assert len(urls) == 6
    assert any("example.com" in u for u in urls)


@pytest.mark.asyncio
async def test_commoncrawl_runner_class_attributes():
    assert CommonCrawlRunner.source_name == "commoncrawl"
    assert CommonCrawlRunner.supports_schedule is True
    assert CommonCrawlRunner.supports_manual_trigger is True
    assert CommonCrawlRunner.is_continuous is False
    assert CommonCrawlRunner.is_api_runner is True


@pytest.mark.asyncio
async def test_commoncrawl_runner_run_once_returns_counts():
    mock_store = MagicMock()
    mock_store.pool = AsyncMock()
    mock_store.pool.execute = AsyncMock(return_value="INSERT 0 1")

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]

    cdx_response = '{"url": "https://sub.example.com/page", "status": "200"}\n'

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = cdx_response
    mock_http.get = AsyncMock(return_value=mock_resp)

    runner = CommonCrawlRunner(store=mock_store, http_client=mock_http)
    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)
