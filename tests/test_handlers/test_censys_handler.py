import base64
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.pivot.handlers.censys_enrich import CensysEnrichHandler


@pytest.mark.asyncio
async def test_censys_handler_no_credentials():
    handler = CensysEnrichHandler()
    results = await handler.execute({"entity_value": "8.8.8.8"}, None)
    assert len(results) == 1
    assert "not configured" in results[0]["message"]


@pytest.mark.asyncio
async def test_censys_handler_with_api_key():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": {
        "services": [{"port": 443}],
        "location": {"country": "US"},
        "autonomous_system": {"asn": 15169},
        "last_updated_at": "2025-01-01",
    }}
    mock_resp.raise_for_status = MagicMock()
    mock_http.get = AsyncMock(return_value=mock_resp)

    handler = CensysEnrichHandler(api_id="testid", api_secret="testsecret", http_client=mock_http)
    results = await handler.execute({"entity_value": "8.8.8.8"}, None)
    assert len(results) == 1
    assert "censys" in results[0]
    assert results[0]["ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_censys_handler_404():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_http.get = AsyncMock(return_value=mock_resp)

    handler = CensysEnrichHandler(api_id="testid", api_secret="testsecret", http_client=mock_http)
    results = await handler.execute({"entity_value": "8.8.8.8"}, None)
    assert len(results) == 1
    assert "no censys data" in results[0]["message"]


def test_censys_handler_class_attributes():
    assert CensysEnrichHandler.pivot_type == "censys_enrich"
    assert CensysEnrichHandler.source_name == "censys"
