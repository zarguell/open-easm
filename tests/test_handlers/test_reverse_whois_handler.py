from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.pivot.handlers.reverse_whois import ReverseWhoisHandler


@pytest.mark.asyncio
async def test_reverse_whois_handler_extracts_domains():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '<html><a href="#">other.com</a><a href="#">test.org</a></html>'
    mock_resp.raise_for_status = MagicMock()
    mock_http.get = AsyncMock(return_value=mock_resp)

    handler = ReverseWhoisHandler(http_client=mock_http)
    results = await handler.execute({"entity_value": "example.com"}, None)
    assert len(results) == 1
    assert "reverse_whois" in results[0]
    assert "other.com" in results[0]["reverse_whois"]["related_domains"]


@pytest.mark.asyncio
async def test_reverse_whois_handler_error():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.get = AsyncMock(side_effect=Exception("connection error"))

    handler = ReverseWhoisHandler(http_client=mock_http)
    results = await handler.execute({"entity_value": "example.com"}, None)
    assert len(results) == 1
    assert "failed" in results[0]["message"]


def test_reverse_whois_handler_class_attributes():
    assert ReverseWhoisHandler.pivot_type == "reverse_whois"
    assert ReverseWhoisHandler.source_name == "reverse_whois"
