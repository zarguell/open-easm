from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from easm.pivot.handlers.passive_dns import PassiveDnsHandler


@pytest.mark.asyncio
async def test_passive_dns_handler_no_api_key():
    handler = PassiveDnsHandler()
    results = await handler.execute({"entity_value": "example.com"}, None)
    assert len(results) == 1
    assert "no securitytrails api key" in results[0]["message"]


@pytest.mark.asyncio
async def test_passive_dns_handler_with_key():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"records": [
        {"values": [{"ip": "1.2.3.4"}], "first_seen": "2024-01-01", "last_seen": "2024-06-01"},
    ]}
    mock_resp.raise_for_status = MagicMock()
    mock_http.get = AsyncMock(return_value=mock_resp)

    handler = PassiveDnsHandler(api_key="testkey", http_client=mock_http)
    results = await handler.execute({"entity_value": "example.com"}, None)
    assert len(results) == 1
    assert "passive_dns" in results[0]
    assert len(results[0]["passive_dns"]["a_records"]) == 1


@pytest.mark.asyncio
async def test_passive_dns_handler_404():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_http.get = AsyncMock(return_value=mock_resp)

    handler = PassiveDnsHandler(api_key="testkey", http_client=mock_http)
    results = await handler.execute({"entity_value": "example.com"}, None)
    assert "no dns history" in results[0]["message"]


def test_passive_dns_handler_class_attributes():
    assert PassiveDnsHandler.pivot_type == "passive_dns"
    assert PassiveDnsHandler.source_name == "securitytrails"
