import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from easm.pivot.handlers.domain_rdap import DomainRdapHandler


@pytest.mark.asyncio
async def test_domain_rdap_handler_returns_enhanced_data():
    handler = DomainRdapHandler()
    job = {"entity_value": "example.com"}
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "a.iana-servers.net"},
            {"ldhName": "b.iana-servers.net"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Corp"]]],
            }
        ],
    }
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("easm.pivot.handlers.domain_rdap.httpx.AsyncClient", return_value=mock_client):
        results = await handler.execute(job, None)

    assert len(results) == 1
    assert results[0]["domain"] == "example.com"
    assert results[0]["source"] == "domain_rdap"
    assert results[0]["registrant_org"] == "Example Corp"
    assert results[0]["created_date"] == "2000-01-01T00:00:00Z"
    assert results[0]["expiration_date"] == "2026-01-01T00:00:00Z"
    assert results[0]["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert results[0]["status"] == ["client transfer prohibited"]


@pytest.mark.asyncio
async def test_domain_rdap_handler_failure_returns_message():
    handler = DomainRdapHandler()
    job = {"entity_value": "nonexistent-domain-xyz123.com"}
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=Exception("RDAP failed"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("easm.pivot.handlers.domain_rdap.httpx.AsyncClient", return_value=mock_client):
        results = await handler.execute(job, None)

    assert len(results) == 1
    assert "message" in results[0]


@pytest.mark.asyncio
async def test_domain_rdap_handler_rdap_url_routing():
    handler = DomainRdapHandler()
    assert "verisign.com" in handler._rdap_url("example.com")
    assert "verisign.com" in handler._rdap_url("example.net")
    assert "rdap.org" in handler._rdap_url("example.org")
    assert "rdap.org" in handler._rdap_url("example.io")
