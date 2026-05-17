import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from easm.vuln_cache import refresh_kev_cache, lookup_kev_for_cve, _parse_date


@pytest.fixture(autouse=True)
def db_pool():
    return None


@pytest.fixture(autouse=True)
async def clean_db(db_pool):
    yield


MOCK_KEV_RESPONSE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2023-44487",
            "shortDescription": "HTTP/2 Rapid Reset Attack",
            "dateAdded": "2023-10-10",
            "dueDate": "2023-10-31",
            "vendorProject": "Multiple",
            "product": "HTTP/2",
            "notes": "",
        },
        {
            "cveID": "CVE-2024-1234",
            "shortDescription": "Example vulnerability",
            "dateAdded": "2024-01-15",
            "dueDate": "2024-02-05",
            "vendorProject": "Example Corp",
            "product": "Example Product",
            "notes": "Patch available",
        },
    ],
}


@pytest.mark.asyncio
async def test_refresh_kev_cache_upserts():
    mock_pool = AsyncMock()
    with patch("easm.vuln_cache.httpx.AsyncClient") as mock_cls:
        mock_response = MagicMock()
        mock_response.json.return_value = MOCK_KEV_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_cls.return_value.__aenter__.return_value = mock_client
        mock_cls.return_value.__aexit__.return_value = False

        count = await refresh_kev_cache(mock_pool)
        assert count == 2
        assert mock_pool.execute.call_count == 2


@pytest.mark.asyncio
async def test_lookup_kev_for_cve_found():
    mock_pool = AsyncMock()
    mock_pool.fetchrow.return_value = {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack",
        "kev_included": True,
        "kev_date_added": "2023-10-10",
        "kev_due_date": "2023-10-31",
    }
    result = await lookup_kev_for_cve(mock_pool, "CVE-2023-44487")
    assert result is not None
    assert result["kev_included"] is True


@pytest.mark.asyncio
async def test_lookup_kev_for_cve_not_found():
    mock_pool = AsyncMock()
    mock_pool.fetchrow.return_value = None
    result = await lookup_kev_for_cve(mock_pool, "CVE-9999-9999")
    assert result is None


def test_parse_date_valid():
    assert _parse_date("2023-10-10") is not None
    assert _parse_date("2023-10-10").year == 2023


def test_parse_date_none():
    assert _parse_date(None) is None
    assert _parse_date("") is None


def test_parse_date_invalid():
    assert _parse_date("not-a-date") is None
