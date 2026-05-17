from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from easm.pivot.handlers import crtsh_search


@pytest_asyncio.fixture
async def db_pool():
    yield None


@pytest_asyncio.fixture(autouse=True)
async def clean_db(db_pool):
    yield


@pytest.mark.asyncio
async def test_crtsh_search_reuses_http_client():
    """crtsh_search should use the http_client passed via kwarg, not create its own."""
    job = {
        "entity_value": "example.com",
        "org_id": "test-org",
        "target_id": "test-target",
    }
    shared_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "name_value": "example.com\nwww.example.com",
            "fingerprint": "abc123",
            "serial_number": "sn",
            "not_before": "2024-01-01",
            "not_after": "2025-01-01",
            "issuer_name_id": "issuer1",
        }
    ]
    mock_resp.headers = {}
    shared_client.get.return_value = mock_resp

    results = await crtsh_search(job, pool=None, http_client=shared_client)
    assert len(results) > 0
    shared_client.get.assert_called()
