import uuid
import pytest
from unittest.mock import AsyncMock

from easm.vuln_enrichment import cpe_vuln_enrich, _classify_risk


@pytest.fixture
def db_pool():
    return None


@pytest.fixture(autouse=True)
def clean_db():
    yield


def test_classify_risk_kev_is_critical():
    cves = [{"kev_included": True, "cvss_score": 5.0}]
    assert _classify_risk(cves) == "critical"


def test_classify_risk_high_cvss():
    cves = [{"kev_included": False, "cvss_score": 9.8}]
    assert _classify_risk(cves) == "critical"


def test_classify_risk_medium():
    cves = [{"kev_included": False, "cvss_score": 6.5}]
    assert _classify_risk(cves) == "medium"


def test_classify_risk_low():
    cves = [{"kev_included": False, "cvss_score": 3.0}]
    assert _classify_risk(cves) == "low"


def test_classify_risk_none():
    assert _classify_risk([]) == "none"


def test_classify_risk_unknown():
    cves = [{"kev_included": False, "cvss_score": None}]
    assert _classify_risk(cves) == "unknown"


@pytest.mark.asyncio
async def test_cpe_vuln_enrich_no_technologies():
    mock_pool = AsyncMock()
    mock_pool.fetchrow.return_value = {
        "attributes": {"ports": [80]},
    }

    job = {
        "entity_type": "hostname",
        "entity_value": "example.com",
        "entity_id": uuid.uuid4(),
    }

    results = await cpe_vuln_enrich(job, mock_pool)
    assert len(results) == 1
    assert results[0]["message"] == "no CPEs computable"


@pytest.mark.asyncio
async def test_cpe_vuln_enrich_with_technologies():
    mock_pool = AsyncMock()
    mock_pool.fetchrow.return_value = {
        "attributes": {
            "technologies": [{"name": "nginx", "version": "1.24.0"}],
        },
    }
    mock_pool.fetch.return_value = []  # no CVE cache matches

    job = {
        "entity_type": "hostname",
        "entity_value": "example.com",
        "entity_id": uuid.uuid4(),
    }

    results = await cpe_vuln_enrich(job, mock_pool)
    assert len(results) == 1
    assert "cpe:2.3:a:nginx:nginx:1.24.0" in str(results[0]["computed_cpes"])
    assert results[0]["total_cves"] == 0
