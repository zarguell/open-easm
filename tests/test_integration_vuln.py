import pytest
import pytest_asyncio
from easm.cpe_mapper import compute_cpes_from_entity


@pytest_asyncio.fixture
async def db_pool():
    yield None


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    yield


def test_wappalyzer_to_cpe_flow():
    """Integration: Wappalyzer detects nginx → CPE computed."""
    wappalyzer_attrs = {
        "technologies": [
            {"name": "nginx", "version": "1.24.0"},
        ],
    }
    cpes = compute_cpes_from_entity("hostname", wappalyzer_attrs)
    assert len(cpes) == 1
    assert "cpe:2.3:a:nginx:nginx:1.24.0" in str(cpes)


def test_shodan_cpes_to_kev_ready():
    """Integration: Shodan CPEs pass through to compute_cpes_from_entity."""
    shodan_attrs = {
        "cpes": ["cpe:/a:apache:http_server:2.4.41"],
    }
    cpes = compute_cpes_from_entity("ip", shodan_attrs)
    assert len(cpes) == 1
    assert "cpe:/a:apache:http_server:2.4.41" in cpes


def test_full_chain_technologies_to_cpes():
    """Full chain: technologies → CPEs → deduplicated."""
    attrs = {
        "technologies": [
            {"name": "nginx", "version": "1.24.0"},
            {"name": "WordPress", "version": "6.4"},
        ],
        "cpes": ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"],
    }
    cpes = compute_cpes_from_entity("hostname", attrs)
    assert len(cpes) == 2
