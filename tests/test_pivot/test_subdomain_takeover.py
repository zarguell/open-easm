from unittest.mock import patch, MagicMock
import pytest
import pytest_asyncio
from easm.pivot.handlers import subdomain_takeover


@pytest_asyncio.fixture
async def db_pool():
    yield None


@pytest.mark.asyncio
@patch("easm.pivot.handlers.dns.resolver.resolve")
async def test_takeover_detects_cname_to_github_pages(mock_resolve, db_pool):
    """Takeover detection should find vulnerability via CNAME resolution, not string matching."""
    cname_rdata = MagicMock()
    cname_rdata.target = MagicMock()
    cname_rdata.target.__str__ = lambda self: "username.github.io."
    cname_answer = MagicMock()
    cname_answer.__iter__ = lambda self: iter([cname_rdata])
    mock_resolve.return_value = cname_answer

    job = {"entity_value": "blog.arguelles.me", "org_id": "test", "target_id": "test"}
    results = await subdomain_takeover(job, db_pool)

    assert len(results) == 1
    check = results[0].get("takeover_check", {})
    assert check.get("takeover_risk") is True
    assert any(f["service"] == "github_pages" for f in check.get("fingerprint_matches", []))
    assert check.get("cname_target") == "username.github.io"


@pytest.mark.asyncio
@patch("easm.pivot.handlers.dns.resolver.resolve")
async def test_takeover_safe_when_no_cname_to_saas(mock_resolve, db_pool):
    """Takeover detection should report no risk when no CNAME or CNAME to non-vulnerable target."""
    from dns.resolver import NoAnswer
    mock_resolve.side_effect = NoAnswer("no CNAME")

    job = {"entity_value": "www.arguelles.me", "org_id": "test", "target_id": "test"}
    results = await subdomain_takeover(job, db_pool)

    assert len(results) == 1
    check = results[0].get("takeover_check", {})
    assert check.get("takeover_risk") is False
    assert check.get("cname_target") is None


@pytest.mark.asyncio
@patch("easm.pivot.handlers.dns.resolver.resolve")
async def test_takeover_detects_azure_app_service(mock_resolve, db_pool):
    """Takeover detection should detect Azure App Service CNAMEs."""
    cname_rdata = MagicMock()
    cname_rdata.target = MagicMock()
    cname_rdata.target.__str__ = lambda self: "myapp.azurewebsites.net."
    cname_answer = MagicMock()
    cname_answer.__iter__ = lambda self: iter([cname_rdata])
    mock_resolve.return_value = cname_answer

    job = {"entity_value": "staging.blodgettpartners.com", "org_id": "test", "target_id": "test"}
    results = await subdomain_takeover(job, db_pool)

    assert len(results) == 1
    check = results[0].get("takeover_check", {})
    assert check.get("takeover_risk") is True
    assert any(f["service"] == "azure_app" for f in check.get("fingerprint_matches", []))
