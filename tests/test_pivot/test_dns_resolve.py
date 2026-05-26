from unittest.mock import patch, MagicMock
import pytest
import pytest_asyncio
from easm.pivot.handlers import dns_resolve


@pytest_asyncio.fixture
async def db_pool():
    yield None


@pytest.mark.asyncio
@patch("easm.pivot.handlers.dns.resolver.resolve")
async def test_dns_resolve_returns_cname_and_a_records(mock_resolve, db_pool):
    """dns_resolve should return CNAME records alongside A records."""
    cname_rdata = MagicMock()
    cname_rdata.target = MagicMock()
    cname_rdata.target.__str__ = lambda self: "username.github.io."
    cname_answer = MagicMock()
    cname_answer.__iter__ = lambda self: iter([cname_rdata])

    a_rdata = MagicMock()
    a_rdata.__str__ = lambda self: "185.199.108.153"
    a_answer = MagicMock()
    a_answer.__iter__ = lambda self: iter([a_rdata])

    def resolve_side_effect(hostname, rtype):
        if rtype == "CNAME":
            return cname_answer
        if rtype == "A":
            return a_answer
        return MagicMock()

    mock_resolve.side_effect = resolve_side_effect
    job = {"entity_value": "www.arguelles.me", "org_id": "test", "target_id": "test"}
    results = await dns_resolve(job, db_pool)

    a_results = [r for r in results if r.get("record_type") == "A"]
    cname_results = [r for r in results if r.get("record_type") == "CNAME"]
    assert len(a_results) == 1
    assert a_results[0]["ip"] == "185.199.108.153"
    assert len(cname_results) == 1
    assert cname_results[0]["cname_target"] == "username.github.io"


@pytest.mark.asyncio
@patch("easm.pivot.handlers.dns.resolver.resolve")
async def test_dns_resolve_handles_no_cname(mock_resolve, db_pool):
    """dns_resolve should work fine when no CNAME exists (direct A record)."""
    a_rdata = MagicMock()
    a_rdata.__str__ = lambda self: "93.184.216.34"
    a_answer = MagicMock()
    a_answer.__iter__ = lambda self: iter([a_rdata])

    def resolve_side_effect(hostname, rtype):
        if rtype == "A":
            return a_answer
        raise Exception("no CNAME")

    mock_resolve.side_effect = resolve_side_effect
    job = {"entity_value": "example.com", "org_id": "test", "target_id": "test"}
    results = await dns_resolve(job, db_pool)

    a_results = [r for r in results if r.get("record_type") == "A"]
    assert len(a_results) == 1
    cname_results = [r for r in results if r.get("record_type") == "CNAME"]
    assert len(cname_results) == 0


@pytest.mark.asyncio
@patch("easm.pivot.handlers.dns.resolver.resolve")
async def test_dns_resolve_handles_nxdomain(mock_resolve, db_pool):
    """dns_resolve should return empty list for NXDOMAIN."""
    import dns.resolver
    mock_resolve.side_effect = dns.resolver.NXDOMAIN("no such domain")
    job = {"entity_value": "nonexistent.invalid", "org_id": "test", "target_id": "test"}
    results = await dns_resolve(job, db_pool)
    assert results == []
