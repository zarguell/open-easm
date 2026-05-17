import pytest
from easm.pivot.handlers.dns_resolve import DnsResolveHandler
from easm.pivot.handlers.crtsh_search import CrtShSearchHandler
from easm.pivot.handlers.shodan_enrich import ShodanEnrichHandler
from easm.pivot.handlers.reverse_dns import ReverseDnsHandler


@pytest.mark.asyncio
async def test_dns_resolve_handler_returns_list():
    handler = DnsResolveHandler()
    job = {"entity_value": "example.com"}
    results = await handler.execute(job, None)
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_dns_resolve_handler_empty_for_nonexistent():
    handler = DnsResolveHandler()
    job = {"entity_value": "nonexistent-domain-xyz.com"}
    results = await handler.execute(job, None)
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_pivot_handler_registry_imports():
    from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY
    assert "dns_resolve" in PIVOT_HANDLER_REGISTRY
    assert "crtsh_search" in PIVOT_HANDLER_REGISTRY
    assert "shodan_enrich" in PIVOT_HANDLER_REGISTRY
    assert "dns_mail_records" in PIVOT_HANDLER_REGISTRY
    assert "tls_cert_grab" in PIVOT_HANDLER_REGISTRY
    assert "geoip_enrich" in PIVOT_HANDLER_REGISTRY
    assert len(PIVOT_HANDLER_REGISTRY) == 11
