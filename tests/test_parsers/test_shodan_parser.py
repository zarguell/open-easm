import pytest
from easm.parse.shodan_parser import ShodanParser


@pytest.mark.asyncio
async def test_shodan_parser_full_api_extracts_all_attributes():
    parser = ShodanParser()
    result = await parser.parse({"raw": {"ip": "8.8.8.8", "shodan": {
        "ports": [53, 443], "hostnames": ["dns.google"],
        "vulns": ["CVE-2020-1234"], "org": "Google LLC", "isp": "Google",
        "asn": "AS15169", "country_name": "United States", "city": "Mountain View",
        "os": "Linux 4.x", "data": [{"port": 443, "transport": "tcp",
            "product": "nginx", "version": "1.18.0"}]
    }}})
    assert not result.unparseable
    assert len(result.entities) == 1
    attrs = result.entities[0].attributes
    assert attrs["source"] == "shodan"
    assert attrs["ports"] == [53, 443]
    assert attrs["hostnames"] == ["dns.google"]
    assert attrs["vulnerabilities"] == ["CVE-2020-1234"]
    assert attrs["org"] == "Google LLC"


@pytest.mark.asyncio
async def test_shodan_parser_internetdb_fallback():
    parser = ShodanParser()
    result = await parser.parse({"raw": {"ip": "8.8.8.8", "ports": [53, 443],
        "hostnames": ["dns.google"], "vulns": [], "source": "shodan"}})
    assert not result.unparseable
    attrs = result.entities[0].attributes
    assert attrs["ports"] == [53, 443]


@pytest.mark.asyncio
async def test_shodan_parser_missing_ip():
    parser = ShodanParser()
    result = await parser.parse({"raw": {}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_shodan_parser_class_attributes():
    assert ShodanParser.source_name == "shodan"
    assert ShodanParser.current_version == 1
