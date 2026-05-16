import pytest
from easm.parse.dnstwist_parser import DnstwistParser


@pytest.mark.asyncio
async def test_dnstwist_parser_returns_lookalike_domain():
    parser = DnstwistParser()
    event = {
        "raw": {
            "domain": "examp1e.com",
            "original_domain": "example.com",
            "type": "typo",
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].value == "examp1e.com"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_dnstwist_parser_creates_lookalike_relationship():
    parser = DnstwistParser()
    event = {
        "raw": {
            "domain": "examp1e.com",
            "original_domain": "example.com",
            "type": "typo",
        }
    }
    result = await parser.parse(event)
    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert rel.source_type == "domain"
    assert rel.source_value == "examp1e.com"
    assert rel.target_type == "domain"
    assert rel.target_value == "example.com"
    assert rel.relationship_type == "lookalike_of"
    assert rel.relationship_source == "runner_direct"
    assert rel.runner == "dnstwist"


@pytest.mark.asyncio
async def test_dnstwist_parser_includes_attributes():
    parser = DnstwistParser()
    event = {
        "raw": {
            "domain": "examp1e.com",
            "original_domain": "example.com",
            "type": "typo",
            "dns": {"a": ["1.2.3.4"]},
            "registered": True,
        }
    }
    result = await parser.parse(event)
    attrs = result.entities[0].attributes
    assert "dnstwist" in attrs
    assert attrs["dnstwist"]["permutation_type"] == "typo"
    assert attrs["dnstwist"]["original_domain"] == "example.com"
    assert attrs["dnstwist"]["dns_records"]["a"] == ["1.2.3.4"]
    assert attrs["dnstwist"]["is_registered"] is True


@pytest.mark.asyncio
async def test_dnstwist_parser_no_original_no_relationship():
    parser = DnstwistParser()
    event = {"raw": {"domain": "examp1e.com", "type": "typo"}}
    result = await parser.parse(event)
    assert len(result.relationships) == 0


@pytest.mark.asyncio
async def test_dnstwist_parser_empty_returns_unparseable():
    parser = DnstwistParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "no domain field"


@pytest.mark.asyncio
async def test_dnstwist_parser_class_attributes():
    assert DnstwistParser.source_name == "dnstwist"
    assert DnstwistParser.current_version == 1
