import pytest
from easm.parse.reverse_whois_parser import ReverseWhoisParser


@pytest.mark.asyncio
async def test_reverse_whois_parser_extracts_related_domains():
    parser = ReverseWhoisParser()
    result = await parser.parse({"raw": {
        "domain": "example.com",
        "reverse_whois": {
            "related_domains": ["other.com", "another.org"],
            "dates_found": ["2025-01-01"],
        },
    }})
    assert not result.unparseable
    assert len(result.entities) == 3
    attrs = result.entities[0].attributes
    assert attrs["source"] == "reverse_whois"
    assert "other.com" in attrs["related_domains"]


@pytest.mark.asyncio
async def test_reverse_whois_parser_missing_domain():
    parser = ReverseWhoisParser()
    result = await parser.parse({"raw": {"reverse_whois": {"related_domains": []}}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_reverse_whois_parser_missing_reverse_whois_data():
    parser = ReverseWhoisParser()
    result = await parser.parse({"raw": {"domain": "example.com"}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_reverse_whois_parser_empty_raw():
    parser = ReverseWhoisParser()
    result = await parser.parse({"raw": {}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_reverse_whois_parser_class_attributes():
    assert ReverseWhoisParser.source_name == "reverse_whois"
    assert ReverseWhoisParser.current_version == 1
