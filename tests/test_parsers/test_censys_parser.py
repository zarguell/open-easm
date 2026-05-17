import pytest
from easm.parse.censys_parser import CensysParser


@pytest.mark.asyncio
async def test_censys_parser_extracts_attributes():
    parser = CensysParser()
    result = await parser.parse({"raw": {
        "ip": "8.8.8.8",
        "censys": {
            "services": [{"port": 443, "service_name": "HTTPS"}],
            "location": {"country": "United States"},
            "autonomous_system": {"asn": 15169},
            "last_updated_at": "2025-01-01",
        },
    }})
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "censys"
    assert len(attrs["services"]) == 1
    assert attrs["location"]["country"] == "United States"


@pytest.mark.asyncio
async def test_censys_parser_missing_ip():
    parser = CensysParser()
    result = await parser.parse({"raw": {"censys": {"services": []}}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_censys_parser_missing_censys_data():
    parser = CensysParser()
    result = await parser.parse({"raw": {"ip": "8.8.8.8"}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_censys_parser_empty_raw():
    parser = CensysParser()
    result = await parser.parse({"raw": {}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_censys_parser_class_attributes():
    assert CensysParser.source_name == "censys"
    assert CensysParser.current_version == 1
