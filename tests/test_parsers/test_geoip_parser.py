import pytest
from easm.parse.geoip_parser import GeoIpParser


@pytest.mark.asyncio
async def test_geoip_parser_adds_geo_attributes():
    parser = GeoIpParser()
    event = {
        "raw": {
            "ip": "8.8.8.8",
            "geo": {
                "city": "Mountain View",
                "country_code": "US",
                "country_name": "United States",
                "latitude": 37.386,
                "longitude": -122.0838,
                "asn": None,
                "asn_org": None,
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    assert result.entities[0].attributes["geo"]["city"] == "Mountain View"
    assert result.entities[0].attributes["geo"]["latitude"] == 37.386


@pytest.mark.asyncio
async def test_geoip_parser_missing_ip():
    parser = GeoIpParser()
    event = {"raw": {"geo": {"city": "Test"}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_geoip_parser_missing_geo():
    parser = GeoIpParser()
    event = {"raw": {"ip": "8.8.8.8"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_geoip_parser_class_attributes():
    assert GeoIpParser.source_name == "geoip"
    assert GeoIpParser.current_version == 1
