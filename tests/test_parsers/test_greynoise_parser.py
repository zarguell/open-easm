import pytest
from easm.parse.greynoise_parser import GreyNoiseParser


@pytest.mark.asyncio
async def test_greynoise_parser_extracts_attributes():
    parser = GreyNoiseParser()
    event = {
        "raw": {
            "ip": "8.8.8.8",
            "greynoise": {
                "classification": "malicious",
                "noise": True,
                "riot": False,
                "name": "Google DNS",
                "link": "https://viz.greynoise.io/ip/8.8.8.8",
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "greynoise"
    assert attrs["threat_intel"]["greynoise"]["classification"] == "malicious"
    assert attrs["threat_intel"]["greynoise"]["noise"] is True


@pytest.mark.asyncio
async def test_greynoise_parser_missing_ip():
    parser = GreyNoiseParser()
    event = {"raw": {"greynoise": {"classification": "benign"}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_greynoise_parser_missing_greynoise_data():
    parser = GreyNoiseParser()
    event = {"raw": {"ip": "8.8.8.8"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_greynoise_parser_empty_raw():
    parser = GreyNoiseParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_greynoise_parser_class_attributes():
    assert GreyNoiseParser.source_name == "greynoise"
    assert GreyNoiseParser.current_version == 1
