import pytest
from easm.parse.wappalyzer_parser import WappalyzerParser


@pytest.mark.asyncio
async def test_wappalyzer_parser_extracts_technologies():
    parser = WappalyzerParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "url": "https://example.com",
            "technologies": [
                {"name": "nginx", "version": "1.24.0", "categories": ["Web Servers"], "confidence": 100},
                {"name": "React", "version": "", "categories": ["JavaScript Frameworks"], "confidence": 90},
            ],
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "hostname"
    assert result.entities[0].value == "example.com"
    assert len(result.entities[0].attributes["technologies"]) == 2
    assert result.entities[0].attributes["technologies"][0]["name"] == "nginx"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_wappalyzer_parser_missing_hostname_unparseable():
    parser = WappalyzerParser()
    event = {"raw": {"url": "https://example.com", "technologies": []}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "missing hostname"


@pytest.mark.asyncio
async def test_wappalyzer_parser_empty_raw_unparseable():
    parser = WappalyzerParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_wappalyzer_parser_class_attributes():
    assert WappalyzerParser.source_name == "wappalyzer"
    assert WappalyzerParser.current_version == 1


@pytest.mark.asyncio
async def test_wappalyzer_parser_multiple_technologies():
    parser = WappalyzerParser()
    event = {
        "raw": {
            "hostname": "shop.example.com",
            "technologies": [
                {"name": "nginx", "version": "1.24.0", "categories": ["Web Servers"], "confidence": 100},
                {"name": "jQuery", "version": "3.6.0", "categories": ["JavaScript Libraries"], "confidence": 100},
                {"name": "WordPress", "version": "6.4", "categories": ["CMS"], "confidence": 100},
            ],
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert len(result.entities[0].attributes["technologies"]) == 3


@pytest.mark.asyncio
async def test_wappalyzer_parser_no_relationships():
    parser = WappalyzerParser()
    event = {"raw": {"hostname": "example.com", "technologies": [{"name": "nginx"}]}}
    result = await parser.parse(event)
    assert len(result.relationships) == 0
