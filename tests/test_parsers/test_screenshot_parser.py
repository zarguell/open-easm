import pytest
from easm.parse.screenshot_parser import ScreenshotParser


@pytest.mark.asyncio
async def test_screenshot_parser_extracts_path():
    parser = ScreenshotParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "url": "https://example.com",
            "screenshot_path": "data/screenshots/example.com.png",
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "hostname"
    assert result.entities[0].value == "example.com"
    assert result.entities[0].attributes["screenshot_path"] == "data/screenshots/example.com.png"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_screenshot_parser_missing_hostname_unparseable():
    parser = ScreenshotParser()
    event = {"raw": {"screenshot_path": "data/screenshots/example.com.png"}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "missing hostname"


@pytest.mark.asyncio
async def test_screenshot_parser_missing_path_unparseable():
    parser = ScreenshotParser()
    event = {"raw": {"hostname": "example.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "missing screenshot_path"


@pytest.mark.asyncio
async def test_screenshot_parser_empty_raw_unparseable():
    parser = ScreenshotParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_screenshot_parser_class_attributes():
    assert ScreenshotParser.source_name == "screenshot"
    assert ScreenshotParser.current_version == 1


@pytest.mark.asyncio
async def test_screenshot_parser_no_relationships():
    parser = ScreenshotParser()
    event = {"raw": {"hostname": "example.com", "screenshot_path": "/tmp/test.png"}}
    result = await parser.parse(event)
    assert len(result.relationships) == 0
