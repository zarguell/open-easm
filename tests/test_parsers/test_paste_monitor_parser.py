import pytest
from easm.parse.paste_monitor_parser import PasteMonitorParser


@pytest.mark.asyncio
async def test_paste_monitor_parser_extracts_finding():
    parser = PasteMonitorParser()
    event = {
        "raw": {
            "id": "abc123",
            "title": "config dump",
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=abc123",
            "keyword_matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
            ],
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].value.startswith("paste-abc123")
    assert findings[0].attributes["keyword"] == "acme corp"
    assert findings[0].attributes["source_url"] == "https://scrape.pastebin.com/api_scrape_item.php?i=abc123"
    assert findings[0].attributes["source_type"] == "pastebin"
    assert findings[0].attributes["severity"] == "medium"


@pytest.mark.asyncio
async def test_paste_monitor_parser_multiple_keywords():
    parser = PasteMonitorParser()
    event = {
        "raw": {
            "id": "def456",
            "title": "leak",
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=def456",
            "keyword_matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
                {"keyword": "secret project", "match_type": "exact", "severity": "high"},
            ],
        }
    }
    result = await parser.parse(event)
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 2
    severities = {f.attributes["severity"] for f in findings}
    assert severities == {"medium", "high"}


@pytest.mark.asyncio
async def test_paste_monitor_parser_no_matches_returns_unparseable():
    parser = PasteMonitorParser()
    event = {"raw": {"id": "x1", "scrape_url": "http://x"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_paste_monitor_parser_class_attributes():
    assert PasteMonitorParser.source_name == "paste_monitor"
    assert PasteMonitorParser.current_version == 1


@pytest.mark.asyncio
async def test_paste_monitor_parser_empty_raw():
    parser = PasteMonitorParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True
