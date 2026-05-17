import pytest
from easm.parse.gist_monitor_parser import GistMonitorParser


@pytest.mark.asyncio
async def test_gist_monitor_parser_extracts_keywords():
    parser = GistMonitorParser()
    event = {
        "raw": {
            "gist_id": "abc123def",
            "gist_url": "https://gist.github.com/abc123def",
            "filename": "config.yml",
            "matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
            ],
            "severity": "medium",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert "abc123def" in findings[0].value
    assert findings[0].attributes["keyword"] == "acme corp"
    assert findings[0].attributes["source"] == "gist_monitor"


@pytest.mark.asyncio
async def test_gist_monitor_parser_missing_data_unparseable():
    parser = GistMonitorParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_gist_monitor_parser_empty_raw():
    parser = GistMonitorParser()
    event = {"raw": {"gist_id": "", "matches": []}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_gist_monitor_parser_class_attributes():
    assert GistMonitorParser.source_name == "gist_monitor"
    assert GistMonitorParser.current_version == 1


@pytest.mark.asyncio
async def test_gist_monitor_parser_multiple_matches():
    parser = GistMonitorParser()
    event = {
        "raw": {
            "gist_id": "xyz789",
            "gist_url": "https://gist.github.com/xyz789",
            "filename": "leak.txt",
            "matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
                {"keyword": "secret project", "match_type": "exact", "severity": "high"},
                {"keyword": "internal.example.com", "match_type": "domain", "severity": "medium"},
            ],
            "severity": "high",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 3
    severities = {f.attributes["severity"] for f in findings}
    assert severities == {"medium", "high"}
