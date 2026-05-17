import pytest
from easm.parse.stackoverflow_monitor_parser import StackOverflowParser


@pytest.mark.asyncio
async def test_stackoverflow_parser_extracts_keywords():
    parser = StackOverflowParser()
    event = {
        "raw": {
            "keyword": "acme corp",
            "question_id": 12345,
            "title": "How to use acme corp API",
            "link": "https://stackoverflow.com/questions/12345/title",
            "matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
            ],
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert "12345" in findings[0].value
    assert findings[0].attributes["keyword"] == "acme corp"
    assert findings[0].attributes["source"] == "stackoverflow_monitor"


@pytest.mark.asyncio
async def test_stackoverflow_parser_missing_data_unparseable():
    parser = StackOverflowParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_stackoverflow_parser_empty_raw():
    parser = StackOverflowParser()
    event = {"raw": {"question_id": 0, "matches": []}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_stackoverflow_parser_class_attributes():
    assert StackOverflowParser.source_name == "stackoverflow_monitor"
    assert StackOverflowParser.current_version == 1


@pytest.mark.asyncio
async def test_stackoverflow_parser_multiple_matches():
    parser = StackOverflowParser()
    event = {
        "raw": {
            "keyword": "acme corp",
            "question_id": 67890,
            "title": "Multiple matches question",
            "link": "https://stackoverflow.com/questions/67890/title",
            "matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
                {"keyword": "internal.example.com", "match_type": "domain", "severity": "medium"},
            ],
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 2
    severities = {f.attributes["severity"] for f in findings}
    assert severities == {"medium"}
