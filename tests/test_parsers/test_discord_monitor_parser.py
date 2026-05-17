import pytest
from easm.parse.discord_monitor_parser import DiscordMonitorParser


@pytest.mark.asyncio
async def test_discord_parser_extracts_keywords():
    parser = DiscordMonitorParser()
    event = {
        "raw": {
            "channel_id": "123456",
            "channel_name": "security-alerts",
            "author": "bot_user",
            "content": "Found acme corp credentials in the log",
            "timestamp": "2024-01-15T10:30:00Z",
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
    assert "123456" in findings[0].value
    assert findings[0].attributes["keyword"] == "acme corp"
    assert findings[0].attributes["source"] == "discord_monitor"


@pytest.mark.asyncio
async def test_discord_parser_missing_data_unparseable():
    parser = DiscordMonitorParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_discord_parser_empty_raw():
    parser = DiscordMonitorParser()
    event = {"raw": {"channel_id": "", "matches": []}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_discord_parser_class_attributes():
    assert DiscordMonitorParser.source_name == "discord_monitor"
    assert DiscordMonitorParser.current_version == 1


@pytest.mark.asyncio
async def test_discord_parser_multiple_matches():
    parser = DiscordMonitorParser()
    event = {
        "raw": {
            "channel_id": "789012",
            "channel_name": "general",
            "author": "user1",
            "content": "Discussed acme corp and internal.example.com",
            "timestamp": "2024-01-15T11:00:00Z",
            "matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
                {"keyword": "internal.example.com", "match_type": "domain", "severity": "high"},
            ],
            "severity": "high",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 2
    severities = {f.attributes["severity"] for f in findings}
    assert severities == {"medium", "high"}
