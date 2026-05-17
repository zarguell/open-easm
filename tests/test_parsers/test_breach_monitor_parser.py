import pytest
from easm.parse.breach_monitor_parser import BreachMonitorParser


@pytest.mark.asyncio
async def test_breach_monitor_parser_hibp_finding():
    parser = BreachMonitorParser()
    event = {
        "raw": {
            "source": "hibp",
            "email": "admin@example.com",
            "breach_name": "Adobe",
            "breach_date": "2013-10-04",
            "data_classes": ["Emails", "Passwords"],
            "domain": "adobe.com",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["breach_name"] == "Adobe"
    assert findings[0].attributes["compromised_email"] == "admin@example.com"
    assert findings[0].attributes["data_classes"] == ["Emails", "Passwords"]
    assert findings[0].attributes["severity"] == "high"


@pytest.mark.asyncio
async def test_breach_monitor_parser_dehashed_finding():
    parser = BreachMonitorParser()
    event = {
        "raw": {
            "source": "dehashed",
            "email": "admin@example.com",
            "password": "s3cret",
            "database_name": "ExampleCorp",
            "query": "domain:example.com",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["compromised_email"] == "admin@example.com"
    assert findings[0].attributes["password"] == "s3cret"


@pytest.mark.asyncio
async def test_breach_monitor_parser_no_data_returns_unparseable():
    parser = BreachMonitorParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_breach_monitor_parser_class_attributes():
    assert BreachMonitorParser.source_name == "breach_monitor"
    assert BreachMonitorParser.current_version == 1
