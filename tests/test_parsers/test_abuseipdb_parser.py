import pytest
from easm.parse.abuseipdb_parser import AbuseIpDbParser


@pytest.mark.asyncio
async def test_abuseipdb_parser_extracts_attributes():
    parser = AbuseIpDbParser()
    event = {
        "raw": {
            "ip": "8.8.8.8",
            "abuseipdb": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "lastReportedAt": None,
                "usageType": "DNS",
                "hostnames": ["dns.google"],
                "domain": "google.com",
                "countryCode": "US",
                "isp": "Google LLC",
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "abuseipdb"
    ti = attrs["threat_intel"]["abuseipdb"]
    assert ti["abuseConfidenceScore"] == 0
    assert ti["totalReports"] == 0
    assert ti["isp"] == "Google LLC"


@pytest.mark.asyncio
async def test_abuseipdb_parser_missing_ip():
    parser = AbuseIpDbParser()
    event = {"raw": {"abuseipdb": {"abuseConfidenceScore": 100}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_abuseipdb_parser_missing_abuseipdb_data():
    parser = AbuseIpDbParser()
    event = {"raw": {"ip": "8.8.8.8"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_abuseipdb_parser_empty_raw():
    parser = AbuseIpDbParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_abuseipdb_parser_class_attributes():
    assert AbuseIpDbParser.source_name == "abuseipdb"
    assert AbuseIpDbParser.current_version == 1
