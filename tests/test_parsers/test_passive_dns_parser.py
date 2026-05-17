import pytest
from easm.parse.passive_dns_parser import PassiveDnsParser


@pytest.mark.asyncio
async def test_passive_dns_parser_extracts_ip_records():
    parser = PassiveDnsParser()
    result = await parser.parse({"raw": {
        "domain": "example.com",
        "passive_dns": {
            "a_records": [
                {"ip": "1.2.3.4", "first_seen": "2024-01-01", "last_seen": "2024-06-01"},
                {"ip": "5.6.7.8", "first_seen": "2024-02-01", "last_seen": "2024-07-01"},
            ],
        },
    }})
    assert not result.unparseable
    assert len(result.entities) == 3
    assert result.entities[0].entity_type == "domain"
    assert result.entities[1].entity_type == "ip"
    assert result.entities[1].value == "1.2.3.4"
    assert result.entities[2].value == "5.6.7.8"


@pytest.mark.asyncio
async def test_passive_dns_parser_missing_domain():
    parser = PassiveDnsParser()
    result = await parser.parse({"raw": {"passive_dns": {"a_records": []}}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_passive_dns_parser_missing_passive_dns_data():
    parser = PassiveDnsParser()
    result = await parser.parse({"raw": {"domain": "example.com"}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_passive_dns_parser_empty_raw():
    parser = PassiveDnsParser()
    result = await parser.parse({"raw": {}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_passive_dns_parser_class_attributes():
    assert PassiveDnsParser.source_name == "securitytrails"
    assert PassiveDnsParser.current_version == 1
