import pytest
from easm.parse.asnmap_parser import AsnmapParser


@pytest.mark.asyncio
async def test_asnmap_parser_returns_asn_entity():
    parser = AsnmapParser()
    event = {"raw": {"asn": "AS12345", "prefixes": []}}
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "asn"
    assert result.entities[0].value == "AS12345"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_asnmap_parser_normalizes_asn():
    parser = AsnmapParser()
    event = {"raw": {"asn": "12345", "prefixes": []}}
    result = await parser.parse(event)
    assert result.entities[0].value == "AS12345"


@pytest.mark.asyncio
async def test_asnmap_parser_returns_ip_ranges_and_relationships():
    parser = AsnmapParser()
    event = {
        "raw": {
            "asn": "AS12345",
            "prefixes": [
                {"ipv4": "192.168.1.0/24"},
                {"ipv4": "10.0.0.0/8"},
            ],
        }
    }
    result = await parser.parse(event)
    asn_entity = result.entities[0]
    assert asn_entity.entity_type == "asn"
    assert asn_entity.value == "AS12345"

    ip_range_entities = [e for e in result.entities if e.entity_type == "ip_range"]
    assert len(ip_range_entities) == 2
    assert ip_range_entities[0].value == "192.168.1.0/24"
    assert ip_range_entities[1].value == "10.0.0.0/8"

    assert len(result.relationships) == 2
    rel = result.relationships[0]
    assert rel.source_type == "asn"
    assert rel.source_value == "AS12345"
    assert rel.target_type == "ip_range"
    assert rel.relationship_type == "owns"
    assert rel.relationship_source == "runner_direct"
    assert rel.runner == "asnmap"


@pytest.mark.asyncio
async def test_asnmap_parser_empty_returns_unparseable():
    parser = AsnmapParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "no asn field"


@pytest.mark.asyncio
async def test_asnmap_parser_empty_prefixes_no_relationships():
    parser = AsnmapParser()
    event = {"raw": {"asn": "AS999", "prefixes": []}}
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert len(result.relationships) == 0


@pytest.mark.asyncio
async def test_asnmap_parser_class_attributes():
    assert AsnmapParser.source_name == "asnmap"
    assert AsnmapParser.current_version == 1
