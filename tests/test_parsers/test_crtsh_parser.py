import pytest
from easm.parse.crtsh_parser import CrtShParser


@pytest.mark.asyncio
async def test_crtsh_parser_extracts_names():
    parser = CrtShParser()
    event = {
        "raw": {
            "fingerprint": "fp123",
            "issuer_name_id": "issuer_1",
            "not_before": "2024-01-01",
            "not_after": "2025-01-01",
            "name_value": "example.com\nsub.example.com",
        }
    }
    result = await parser.parse(event)
    domains = [e for e in result.entities if e.entity_type == "domain"]
    assert len(domains) == 2
    assert {d.value for d in domains} == {"example.com", "sub.example.com"}
    assert not result.unparseable


@pytest.mark.asyncio
async def test_crtsh_parser_creates_certificate_entity():
    parser = CrtShParser()
    event = {
        "raw": {
            "fingerprint": "fp456",
            "issuer_name_id": "issuer_2",
            "not_before": "2024-06-01",
            "not_after": "2025-06-01",
            "name_value": "test.com",
        }
    }
    result = await parser.parse(event)
    certs = [e for e in result.entities if e.entity_type == "certificate"]
    assert len(certs) == 1
    assert certs[0].value == "fp456"
    assert certs[0].attributes["issuer_name_id"] == "issuer_2"


@pytest.mark.asyncio
async def test_crtsh_parser_creates_relationships():
    parser = CrtShParser()
    event = {
        "raw": {
            "fingerprint": "fp_rel",
            "name_value": "example.com",
        }
    }
    result = await parser.parse(event)
    issued_for_rels = [r for r in result.relationships if r.relationship_type == "issued_for"]
    assert len(issued_for_rels) == 1
    assert issued_for_rels[0].source_type == "certificate"
    assert issued_for_rels[0].target_value == "example.com"
    assert issued_for_rels[0].relationship_source == "runner_direct"
    assert issued_for_rels[0].runner == "crtsh"

    reverse_rels = [r for r in result.relationships if r.relationship_type == "reverse_of"]
    assert len(reverse_rels) == 1
    assert reverse_rels[0].source_type == "domain"
    assert reverse_rels[0].target_type == "certificate"
    assert reverse_rels[0].relationship_source == "correlation"


@pytest.mark.asyncio
async def test_crtsh_parser_empty_returns_unparseable():
    parser = CrtShParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_crtsh_parser_missing_name_value_returns_unparseable():
    parser = CrtShParser()
    event = {"raw": {"serial_number": "123"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_crtsh_parser_class_attributes():
    assert CrtShParser.source_name == "crtsh"
    assert CrtShParser.current_version == 1
