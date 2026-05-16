import pytest
from easm.parse.certstream_parser import CertStreamParser


@pytest.mark.asyncio
async def test_certstream_parser_extracts_cn():
    parser = CertStreamParser()
    event = {
        "raw": {
            "fingerprint": "abc123",
            "cert_data": {
                "subject": {"CN": "example.com"},
                "extensions": {"subjectAltName": {"dnsNames": []}},
            },
        }
    }
    result = await parser.parse(event)
    domains = [e for e in result.entities if e.entity_type == "domain"]
    assert len(domains) == 1
    assert domains[0].value == "example.com"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_certstream_parser_extracts_san():
    parser = CertStreamParser()
    event = {
        "raw": {
            "fingerprint": "abc456",
            "cert_data": {
                "subject": {},
                "extensions": {
                    "subjectAltName": {
                        "dnsNames": ["san1.com", "san2.org"],
                    }
                },
            },
        }
    }
    result = await parser.parse(event)
    domains = [e for e in result.entities if e.entity_type == "domain"]
    assert len(domains) == 2
    assert {d.value for d in domains} == {"san1.com", "san2.org"}


@pytest.mark.asyncio
async def test_certstream_parser_creates_certificate_entity():
    parser = CertStreamParser()
    event = {
        "raw": {
            "fingerprint": "fp789",
            "cert_data": {
                "subject": {"CN": "example.com"},
                "issuer": {"O": "Test CA"},
                "not_before": "2024-01-01",
                "not_after": "2025-01-01",
                "extensions": {"subjectAltName": {"dnsNames": []}},
            },
        }
    }
    result = await parser.parse(event)
    certs = [e for e in result.entities if e.entity_type == "certificate"]
    assert len(certs) == 1
    assert certs[0].value == "fp789"
    assert certs[0].attributes["subject"]["CN"] == "example.com"
    assert certs[0].attributes["issuer"]["O"] == "Test CA"


@pytest.mark.asyncio
async def test_certstream_parser_creates_relationships():
    parser = CertStreamParser()
    event = {
        "raw": {
            "fingerprint": "fp_rel",
            "cert_data": {
                "subject": {"CN": "example.com"},
                "extensions": {"subjectAltName": {"dnsNames": []}},
            },
        }
    }
    result = await parser.parse(event)
    issued_for_rels = [r for r in result.relationships if r.relationship_type == "issued_for"]
    assert len(issued_for_rels) == 1
    assert issued_for_rels[0].source_type == "certificate"
    assert issued_for_rels[0].source_value == "fp_rel"
    assert issued_for_rels[0].target_type == "domain"
    assert issued_for_rels[0].target_value == "example.com"
    assert issued_for_rels[0].relationship_source == "runner_direct"
    assert issued_for_rels[0].runner == "certstream"

    reverse_rels = [r for r in result.relationships if r.relationship_type == "reverse_of"]
    assert len(reverse_rels) == 1
    assert reverse_rels[0].source_type == "domain"
    assert reverse_rels[0].target_type == "certificate"
    assert reverse_rels[0].relationship_source == "correlation"


@pytest.mark.asyncio
async def test_certstream_parser_empty_returns_unparseable():
    parser = CertStreamParser()
    event = {"raw": {"cert_data": {"subject": {}, "extensions": {}}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_certstream_parser_class_attributes():
    assert CertStreamParser.source_name == "certstream"
    assert CertStreamParser.current_version == 1
