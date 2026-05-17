import pytest
from easm.parse.tls_cert_parser import TlsCertParser


@pytest.mark.asyncio
async def test_tls_cert_parser_extracts_cert_entity():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "port": 443,
            "cert": {
                "subject_cn": "example.com",
                "issuer_cn": "Let's Encrypt Authority X3",
                "issuer_org": "Let's Encrypt",
                "serial_number": "0123456789abcdef",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2025-01-01T00:00:00Z",
                "fingerprint_sha256": "abc123def456",
                "san_dns_names": ["example.com", "www.example.com", "api.example.com"],
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    cert_entities = [e for e in result.entities if e.entity_type == "certificate"]
    assert len(cert_entities) == 1
    assert cert_entities[0].attributes["subject_cn"] == "example.com"
    assert cert_entities[0].attributes["issuer_cn"] == "Let's Encrypt Authority X3"
    assert cert_entities[0].attributes["san_dns_names"] == [
        "example.com", "www.example.com", "api.example.com"
    ]


@pytest.mark.asyncio
async def test_tls_cert_parser_creates_san_domain_entities():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "cert": {
                "subject_cn": "example.com",
                "fingerprint_sha256": "fp789",
                "san_dns_names": ["example.com", "api.example.com"],
            },
        }
    }
    result = await parser.parse(event)
    domain_entities = [e for e in result.entities if e.entity_type == "domain"]
    domain_values = {e.value for e in domain_entities}
    assert "example.com" in domain_values
    assert "api.example.com" in domain_values


@pytest.mark.asyncio
async def test_tls_cert_parser_creates_san_relationships():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "cert": {
                "subject_cn": "example.com",
                "fingerprint_sha256": "fp_rels",
                "san_dns_names": ["example.com", "sub.example.com"],
            },
        }
    }
    result = await parser.parse(event)
    issued_for_rels = [r for r in result.relationships if r.relationship_type == "san_contains"]
    assert len(issued_for_rels) == 2
    san_targets = {r.target_value for r in issued_for_rels}
    assert san_targets == {"example.com", "sub.example.com"}


@pytest.mark.asyncio
async def test_tls_cert_parser_empty_san():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "cert": {
                "subject_cn": "example.com",
                "fingerprint_sha256": "fp_empty_san",
                "san_dns_names": [],
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    cert_entities = [e for e in result.entities if e.entity_type == "certificate"]
    assert len(cert_entities) == 1


@pytest.mark.asyncio
async def test_tls_cert_parser_missing_cert():
    parser = TlsCertParser()
    event = {"raw": {"hostname": "example.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_tls_cert_parser_class_attributes():
    assert TlsCertParser.source_name == "tls_cert"
    assert TlsCertParser.current_version == 1
