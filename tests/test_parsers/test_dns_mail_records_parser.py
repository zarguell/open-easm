import pytest
from easm.parse.dns_mail_records_parser import DnsMailRecordsParser


@pytest.mark.asyncio
async def test_mail_records_parser_extracts_mx():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [
                {"preference": 10, "exchange": "mail.example.com"},
                {"preference": 20, "exchange": "backup.mail.example.com"},
            ],
            "spf_record": "v=spf1 include:_spf.google.com ~all",
            "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    domain_entities = [e for e in result.entities if e.entity_type == "domain"]
    assert any(e.value == "example.com" for e in domain_entities)
    domain_ent = next(e for e in domain_entities if e.value == "example.com")
    assert domain_ent.attributes["mx_records"] == [
        {"preference": 10, "exchange": "mail.example.com"},
        {"preference": 20, "exchange": "backup.mail.example.com"},
    ]
    assert domain_ent.attributes["spf_record"] == "v=spf1 include:_spf.google.com ~all"
    assert domain_ent.attributes["dmarc_record"] == "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


@pytest.mark.asyncio
async def test_mail_records_parser_creates_mx_hostname_entities():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [{"preference": 10, "exchange": "mail.google.com"}],
        }
    }
    result = await parser.parse(event)
    hostname_entities = [e for e in result.entities if e.entity_type == "hostname"]
    assert len(hostname_entities) == 1
    assert hostname_entities[0].value == "mail.google.com"
    assert hostname_entities[0].attributes["source"] == "dns_mail_records"
    assert hostname_entities[0].attributes["mx_for"] == "example.com"


@pytest.mark.asyncio
async def test_mail_records_parser_creates_relationships():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [{"preference": 10, "exchange": "mail.example.com"}],
        }
    }
    result = await parser.parse(event)
    mx_rels = [r for r in result.relationships if r.relationship_type == "mail_handled_by"]
    assert len(mx_rels) == 1
    assert mx_rels[0].source_type == "domain"
    assert mx_rels[0].source_value == "example.com"
    assert mx_rels[0].target_type == "hostname"
    assert mx_rels[0].target_value == "mail.example.com"


@pytest.mark.asyncio
async def test_mail_records_parser_empty_records():
    parser = DnsMailRecordsParser()
    event = {"raw": {"domain": "example.com"}}
    result = await parser.parse(event)
    assert not result.unparseable
    domain_entities = [e for e in result.entities if e.entity_type == "domain"]
    assert len(domain_entities) == 1
    assert domain_entities[0].attributes.get("mx_records") == []


@pytest.mark.asyncio
async def test_mail_records_parser_missing_domain():
    parser = DnsMailRecordsParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_mail_records_parser_includes_mail_provider():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [{"preference": 10, "exchange": "smtp.google.com"}],
            "spf_record": "v=spf1 include:_spf.google.com ~all",
        }
    }
    result = await parser.parse(event)
    domain_ent = next(e for e in result.entities if e.entity_type == "domain" and e.value == "example.com")
    assert domain_ent.attributes["mail_provider"]["provider"] == "google_workspace"
    assert domain_ent.attributes["mail_provider"]["confidence"] == "high"


@pytest.mark.asyncio
async def test_mail_records_parser_class_attributes():
    assert DnsMailRecordsParser.source_name == "dns_mail_records"
    assert DnsMailRecordsParser.current_version == 1
