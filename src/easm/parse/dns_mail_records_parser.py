from easm.mail_provider import classify_mail_provider
from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class DnsMailRecordsParser(BaseParser):
    source_name = "dns_mail_records"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        if not domain:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing domain")

        normalized_domain = normalize_entity_value("domain", domain)
        mx_records = raw.get("mx_records", [])
        spf_record = raw.get("spf_record", "")
        dmarc_record = raw.get("dmarc_record", "")

        entities: list[EntityCandidate] = []
        relationships: list[RelationshipCandidate] = []

        domain_attrs: dict = {
            "source": "dns_mail_records",
            "mx_records": mx_records,
        }
        if spf_record:
            domain_attrs["spf_record"] = spf_record
        if dmarc_record:
            domain_attrs["dmarc_record"] = dmarc_record

        mail_provider = classify_mail_provider(
            mx_records=mx_records,
            spf_record=spf_record,
        )
        domain_attrs["mail_provider"] = mail_provider

        entities.append(EntityCandidate(
            entity_type="domain",
            value=normalized_domain,
            attributes=domain_attrs,
        ))

        for mx in mx_records:
            exchange = mx.get("exchange", "").strip()
            if not exchange:
                continue
            normalized_exchange = normalize_entity_value("hostname", exchange)
            entities.append(EntityCandidate(
                entity_type="hostname",
                value=normalized_exchange,
                attributes={
                    "source": "dns_mail_records",
                    "mx_for": normalized_domain,
                },
            ))
            relationships.append(RelationshipCandidate(
                source_type="domain",
                source_value=normalized_domain,
                target_type="hostname",
                target_value=normalized_exchange,
                relationship_type="mail_handled_by",
                relationship_source="pivot",
                runner="dns_mail_records",
            ))

        return ParseResult(entities=entities, relationships=relationships)
