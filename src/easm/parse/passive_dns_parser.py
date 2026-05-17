from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class PassiveDnsParser(BaseParser):
    source_name = "securitytrails"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        passive_dns = raw.get("passive_dns")
        if not domain or not passive_dns:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing domain or passive_dns data")
        normalized = normalize_entity_value("domain", domain)
        a_records = passive_dns.get("a_records", [])
        entities = [EntityCandidate(
            entity_type="domain", value=normalized,
            attributes={
                "source": "securitytrails",
                "dns_history": a_records,
            },
        )]
        for record in a_records:
            ip = record.get("ip", "").strip()
            if ip:
                ip_normalized = normalize_entity_value("ip", ip)
                entities.append(EntityCandidate(
                    entity_type="ip", value=ip_normalized,
                    attributes={
                        "source": "securitytrails",
                        "first_seen": record.get("first_seen", ""),
                        "last_seen": record.get("last_seen", ""),
                        "resolved_for": domain,
                    },
                ))
        return ParseResult(entities=entities, relationships=[])
