from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class ReverseWhoisParser(BaseParser):
    source_name = "reverse_whois"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        reverse_whois = raw.get("reverse_whois")
        if not domain or not reverse_whois:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing domain or reverse_whois data")
        normalized = normalize_entity_value("domain", domain)
        related = reverse_whois.get("related_domains", [])
        entities = [EntityCandidate(
            entity_type="domain", value=normalized,
            attributes={
                "source": "reverse_whois",
                "related_domains": related,
                "dates_found": reverse_whois.get("dates_found", []),
            },
        )]
        for rd in related:
            rd_normalized = normalize_entity_value("domain", rd)
            entities.append(EntityCandidate(
                entity_type="domain", value=rd_normalized,
                attributes={"source": "reverse_whois", "discovered_via": domain},
            ))
        return ParseResult(entities=entities, relationships=[])
