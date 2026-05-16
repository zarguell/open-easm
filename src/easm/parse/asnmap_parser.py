from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class AsnmapParser(BaseParser):
    source_name = "asnmap"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        asn_val = raw.get("asn", "").strip()
        if not asn_val:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no asn field")
        normalized_asn = normalize_entity_value("asn", asn_val)
        entities = [EntityCandidate(entity_type="asn", value=normalized_asn, attributes={"source": "asnmap"})]
        relationships = []
        for prefix in raw.get("prefixes", []):
            cidr = prefix.get("ipv4", "").strip()
            if cidr:
                entities.append(EntityCandidate(entity_type="ip_range", value=cidr, attributes={"source": "asnmap"}))
                rel_value = normalize_entity_value("ip_range", cidr)
                relationships.append(RelationshipCandidate(
                    source_type="asn", source_value=normalized_asn,
                    target_type="ip_range", target_value=rel_value,
                    relationship_type="owns",
                    relationship_source="runner_direct",
                    runner="asnmap",
                ))
        return ParseResult(entities=entities, relationships=relationships)
