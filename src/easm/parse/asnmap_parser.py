from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class AsnmapParser(BaseParser):
    source_name = "asnmap"
    current_version = 2

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        asn_val = raw.get("as_number", str(raw.get("asn", ""))).strip()
        if not asn_val:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no as_number field")
        normalized_asn = normalize_entity_value("asn", asn_val)
        entities = [EntityCandidate(entity_type="asn", value=normalized_asn, attributes={
            "source": "asnmap", "as_name": raw.get("as_name", ""), "as_country": raw.get("as_country", ""),
        })]
        relationships = []
        for cidr in raw.get("as_range", []):
            if isinstance(cidr, dict):
                cidr = cidr.get("ipv4", "").strip()
            elif isinstance(cidr, str):
                cidr = cidr.strip()
            else:
                continue
            if cidr:
                rel_value = normalize_entity_value("ip_range", cidr)
                entities.append(EntityCandidate(entity_type="ip_range", value=rel_value, attributes={"source": "asnmap"}))
                relationships.append(RelationshipCandidate(
                    source_type="asn", source_value=normalized_asn,
                    target_type="ip_range", target_value=rel_value,
                    relationship_type="owns",
                    relationship_source="runner_direct",
                    runner="asnmap",
                ))
        return ParseResult(entities=entities, relationships=relationships)
