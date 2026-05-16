from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class DnstwistParser(BaseParser):
    source_name = "dnstwist"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        lookalike = raw.get("domain", "").strip()
        original = raw.get("original_domain", "").strip()
        permutation_type = raw.get("type", "").strip()
        if not lookalike:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no domain field")
        normalized_lookalike = normalize_entity_value("domain", lookalike)
        entities = [EntityCandidate(
            entity_type="domain",
            value=normalized_lookalike,
            attributes={"dnstwist": {
                "permutation_type": permutation_type,
                "original_domain": original,
                "dns_records": raw.get("dns", {}),
                "is_registered": raw.get("registered", False),
            }},
        )]
        relationships = []
        if original:
            normalized_original = normalize_entity_value("domain", original)
            relationships.append(RelationshipCandidate(
                source_type="domain", source_value=normalized_lookalike,
                target_type="domain", target_value=normalized_original,
                relationship_type="lookalike_of",
                relationship_source="runner_direct",
                runner="dnstwist",
            ))
        return ParseResult(entities=entities, relationships=relationships)
