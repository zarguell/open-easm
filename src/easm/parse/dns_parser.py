from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class DnsParser(BaseParser):
    source_name = "dns"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        ip = raw.get("ip", "").strip()
        if not hostname or not ip:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing hostname or ip")
        normalized_hostname = normalize_entity_value("hostname", hostname)
        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(entity_type="hostname", value=normalized_hostname,
                                attributes={"source": "dns", "record_type": raw.get("record_type", "A")}),
                EntityCandidate(entity_type="ip", value=normalized_ip,
                                attributes={"source": "dns"}),
            ],
            relationships=[
                RelationshipCandidate(
                    source_type="hostname", source_value=normalized_hostname,
                    target_type="ip", target_value=normalized_ip,
                    relationship_type="resolves_to",
                    relationship_source="pivot",
                    runner="dns",
                ),
                RelationshipCandidate(
                    source_type="ip", source_value=normalized_ip,
                    target_type="hostname", target_value=normalized_hostname,
                    relationship_type="reverse_of",
                    relationship_source="correlation",
                ),
            ],
        )
