from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class ReverseDnsParser(BaseParser):
    source_name = "reverse_dns"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        hostname = raw.get("hostname", "").strip()
        if not ip or not hostname:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing ip or hostname")
        normalized_ip = normalize_entity_value("ip", ip)
        normalized_hostname = normalize_entity_value("hostname", hostname)
        return ParseResult(
            entities=[
                EntityCandidate(entity_type="ip", value=normalized_ip,
                                attributes={"source": "reverse_dns"}),
                EntityCandidate(entity_type="hostname", value=normalized_hostname,
                                attributes={"source": "reverse_dns"}),
            ],
            relationships=[
                RelationshipCandidate(
                    source_type="ip", source_value=normalized_ip,
                    target_type="hostname", target_value=normalized_hostname,
                    relationship_type="reverse_of",
                    relationship_source="pivot",
                    runner="reverse_dns",
                ),
            ],
        )
