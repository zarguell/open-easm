from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, ParseResult, EntityCandidate


class SubfinderParser(BaseParser):
    source_name = "subfinder"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("host", "").strip()
        if not domain:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no host field")
        return ParseResult(
            entities=[EntityCandidate(entity_type="domain", value=normalize_entity_value("domain", domain), attributes={"source": "subfinder"})],
            relationships=[],
        )
