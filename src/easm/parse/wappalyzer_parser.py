from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class WappalyzerParser(BaseParser):
    source_name = "wappalyzer"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        techs = raw.get("technologies", [])
        if not hostname:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing hostname",
            )
        normalized = normalize_entity_value("hostname", hostname)
        return ParseResult(
            entities=[EntityCandidate(
                entity_type="hostname", value=normalized,
                attributes={"source": "wappalyzer", "technologies": techs},
            )],
            relationships=[],
        )
