from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class CensysParser(BaseParser):
    source_name = "censys"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        censys = raw.get("censys")
        if not ip or not censys:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing ip or censys data")
        normalized = normalize_entity_value("ip", ip)
        return ParseResult(entities=[EntityCandidate(
            entity_type="ip", value=normalized,
            attributes={
                "source": "censys",
                "services": censys.get("services", []),
                "location": censys.get("location", {}),
                "autonomous_system": censys.get("autonomous_system", {}),
                "last_updated_at": censys.get("last_updated_at", ""),
            },
        )], relationships=[])
