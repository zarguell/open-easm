from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class GeoIpParser(BaseParser):
    source_name = "geoip"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        geo = raw.get("geo")
        if not ip or not geo:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing ip or geo data")

        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="ip",
                    value=normalized_ip,
                    attributes={"source": "geoip", "geo": geo},
                ),
            ],
            relationships=[],
        )
