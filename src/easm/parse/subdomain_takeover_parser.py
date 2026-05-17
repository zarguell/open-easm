from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class SubdomainTakeoverParser(BaseParser):
    source_name = "takeover"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        takeover_check = raw.get("takeover_check")
        if not hostname or not takeover_check:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing hostname or takeover_check data")
        normalized = normalize_entity_value("hostname", hostname)
        at_risk = takeover_check.get("takeover_risk", False)
        return ParseResult(entities=[EntityCandidate(
            entity_type="hostname", value=normalized,
            attributes={
                "source": "takeover",
                "takeover_risk": at_risk,
                "fingerprint_matches": takeover_check.get("fingerprint_matches", []),
            },
        )], relationships=[])
