from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class GreyNoiseParser(BaseParser):
    source_name = "greynoise"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        greynoise = raw.get("greynoise")
        if not ip or not greynoise:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing ip or greynoise data",
            )

        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="ip",
                    value=normalized_ip,
                    attributes={
                        "source": "greynoise",
                        "threat_intel": {
                            "greynoise": {
                                "classification": greynoise.get("classification"),
                                "noise": greynoise.get("noise"),
                                "riot": greynoise.get("riot"),
                                "name": greynoise.get("name", ""),
                                "link": greynoise.get("link", ""),
                            }
                        },
                    },
                ),
            ],
            relationships=[],
        )
