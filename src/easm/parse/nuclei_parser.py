from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class NucleiParser(BaseParser):
    source_name = "nuclei"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        if not hostname or "template-id" not in raw:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing hostname or nuclei data",
            )
        normalized = normalize_entity_value("hostname", hostname)
        return ParseResult(
            entities=[EntityCandidate(
                entity_type="hostname", value=normalized,
                attributes={
                    "source": "nuclei",
                    "vulnerability": {
                        "template_id": raw.get("template-id", ""),
                        "name": raw.get("info", {}).get("name", ""),
                        "severity": raw.get("info", {}).get("severity", "unknown"),
                        "description": raw.get("info", {}).get("description", ""),
                        "matched_at": raw.get("matched-at", ""),
                        "curl_command": raw.get("curl-command", ""),
                    },
                },
            )],
            relationships=[],
        )
