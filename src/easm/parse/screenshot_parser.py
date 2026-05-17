from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class ScreenshotParser(BaseParser):
    source_name = "screenshot"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        screenshot_path = raw.get("screenshot_path", "")
        if not hostname:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing hostname",
            )
        if not screenshot_path:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing screenshot_path",
            )
        normalized = normalize_entity_value("hostname", hostname)
        return ParseResult(
            entities=[EntityCandidate(
                entity_type="hostname", value=normalized,
                attributes={"source": "screenshot", "screenshot_path": screenshot_path},
            )],
            relationships=[],
        )
