from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class SearchEngineParser(BaseParser):
    source_name = "searchengine"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        subdomain = raw.get("subdomain", "").strip()
        if not subdomain:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing subdomain")
        normalized = normalize_entity_value("domain", subdomain)
        return ParseResult(entities=[EntityCandidate(
            entity_type="domain", value=normalized,
            attributes={
                "source": "searchengine",
                "source_engine": raw.get("source_engine", ""),
                "discovered_from": raw.get("domain", ""),
                "url": raw.get("url", ""),
            },
        )], relationships=[])
