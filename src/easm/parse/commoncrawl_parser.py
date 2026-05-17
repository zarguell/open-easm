import re

from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class CommonCrawlParser(BaseParser):
    source_name = "commoncrawl"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        url = raw.get("url", "").strip()
        if not url:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing url")
        subdomain = self._extract_subdomain(url)
        if not subdomain:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="could not extract domain from url")
        normalized = normalize_entity_value("domain", subdomain)
        return ParseResult(entities=[EntityCandidate(
            entity_type="domain", value=normalized,
            attributes={
                "source": "commoncrawl",
                "url": url,
                "discovered_from": raw.get("domain", ""),
            },
        )], relationships=[])

    @staticmethod
    def _extract_subdomain(url: str) -> str:
        host_match = re.search(r'://([^/]+)', url)
        if not host_match:
            return ""
        host = host_match.group(1).split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
