from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class DomainExtractParser(BaseParser):
    source_name = "domain_extract"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        if not domain:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="no domain field")
        normalized = normalize_entity_value("domain", domain)
        return ParseResult(
            entities=[EntityCandidate(entity_type="domain", value=normalized,
                                      attributes={"source": "domain_extract",
                                                  "source_hostname": raw.get("source_hostname", "")})],
            relationships=[],
        )
