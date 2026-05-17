from __future__ import annotations

from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate


class PasteMonitorParser(BaseParser):
    source_name = "paste_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        paste_id = raw.get("id", "")
        matches = raw.get("keyword_matches", [])

        if not paste_id or not matches:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no paste id or matches")

        entities: list[EntityCandidate] = []
        for m in matches:
            finding_id = f"paste-{paste_id}-{m.get('keyword', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "keyword": m.get("keyword", ""),
                    "match_type": m.get("match_type", ""),
                    "severity": m.get("severity", "medium"),
                    "source_type": "pastebin",
                    "source_url": raw.get("scrape_url", ""),
                    "paste_title": raw.get("title", ""),
                    "paste_date": raw.get("date", ""),
                    "paste_user": raw.get("user", ""),
                    "source": "paste_monitor",
                },
            ))

        return ParseResult(entities=entities, relationships=[])
