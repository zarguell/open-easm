from __future__ import annotations

from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class StackOverflowParser(BaseParser):
    source_name = "stackoverflow_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        question_id = raw.get("question_id", 0)
        matches = raw.get("matches", [])

        if not question_id or not matches:
            return ParseResult(
                entities=[], relationships=[],
                unparseable=True, parse_error="no question_id or matches",
            )

        entities: list[EntityCandidate] = []
        for m in matches:
            finding_id = f"so-{question_id}-{m.get('keyword', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "keyword": m.get("keyword", ""),
                    "match_type": m.get("match_type", ""),
                    "severity": m.get("severity", "medium"),
                    "source_type": "stackoverflow",
                    "source_url": raw.get("link", ""),
                    "question_title": raw.get("title", ""),
                    "searched_keyword": raw.get("keyword", ""),
                    "source": "stackoverflow_monitor",
                },
            ))

        return ParseResult(entities=entities, relationships=[])
