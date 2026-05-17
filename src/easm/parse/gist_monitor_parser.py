from __future__ import annotations

from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class GistMonitorParser(BaseParser):
    source_name = "gist_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        gist_id = raw.get("gist_id", "")
        matches = raw.get("matches", [])

        if not gist_id or not matches:
            return ParseResult(
                entities=[], relationships=[],
                unparseable=True, parse_error="no gist_id or matches",
            )

        entities: list[EntityCandidate] = []
        for m in matches:
            finding_id = f"gist-{gist_id}-{m.get('keyword', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "keyword": m.get("keyword", ""),
                    "match_type": m.get("match_type", ""),
                    "severity": m.get("severity", "medium"),
                    "source_type": "github_gist",
                    "source_url": raw.get("gist_url", ""),
                    "filename": raw.get("filename", ""),
                    "source": "gist_monitor",
                },
            ))

        return ParseResult(entities=entities, relationships=[])
