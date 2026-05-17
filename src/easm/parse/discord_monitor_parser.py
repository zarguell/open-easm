from __future__ import annotations

from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class DiscordMonitorParser(BaseParser):
    source_name = "discord_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        channel_id = raw.get("channel_id", "")
        matches = raw.get("matches", [])

        if not channel_id or not matches:
            return ParseResult(
                entities=[], relationships=[],
                unparseable=True, parse_error="no channel_id or matches",
            )

        entities: list[EntityCandidate] = []
        for m in matches:
            finding_id = f"discord-{channel_id}-{m.get('keyword', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "keyword": m.get("keyword", ""),
                    "match_type": m.get("match_type", ""),
                    "severity": m.get("severity", "medium"),
                    "source_type": "discord",
                    "source_url": f"https://discord.com/channels/{channel_id}",
                    "channel_name": raw.get("channel_name", ""),
                    "author": raw.get("author", ""),
                    "content": raw.get("content", ""),
                    "message_timestamp": raw.get("timestamp", ""),
                    "source": "discord_monitor",
                },
            ))

        return ParseResult(entities=entities, relationships=[])
