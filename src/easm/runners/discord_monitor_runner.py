from __future__ import annotations

import logging
import uuid

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)


class DiscordMonitorRunner(ApiRunner):
    source_name = "discord_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    def __init__(self, store, http_client=None):
        super().__init__(store, http_client=http_client)
        self._pending_messages: list[dict] = []

    def add_message(
        self,
        channel_id: str,
        channel_name: str,
        author: str,
        content: str,
        timestamp: str,
    ) -> None:
        self._pending_messages.append({
            "channel_id": channel_id,
            "channel_name": channel_name,
            "author": author,
            "content": content,
            "timestamp": timestamp,
        })

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        kw_engine = KeywordEngine(target)
        inserted = deduped = errors = 0

        messages = list(self._pending_messages)
        self._pending_messages.clear()

        for msg in messages:
            try:
                content = msg.get("content", "")
                if not content:
                    continue

                matches = kw_engine.match(content)
                if not matches:
                    continue

                max_severity = "low"
                for m in matches:
                    if m.severity == "high":
                        max_severity = "high"
                    elif m.severity == "medium" and max_severity != "high":
                        max_severity = "medium"

                raw = {
                    "channel_id": msg.get("channel_id", ""),
                    "channel_name": msg.get("channel_name", ""),
                    "author": msg.get("author", ""),
                    "content": content,
                    "timestamp": msg.get("timestamp", ""),
                    "matches": [
                        {
                            "keyword": m.keyword,
                            "match_type": m.match_type,
                            "severity": m.severity,
                        }
                        for m in matches
                    ],
                    "severity": max_severity,
                }

                result = await self.store.insert_raw_event(
                    target.org_id, target.id, self.source_name, raw, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("discord message processing error: %s", e)

        return inserted, deduped, errors
