from __future__ import annotations

import logging
import uuid

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

STACKEXCHANGE_SEARCH_URL = "https://api.stackexchange.com/2.3/search"


class StackOverflowMonitorRunner(ApiRunner):
    source_name = "stackoverflow_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        args = cfg.get("args", {})
        timeout = args.get("timeout_seconds", 60)

        http = self._http_client or httpx.AsyncClient(timeout=float(timeout))
        inserted = deduped = errors = 0

        kw_engine = KeywordEngine(target)

        try:
            keywords = target.match_rules.keywords
            if not keywords:
                return 0, 0, 0

            for keyword in keywords:
                try:
                    params = {
                        "order": "desc",
                        "sort": "activity",
                        "intitle": keyword,
                        "site": "stackoverflow",
                    }
                    resp = await http.get(STACKEXCHANGE_SEARCH_URL, params=params)
                    if resp.status_code != 200:
                        logger.warning("StackExchange API returned %d for keyword '%s'", resp.status_code, keyword)
                        errors += 1
                        continue

                    data = resp.json()
                    items = data.get("items", [])

                    for item in items:
                        try:
                            question_id = item.get("question_id", 0)
                            title = item.get("title", "")
                            link = item.get("link", "")
                            body = item.get("body", "")

                            combined_text = f"{title}\n{body}"
                            matches = kw_engine.match(combined_text)
                            if not matches:
                                continue

                            max_severity = "low"
                            for m in matches:
                                if m.severity == "high":
                                    max_severity = "high"
                                elif m.severity == "medium" and max_severity != "high":
                                    max_severity = "medium"

                            raw = {
                                "keyword": keyword,
                                "question_id": question_id,
                                "title": title,
                                "link": link,
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
                            logger.warning("stackoverflow question processing error: %s", e)

                except Exception as e:
                    errors += 1
                    logger.warning("stackoverflow keyword query failed for '%s': %s", keyword, e)
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors
