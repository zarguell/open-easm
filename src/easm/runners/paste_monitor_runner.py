from __future__ import annotations

import json
import logging
import uuid

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

PASTEBIN_SCRAPE_URL = "https://scrape.pastebin.com/api_scraping.php?limit=100"


class PasteMonitorRunner(ApiRunner):
    source_name = "paste_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        sources: list[str] = cfg.get("sources", ["pastebin"])
        max_pastes: int = cfg.get("max_pastes_per_run", 100)
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0

        kw_engine = KeywordEngine(target)

        try:
            if "pastebin" in sources:
                ins, ded, err = await self._poll_pastebin(http, kw_engine, target, run_id, max_pastes)
                inserted += ins
                deduped += ded
                errors += err
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors

    async def _poll_pastebin(
        self,
        http: httpx.AsyncClient,
        kw_engine: KeywordEngine,
        target: TargetConfig,
        run_id: uuid.UUID,
        max_pastes: int,
    ) -> tuple[int, int, int]:
        inserted = deduped = errors = 0

        try:
            resp = await http.get(PASTEBIN_SCRAPE_URL)
            if resp.status_code != 200:
                logger.warning("pastebin API returned %d", resp.status_code)
                return 0, 0, 0
            pastes = resp.json()
        except Exception as e:
            logger.warning("pastebin scrape failed: %s", e)
            return 0, 0, 1

        for paste in pastes[:max_pastes]:
            try:
                raw = {
                    "id": paste.get("id", ""),
                    "title": paste.get("title", ""),
                    "user": paste.get("user", ""),
                    "date": paste.get("date", ""),
                    "size": paste.get("size", 0),
                    "scrape_url": paste.get("scrape_url", ""),
                }

                scrape_url = paste.get("scrape_url", "")
                if scrape_url:
                    try:
                        content_resp = await http.get(scrape_url)
                        if content_resp.status_code == 200:
                            content = content_resp.text
                            raw["content_length"] = len(content)
                            matches = kw_engine.match(content)
                            raw["keyword_matches"] = [
                                {"keyword": m.keyword, "match_type": m.match_type, "severity": m.severity}
                                for m in matches
                            ]

                            if not matches:
                                continue
                        else:
                            raw["fetch_error"] = f"HTTP {content_resp.status_code}"
                    except Exception as e:
                        raw["fetch_error"] = str(e)

                result = await self.store.insert_raw_event(
                    target.org_id, target.id, self.source_name, raw, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("paste processing error: %s", e)

        return inserted, deduped, errors
