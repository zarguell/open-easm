from __future__ import annotations

import json
import logging
import re
import uuid

import httpx

from easm.config import TargetConfig
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

CDX_API = "http://index.commoncrawl.org/CC-MAIN-{index}-index"


def _derive_cc_urls(domain: str) -> list[str]:
    recent_indices = ["2025-13", "2025-09", "2025-05"]
    urls = []
    for idx in recent_indices:
        base = CDX_API.format(index=idx)
        urls.append(f"{base}?url=*.{domain}&output=json")
        urls.append(f"{base}?url={domain}&output=json")
    return urls


class CommonCrawlRunner(ApiRunner):
    source_name = "commoncrawl"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False
    is_api_runner = True

    def __init__(self, store, http_client: httpx.AsyncClient | None = None):
        super().__init__(store, http_client=http_client)

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        from easm.store import _compute_event_hash

        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0

        seen_urls: set[str] = set()

        for domain in target.match_rules.domains:
            cc_urls = _derive_cc_urls(domain)
            for cc_url in cc_urls:
                try:
                    resp = await http.get(cc_url)
                    if resp.status_code != 200:
                        continue
                    for line in resp.text.strip().splitlines():
                        if not line.strip():
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        url = record.get("url", "")
                        if not url or url in seen_urls:
                            continue
                        seen_urls.add(url)
                        event = {
                            "url": url,
                            "domain": domain,
                            "source": "commoncrawl",
                        }
                        event_hash = _compute_event_hash(
                            target.org_id, target.id, self.source_name, event
                        )
                        db_result = await self.store.pool.execute(
                            """INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
                               VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                               ON CONFLICT (event_hash) DO NOTHING""",
                            target.org_id, target.id, self.source_name,
                            json.dumps(event), event_hash, run_id,
                        )
                        if db_result == "INSERT 0 0":
                            deduped += 1
                        else:
                            inserted += 1
                except Exception as e:
                    errors += 1
                    logger.debug("commoncrawl: query failed for %s: %s", cc_url, e)

        if not self._http_client:
            await http.aclose()

        logger.info("commoncrawl: inserted=%d deduped=%d errors=%d", inserted, deduped, errors)
        return inserted, deduped, errors
