from __future__ import annotations

import json
import logging
import re
import uuid

import httpx

from easm.config import TargetConfig
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

DDG_HTML_URL = "https://html.duckduckgo.com/html/?q=site:{domain}"
GOOGLE_API_URL = "https://www.googleapis.com/customsearch/v1"
BING_API_URL = "https://api.bing.microsoft.com/v7.0/search"


class SearchEngineRunner(ApiRunner):
    source_name = "searchengine"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False
    is_api_runner = True

    def __init__(self, store, http_client: httpx.AsyncClient | None = None,
                 google_api_key: str = "", google_cx: str = "",
                 bing_api_key: str = ""):
        super().__init__(store, http_client=http_client)
        self._google_api_key = google_api_key
        self._google_cx = google_cx
        self._bing_api_key = bing_api_key

    async def _search_duckduckgo(self, domain: str, http: httpx.AsyncClient) -> list[dict]:
        results = []
        try:
            resp = await http.get(DDG_HTML_URL.format(domain=domain),
                headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            found_domains = set()
            for match in re.findall(r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.' + re.escape(domain) + r')', resp.text):
                if match not in found_domains:
                    found_domains.add(match)
                    results.append({"subdomain": match, "source_engine": "duckduckgo"})
        except Exception as e:
            logger.debug("searchengine: DDG search failed for %s: %s", domain, e)
        return results

    async def _search_google(self, domain: str, http: httpx.AsyncClient) -> list[dict]:
        if not self._google_api_key or not self._google_cx:
            return []
        results = []
        try:
            resp = await http.get(GOOGLE_API_URL, params={
                "key": self._google_api_key,
                "cx": self._google_cx,
                "q": f"site:{domain}",
            })
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("items", []):
                link = item.get("link", "")
                host_match = re.search(r'://([^/]+)', link)
                if host_match:
                    results.append({"url": link, "subdomain": host_match.group(1), "source_engine": "google"})
        except Exception as e:
            logger.debug("searchengine: Google search failed for %s: %s", domain, e)
        return results

    async def _search_bing(self, domain: str, http: httpx.AsyncClient) -> list[dict]:
        if not self._bing_api_key:
            return []
        results = []
        try:
            resp = await http.get(BING_API_URL, params={"q": f"site:{domain}"},
                headers={"Ocp-Apim-Subscription-Key": self._bing_api_key})
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("webPages", {}).get("value", []):
                url = item.get("url", "")
                host_match = re.search(r'://([^/]+)', url)
                if host_match:
                    results.append({"url": url, "subdomain": host_match.group(1), "source_engine": "bing"})
        except Exception as e:
            logger.debug("searchengine: Bing search failed for %s: %s", domain, e)
        return results

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        from easm.store import _compute_event_hash

        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            all_results = []
            all_results.extend(await self._search_duckduckgo(domain, http))
            all_results.extend(await self._search_google(domain, http))
            all_results.extend(await self._search_bing(domain, http))

            for result in all_results:
                try:
                    event = {"domain": domain, **result}
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
                    logger.debug("searchengine: insert error: %s", e)

        if not self._http_client:
            await http.aclose()

        logger.info("searchengine: inserted=%d deduped=%d errors=%d", inserted, deduped, errors)
        return inserted, deduped, errors
