from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


class UrlScanHandler(PivotHandler):
    pivot_type = "urlscan_enrich"
    source_name = "urlscan"

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        try:
            resp = await http.get(
                URLSCAN_SEARCH_URL,
                params={"q": f"domain:{domain}", "size": 100},
            )
            if resp.status_code == 404:
                return [{"domain": domain, "message": "no urlscan data"}]
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            return [{
                "domain": domain,
                "urlscan": {
                    "total_results": data.get("total", 0),
                    "results": [
                        {
                            "page_url": r.get("page", {}).get("url", ""),
                            "ip": r.get("page", {}).get("ip", ""),
                            "domain": r.get("page", {}).get("domain", ""),
                            "is_malicious": r.get("isMalicious", False),
                            "screenshot_url": r.get("screenshot", ""),
                        }
                        for r in results
                    ],
                },
            }]
        except Exception as e:
            logger.debug("URLScan lookup failed for %s: %s", domain, e)
            return [{"domain": domain, "message": f"urlscan lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
