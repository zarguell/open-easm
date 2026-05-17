from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseHandler(PivotHandler):
    pivot_type = "greynoise_enrich"
    source_name = "greynoise"

    def __init__(self, api_key: str = "", http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        url = GREYNOISE_COMMUNITY_URL.format(ip=ip)
        headers = {}
        if self._api_key:
            headers["key"] = self._api_key
        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            resp = await http.get(url, headers=headers)
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no greynoise data"}]
            resp.raise_for_status()
            data = resp.json()
            return [{
                "ip": ip,
                "greynoise": {
                    "classification": data.get("classification", ""),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "name": data.get("name", ""),
                    "link": data.get("link", ""),
                },
            }]
        except Exception as e:
            logger.debug("GreyNoise lookup failed for %s: %s", ip, e)
            return [{"ip": ip, "message": f"greynoise lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
