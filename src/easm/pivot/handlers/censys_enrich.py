from __future__ import annotations

import base64
import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

CENSYS_HOST_API = "https://search.censys.io/api/v2/hosts/{ip}"


class CensysEnrichHandler(PivotHandler):
    pivot_type = "censys_enrich"
    source_name = "censys"

    def __init__(self, api_id: str = "", api_secret: str = "", http_client=None):
        self._api_id = api_id
        self._api_secret = api_secret
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        if not self._api_id or not self._api_secret:
            return [{"ip": ip, "message": "censys API credentials not configured"}]
        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            auth = base64.b64encode(f"{self._api_id}:{self._api_secret}".encode()).decode()
            resp = await http.get(CENSYS_HOST_API.format(ip=ip),
                headers={"Authorization": f"Basic {auth}"})
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no censys data"}]
            resp.raise_for_status()
            data = resp.json().get("result", {})
            return [{"ip": ip, "censys": {
                "services": data.get("services", []),
                "location": data.get("location", {}),
                "autonomous_system": data.get("autonomous_system", {}),
                "last_updated_at": data.get("last_updated_at", ""),
            }}]
        except Exception as e:
            logger.debug("Censys lookup failed for %s: %s", ip, e)
            return [{"ip": ip, "message": f"censys lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
