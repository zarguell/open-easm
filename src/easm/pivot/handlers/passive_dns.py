from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

ST_API = "https://api.securitytrails.com/v1/history/{domain}/dns/a"


class PassiveDnsHandler(PivotHandler):
    pivot_type = "passive_dns"
    source_name = "securitytrails"

    def __init__(self, api_key: str = "", http_client=None):
        self._api_key = api_key
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        if not self._api_key:
            return [{"domain": domain, "message": "no securitytrails api key"}]
        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            resp = await http.get(ST_API.format(domain=domain),
                headers={"APIKEY": self._api_key})
            if resp.status_code == 404:
                return [{"domain": domain, "message": "no dns history"}]
            resp.raise_for_status()
            data = resp.json()
            records = data.get("records", [])
            return [{"domain": domain, "passive_dns": {
                "a_records": [{"ip": r.get("values", [{}])[0].get("ip", ""),
                    "first_seen": r.get("first_seen", ""),
                    "last_seen": r.get("last_seen", "")}
                    for r in records],
            }}]
        except Exception as e:
            logger.debug("Passive DNS failed for %s: %s", domain, e)
            return [{"domain": domain, "message": f"passive dns failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
