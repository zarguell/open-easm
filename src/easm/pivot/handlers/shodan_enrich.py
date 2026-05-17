from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

SHODAN_API_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_FREE_URL = "https://internetdb.shodan.io/{ip}"


class ShodanEnrichHandler(PivotHandler):
    pivot_type = "shodan_enrich"
    source_name = "shodan"

    def __init__(self, api_key: str = "", http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            if self._api_key:
                resp = await http.get(SHODAN_API_URL.format(ip=ip), params={"key": self._api_key})
                if resp.status_code == 404:
                    return [{"ip": ip, "message": "no shodan data"}]
                resp.raise_for_status()
                data = resp.json()
                return [{"ip": ip, "shodan": {
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                    "vulns": data.get("vulns", []),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "asn": data.get("asn", ""),
                    "country_name": data.get("country_name", ""),
                    "city": data.get("city", ""),
                    "os": data.get("os", ""),
                    "data": data.get("data", []),
                }}]
            else:
                resp = await http.get(SHODAN_FREE_URL.format(ip=ip))
                if resp.status_code == 404:
                    return [{"ip": ip, "message": "no shodan data"}]
                resp.raise_for_status()
                data = resp.json()
                return [{"ip": ip, "ports": data.get("ports", []),
                         "hostnames": data.get("hostnames", []),
                         "cpes": data.get("cpes", []),
                         "vulns": data.get("vulns", []),
                         "source": "shodan"}]
        except Exception as e:
            logger.debug("Shodan lookup failed for %s: %s", ip, e)
            return [{"ip": ip, "message": f"shodan lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
