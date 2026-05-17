from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpDbHandler(PivotHandler):
    pivot_type = "abuseipdb_enrich"
    source_name = "abuseipdb"

    def __init__(self, api_key: str = "", http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        if not self._api_key:
            return [{"ip": ip, "message": "no abuseipdb api key configured"}]

        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            resp = await http.get(
                ABUSEIPDB_API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no abuseipdb data"}]
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return [{
                "ip": ip,
                "abuseipdb": {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "totalReports": data.get("totalReports"),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "usageType": data.get("usageType", ""),
                    "hostnames": data.get("hostnames", []),
                    "domain": data.get("domain", ""),
                    "countryCode": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                },
            }]
        except Exception as e:
            logger.debug("AbuseIPDB lookup failed for %s: %s", ip, e)
            return [{"ip": ip, "message": f"abuseipdb lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
