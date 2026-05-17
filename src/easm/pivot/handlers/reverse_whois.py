from __future__ import annotations

import logging
import re

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

REVERSEWHOIS_URL = "https://reversewhois.io/?searchterm={domain}"


class ReverseWhoisHandler(PivotHandler):
    pivot_type = "reverse_whois"
    source_name = "reverse_whois"

    def __init__(self, http_client=None):
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        try:
            resp = await http.get(REVERSEWHOIS_URL.format(domain=domain),
                headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            # Simple regex extraction from HTML
            domains = re.findall(r'<a[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})</a>', resp.text)
            registrars = re.findall(r'(\d{4}-\d{2}-\d{2})', resp.text)
            return [{"domain": domain, "reverse_whois": {
                "related_domains": list(set(domains)),
                "dates_found": registrars,
            }}]
        except Exception as e:
            logger.debug("Reverse WHOIS failed for %s: %s", domain, e)
            return [{"domain": domain, "message": f"reverse whois failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
