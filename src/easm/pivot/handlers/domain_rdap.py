from __future__ import annotations

import logging
from typing import Any

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)


class DomainRdapHandler(PivotHandler):
    pivot_type = "domain_rdap"
    source_name = "domain_rdap"

    _RDAP_BOOTSTRAP: dict[str, str] = {
        "com": "https://rdap.verisign.com/com/v1",
        "net": "https://rdap.verisign.com/net/v1",
        "org": "https://rdap.org",
    }

    def _rdap_url(self, domain: str) -> str:
        parts = domain.rsplit(".", 1)
        tld = parts[-1].lower() if len(parts) > 1 else ""
        base = self._RDAP_BOOTSTRAP.get(tld, "https://rdap.org")
        return f"{base}/domain/{domain}"

    def _extract_vcard_fn(self, entities: list[dict]) -> str:
        for entity in entities:
            vcard_arr = entity.get("vcardArray", [])
            if isinstance(vcard_arr, list) and len(vcard_arr) >= 2:
                for item in vcard_arr[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
        return ""

    def _extract_events(self, data: dict) -> dict[str, str]:
        events: dict[str, str] = {}
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action and date:
                events[action] = date
        return events

    async def execute(self, job: dict, pool) -> list[dict[str, Any]]:
        domain = job["entity_value"]
        url = self._rdap_url(domain)

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.debug("RDAP lookup failed for %s: %s", domain, e)
                return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]

        result: dict[str, Any] = {"domain": domain, "source": "domain_rdap"}

        if data.get("status"):
            result["status"] = data["status"]

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                result["registrar"] = self._extract_vcard_fn([entity])
            if "registrant" in roles:
                result["registrant_org"] = self._extract_vcard_fn([entity])

        if not result.get("registrant_org"):
            org = self._extract_vcard_fn(data.get("entities", []))
            if org:
                result["registrant_org"] = org

        events = self._extract_events(data)
        if events.get("registration"):
            result["created_date"] = events["registration"]
        if events.get("expiration"):
            result["expiration_date"] = events["expiration"]
        if events.get("last changed"):
            result["updated_date"] = events["last changed"]

        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
        if nameservers:
            result["nameservers"] = nameservers

        return [result]
