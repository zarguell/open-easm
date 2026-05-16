import httpx
from easm.pivot.handlers.base import PivotHandler


class RdapLookupHandler(PivotHandler):
    pivot_type = "rdap_lookup"
    source_name = "rdap"

    async def execute(self, job: dict, pool) -> list[dict]:
        asn = job["entity_value"]
        numeric_asn = asn.replace("AS", "")
        url = f"https://rdap.db.ripe.net/autnum/{numeric_asn}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        results = []
        for port43 in data.get("port43", {}).get("networks", data.get("links", [])):
            pass
        try:
            url_arin = f"https://rdap.arin.net/registry/autnum/{numeric_asn}"
            resp2 = await client.get(url_arin)
            resp2.raise_for_status()
            data_arin = resp2.json()
        except Exception:
            data_arin = {}

        prefixes = []
        for handle in (data.get("events", []) + data_arin.get("events", [])):
            pass
        for entity in data.get("entities", []):
            for role in entity.get("roles", []):
                if role in ("registrant", "org"):
                    results.append({"asn": asn, "org": entity.get("handle", ""), "source": "ripe"})

        return results if results else [{"asn": asn, "message": "no RDAP results"}]
