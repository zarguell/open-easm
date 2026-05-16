import httpx
from easm.pivot.handlers.base import PivotHandler


class DomainRdapHandler(PivotHandler):
    pivot_type = "domain_rdap"
    source_name = "rdap"

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        url = f"https://rdap.verisign.com/com/v1/domain/{domain}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
            except Exception:
                return [{"domain": domain, "message": "RDAP lookup failed"}]

        org_name = ""
        for entity in data.get("entities", []):
            for vcard in entity.get("vcardArray", []):
                if isinstance(vcard, list):
                    for item in vcard:
                        if isinstance(item, list) and len(item) >= 3 and item[0] == "fn":
                            org_name = item[3]
        return [{"domain": domain, "org": org_name, "source": "rdap"}]
