import httpx
from easm.pivot.handlers.base import PivotHandler


class ShodanEnrichHandler(PivotHandler):
    pivot_type = "shodan_enrich"
    source_name = "shodan"

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        url = f"https://internetdb.shodan.io/{ip}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no shodan data"}]
            resp.raise_for_status()
            data = resp.json()
        return [{"ip": ip, "ports": data.get("ports", []), "hostnames": data.get("hostnames", []),
                  "cpes": data.get("cpes", []), "vulns": data.get("vulns", []), "source": "shodan"}]
