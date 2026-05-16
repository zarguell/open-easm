import httpx
from easm.pivot.handlers.base import PivotHandler


class CrtShSearchHandler(PivotHandler):
    pivot_type = "crtsh_search"
    source_name = "crtsh"

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            certs = resp.json()
        results = []
        for cert in certs:
            results.append({
                "name_value": cert.get("name_value", ""),
                "issuer_name_id": cert.get("issuer_name_id", ""),
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
                "serial_number": cert.get("serial_number", ""),
                "fingerprint": cert.get("fingerprint", ""),
            })
        return results
