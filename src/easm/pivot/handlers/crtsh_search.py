import asyncio
import logging
import random

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRYABLE_STATUSES = (429, 502, 503, 504)


class CrtShSearchHandler(PivotHandler):
    pivot_type = "crtsh_search"
    source_name = "crtsh"

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with httpx.AsyncClient(timeout=30.0) as client:
            certs = None
            for attempt in range(MAX_RETRIES):
                resp = await client.get(url)
                if resp.status_code == 200:
                    certs = resp.json()
                    break
                if resp.status_code in RETRYABLE_STATUSES and attempt < MAX_RETRIES - 1:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except ValueError:
                            wait = (2 ** attempt) + random.uniform(0, 1)
                    else:
                        wait = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        "crtsh rate limited (status %d) for %s, retrying in %.1fs (attempt %d/%d)",
                        resp.status_code, domain, wait, attempt + 1, MAX_RETRIES,
                    )
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
            if certs is None:
                raise RuntimeError("crtsh request failed after all retries")
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
