"""Local cache for CISA KEV (Known Exploited Vulnerabilities) data.

Downloads and caches the CISA KEV JSON feed into the ``cve_cache`` table.
Provides lookup functions for matching CVEs against known-exploited vulnerabilities.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, UTC
from typing import Any

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def refresh_kev_cache(pool: Any) -> int:
    """Download CISA KEV JSON and upsert into cve_cache table.

    Returns the number of CVEs upserted.
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()

    vulnerabilities = data.get("vulnerabilities", [])
    upserted = 0
    now = datetime.now(UTC)

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        await pool.execute("""
            INSERT INTO cve_cache (cve_id, description, kev_included, kev_date_added,
                                   kev_due_date, kev_vendor, kev_product, kev_notes,
                                   last_refreshed)
            VALUES ($1, $2, TRUE, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (cve_id) DO UPDATE SET
                kev_included = TRUE,
                kev_date_added = EXCLUDED.kev_date_added,
                kev_due_date = EXCLUDED.kev_due_date,
                kev_vendor = EXCLUDED.kev_vendor,
                kev_product = EXCLUDED.kev_product,
                kev_notes = EXCLUDED.kev_notes,
                last_refreshed = EXCLUDED.last_refreshed
        """,
            cve_id,
            vuln.get("shortDescription", ""),
            _parse_date(vuln.get("dateAdded")),
            _parse_date(vuln.get("dueDate")),
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("notes", ""),
            now,
        )
        upserted += 1

    logger.info("kev cache refreshed", extra={"upserted": upserted})
    return upserted


async def lookup_kev_for_cve(pool: Any, cve_id: str) -> dict[str, Any] | None:
    """Check if a CVE is in the KEV list."""
    row = await pool.fetchrow(
        "SELECT * FROM cve_cache WHERE cve_id = $1 AND kev_included = TRUE",
        cve_id,
    )
    if row is None:
        return None
    return dict(row)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None
