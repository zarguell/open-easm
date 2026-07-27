"""EPSS (Exploit Prediction Scoring System) integration.

Downloads daily EPSS scores from FIRST.org, caches them in the
``cve_cache`` table, and provides lookup functions.
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
from datetime import datetime, UTC
from typing import Any

import httpx

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


async def refresh_epss_cache(pool: Any) -> int:
    """Download the EPSS bulk CSV and upsert scores into cve_cache.

    Returns the number of CVEs upserted.
    """
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(EPSS_URL)
        resp.raise_for_status()

    # Decompress the gzipped CSV
    gz_bytes = io.BytesIO(resp.content)
    text = gzip.decompress(gz_bytes.read()).decode("utf-8")

    reader = csv.reader(io.StringIO(text))
    upserted = 0
    now = datetime.now(UTC)

    for row in reader:
        # Skip comment/header lines
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 5:
            continue

        cve_id = row[0].strip()
        if not cve_id.startswith("CVE-"):
            continue

        try:
            score = float(row[3])
            percentile = float(row[4])
        except (ValueError, IndexError):
            continue

        await pool.execute(
            """
            INSERT INTO cve_cache (cve_id, epss_score, epss_percentile, last_refreshed)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cve_id) DO UPDATE SET
                epss_score = EXCLUDED.epss_score,
                epss_percentile = EXCLUDED.epss_percentile,
                last_refreshed = EXCLUDED.last_refreshed
            """,
            cve_id,
            score,
            percentile,
            now,
        )
        upserted += 1

    logger.info("epss cache refreshed", extra={"upserted": upserted})
    return upserted


async def lookup_epss(pool: Any, cve_id: str) -> dict[str, Any] | None:
    """Look up EPSS score and percentile for a CVE.

    Returns ``{"epss_score": ..., "epss_percentile": ...}`` or ``None``.
    """
    row = await pool.fetchrow(
        "SELECT epss_score, epss_percentile FROM cve_cache WHERE cve_id = $1",
        cve_id,
    )
    if row is None or row["epss_score"] is None:
        return None
    return {
        "epss_score": float(row["epss_score"]),
        "epss_percentile": float(row["epss_percentile"]),
    }
