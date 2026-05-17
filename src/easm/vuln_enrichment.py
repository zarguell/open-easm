"""Pivot handler for CPE → CVE → KEV vulnerability enrichment.

Triggered after software detection (Wappalyzer, nmap, Shodan) stores
technologies/CVEs on an entity. Computes CPEs, looks up matching CVEs
in the local cache, and flags KEV-listed vulnerabilities.
"""
from __future__ import annotations

import logging
from typing import Any

from easm.cpe_mapper import compute_cpes_from_entity

logger = logging.getLogger(__name__)

# Severity mapping for CVSS v3 scores
CVSS_TO_RISK = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]


async def cpe_vuln_enrich(job: dict, pool,
                          http_client=None, limiters=None) -> list[dict[str, Any]]:
    """Compute CPEs from entity attributes and match against cached CVEs.

    Returns enriched entity data with vulnerability findings.
    """
    entity_type = job["entity_type"]
    entity_value = job["entity_value"]
    entity_id = job["entity_id"]

    # Fetch entity attributes from DB
    row = await pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1", entity_id,
    )
    if not row:
        return [{"entity_id": str(entity_id), "message": "entity not found"}]

    attrs = row["attributes"] or {}

    # Compute CPEs from attributes
    cpes = compute_cpes_from_entity(entity_type, attrs)
    if not cpes:
        return [{"entity_id": str(entity_id), "message": "no CPEs computable"}]

    # Look up matching CVEs from cache
    matched_cves: list[dict[str, Any]] = []

    for cpe in cpes:
        rows = await pool.fetch("""
            SELECT cve_id, description, cvss_score, cvss_severity,
                   kev_included, kev_date_added, kev_due_date,
                   kev_vendor, kev_product
            FROM cve_cache
            WHERE cpe_matches @> $1::jsonb
        """, f'[{{"cpe23Uri": "{cpe}"}}]')

        for row_obj in rows:
            cve_id = row_obj["cve_id"]
            if cve_id not in {c.get("cve_id") for c in matched_cves}:
                matched_cves.append({
                    "cve_id": cve_id,
                    "description": row_obj["description"] or "",
                    "cvss_score": row_obj["cvss_score"],
                    "severity": row_obj["cvss_severity"] or "unknown",
                    "kev_included": row_obj["kev_included"] or False,
                    "kev_date_added": str(row_obj["kev_date_added"]) if row_obj["kev_date_added"] else None,
                    "kev_due_date": str(row_obj["kev_due_date"]) if row_obj["kev_due_date"] else None,
                    "matched_cpe": cpe,
                })

    risk = _classify_risk(matched_cves)

    return [{
        "entity_id": str(entity_id),
        "entity_type": entity_type,
        "entity_value": entity_value,
        "computed_cpes": cpes,
        "matched_cves": matched_cves,
        "kev_count": sum(1 for c in matched_cves if c["kev_included"]),
        "total_cves": len(matched_cves),
        "risk": risk,
    }]


def _classify_risk(cves: list[dict[str, Any]]) -> str:
    """Classify overall risk based on matched CVEs.

    Priority: KEV-listed > highest CVSS score.
    """
    if any(c.get("kev_included") for c in cves):
        return "critical"
    if not cves:
        return "none"
    scores = [c.get("cvss_score") for c in cves if c.get("cvss_score") is not None]
    if not scores:
        return "unknown"
    max_score = max(scores)
    for threshold, level in CVSS_TO_RISK:
        if max_score >= threshold:
            return level
    return "unknown"
