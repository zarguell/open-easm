"""Executive scoring API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from easm.api.deps import get_store
from easm.scoring.executive import build_executive_risk
from easm.store import Store

router = APIRouter(tags=["scoring"])


@router.get("/scoring/executive")
async def executive_risk(
    target_id: str = Query(..., description="Target ID to score"),
    store: Store = Depends(get_store),
):
    """Return executive risk assessment for a target."""
    findings = await store.list_findings(target_id=target_id, limit=5000)

    # Gather context signals from entity counts
    ip_count = await store.count_entities(target_id=target_id, entity_type="ip")
    hostname_count = await store.count_entities(target_id=target_id, entity_type="hostname")
    domain_count = await store.count_entities(target_id=target_id, entity_type="domain")
    subdomain_count = hostname_count + domain_count

    # Count findings with CVE in rule_id as proxy
    cve_count = sum(
        1 for f in findings
        if "cve" in (f.get("rule_id", "") or "").lower()
        or "vuln" in (f.get("rule_id", "") or "").lower()
    )

    # Check if target has web and mail presence
    has_web = any(
        "web" in (f.get("rule_id", "") or "").lower()
        or "header" in (f.get("headline", "") or "").lower()
        for f in findings
    )
    has_mail = any(
        "mail" in (f.get("rule_id", "") or "").lower()
        or "dmarc" in (f.get("headline", "") or "").lower()
        or "spf" in (f.get("headline", "") or "").lower()
        for f in findings
    )

    return build_executive_risk(
        findings,
        has_mail=has_mail,
        has_web=has_web,
        ip_count=ip_count,
        subdomain_count=subdomain_count,
        cve_count=cve_count,
    )


@router.get("/scoring/pillars")
async def pillar_breakdown(
    target_id: str = Query(..., description="Target ID to score"),
    store: Store = Depends(get_store),
):
    """Return per-pillar risk breakdown for a target."""
    result = await executive_risk(target_id=target_id, store=store)
    return {
        "target_id": target_id,
        "pillars": result["pillars"],
        "weakest_pillars": result["weakest_pillars"],
    }
