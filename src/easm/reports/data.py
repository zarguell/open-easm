"""Gather report data from the store for PDF/Excel generation."""

from __future__ import annotations

from typing import Any

from easm.scoring.executive import build_executive_risk
from easm.sla.models import compute_sla_summary
from easm.store import Store


async def gather_report_data(target_id: str, store: Store) -> dict[str, Any]:
    """Collect all data needed for a report from the store."""
    findings = await store.list_findings(target_id=target_id, limit=5000)
    assets = await store.list_asset_inventory(
        target_id=target_id, limit=5000,
    )
    certs_result = await store.list_certificate_inventory(target_id=target_id, limit=5000)
    certs = certs_result["certificates"] if isinstance(certs_result, dict) else []
    cert_summary = await store.summarize_certificate_inventory(target_id=target_id)
    runs = await store.list_runs(target_id=target_id, limit=50)
    change_events = await store.list_asset_change_events(
        target_id=target_id, limit=100,
    )

    # Context signals
    ip_count = await store.count_entities(target_id=target_id, entity_type="ip")
    hostname_count = await store.count_entities(
        target_id=target_id, entity_type="hostname"
    )
    domain_count = await store.count_entities(
        target_id=target_id, entity_type="domain"
    )

    has_web = any(
        "web" in (f.get("rule_id", "") or "").lower()
        or "header" in (f.get("headline", "") or "").lower()
        for f in findings
    )
    has_mail = any(
        "mail" in (f.get("rule_id", "") or "").lower()
        or "dmarc" in (f.get("headline", "") or "").lower()
        for f in findings
    )

    cve_count = sum(
        1
        for f in findings
        if "cve" in (f.get("rule_id", "") or "").lower()
        or "vuln" in (f.get("rule_id", "") or "").lower()
    )

    executive_risk = build_executive_risk(
        findings,
        has_mail=has_mail,
        has_web=has_web,
        ip_count=ip_count,
        subdomain_count=hostname_count + domain_count,
        cve_count=cve_count,
    )

    sla_summary = compute_sla_summary(findings)

    entities = assets.get("entities", []) if isinstance(assets, dict) else assets

    return {
        "target_id": target_id,
        "findings": findings,
        "entities": entities,
        "certificates": certs if isinstance(certs, list) else [],
        "certificate_summary": cert_summary,
        "runs": runs if isinstance(runs, list) else [],
        "change_events": change_events if isinstance(change_events, list) else [],
        "executive_risk": executive_risk,
        "sla_summary": sla_summary,
        "ip_count": ip_count,
        "hostname_count": hostname_count,
        "domain_count": domain_count,
    }
