"""Executive risk scoring engine.

Produces a weighted risk score across 7 pillars, adjusted by domain profile.
"""

from __future__ import annotations

from typing import Any

from easm.scoring.pillars import PILLARS, PROFILE_WEIGHTS, classify_domain

# Penalty points subtracted from a pillar's 100-point starting score.
# Calibrated so a single critical finding → ~60, high → ~75, medium → ~88, low → ~95.
# Multiple findings of the same severity accumulate (clamped to 0).
SEVERITY_PENALTY = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 0,
}


def _category_match(finding: dict, patterns: list[str]) -> bool:
    haystack = " ".join([
        str(finding.get("rule_id", "")),
        str(finding.get("headline", "")),
        str(finding.get("risk", "")),
    ]).lower()
    return any(p.lower() in haystack for p in patterns)


def _confidence(finding: dict) -> str:
    headline = str(finding.get("headline", "")).lower()
    if any(x in headline for x in ("dmarc", "spf", "mx", "caa", "header", "certificate")):
        return "high"
    if "cve" in headline or "passive" in headline:
        return "medium"
    return "medium"


def _score_from_findings(
    findings: list[dict], extra_penalty: int = 0,
) -> tuple[int, list[dict]]:
    evidence: list[dict] = []
    penalty = extra_penalty

    for finding in findings:
        severity = str(finding.get("risk", "info")).lower()
        lost = SEVERITY_PENALTY.get(severity, 0)
        penalty += lost
        if lost:
            evidence.append({
                "label": finding.get("headline", ""),
                "severity": severity,
                "points_lost": lost,
                "confidence": _confidence(finding),
            })

    return max(0, min(100, 100 - penalty)), evidence


def _level(score: int) -> str:
    if score >= 85:
        return "Controlled"
    if score >= 70:
        return "Adequate"
    if score >= 55:
        return "Needs Attention"
    return "High Risk"


def _risk_label(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Moderate"
    if score >= 55:
        return "Significant"
    return "High"


def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        str(sev).lower(), 9
    )


def build_executive_risk(
    findings: list[dict],
    *,
    has_mail: bool = False,
    has_web: bool = False,
    ip_count: int = 0,
    subdomain_count: int = 0,
    cve_count: int = 0,
    listed_ip_count: int = 0,
    non_public_ip_count: int = 0,
) -> dict[str, Any]:
    """Build a complete executive risk assessment.

    Returns a dict with overall score, pillar breakdown, top risks, quick wins,
    and board summary.
    """
    profile_name = classify_domain(has_mail=has_mail, has_web=has_web)
    weights = PROFILE_WEIGHTS.get(profile_name, PROFILE_WEIGHTS["undetermined"])

    pillars: list[dict] = []
    for pillar in PILLARS:
        pillar_id = pillar["id"]
        weight = weights.get(pillar_id, 0)
        applicability = "applicable" if weight > 0 else "not_applicable"
        pf = [f for f in findings if _category_match(f, pillar["patterns"])]

        if applicability == "not_applicable":
            score = None
            evidence = []
        else:
            extra = 0
            if pillar_id == "surface":
                if non_public_ip_count > 0:
                    extra += 25
                if ip_count > 10:
                    extra += 8
                if subdomain_count > 80:
                    extra += 5
            if pillar_id == "cti":
                if listed_ip_count > 0:
                    extra += 40
            if pillar_id == "cve":
                if cve_count > 0:
                    extra += min(35, cve_count * 10)
            score, evidence = _score_from_findings(pf, extra_penalty=extra)

        critical_high = sum(
            1 for f in pf if str(f.get("risk")).lower() in ("critical", "high")
        )
        pillars.append({
            "id": pillar_id,
            "label": pillar["label"],
            "weight": weight,
            "applicability": applicability,
            "score": score,
            "level": "Not applicable" if score is None else _level(score),
            "risk": "Not applicable" if score is None else _risk_label(score),
            "findings_count": len(pf),
            "critical_high_count": critical_high,
            "description": pillar["description"],
            "recommendation": pillar["recommendation"],
            "evidence": evidence[:10],
        })

    applicable = [
        p for p in pillars
        if p["applicability"] == "applicable"
        and isinstance(p["score"], int)
        and p["weight"] > 0
    ]
    total_weight = sum(p["weight"] for p in applicable)
    overall = (
        round(sum(p["score"] * p["weight"] for p in applicable) / total_weight)
        if total_weight
        else 0
    )
    technical_score = max(0, min(1000, overall * 10))

    sorted_findings = sorted(
        findings, key=lambda f: _sev_rank(f.get("risk", "info"))
    )

    top_risks = []
    for f in sorted_findings:
        if len(top_risks) >= 5:
            break
        if str(f.get("risk", "info")).lower() in ("critical", "high", "medium"):
            top_risks.append({
                "severity": f.get("risk", "info"),
                "rule_id": f.get("rule_id", ""),
                "headline": f.get("headline", ""),
                "confidence": _confidence(f),
            })

    quick_wins = []
    for f in sorted_findings:
        text = f"{f.get('headline', '')} {f.get('rule_id', '')}".lower()
        if len(quick_wins) >= 5:
            break
        if any(
            word in text
            for word in ["header", "hsts", "dmarc", "spf", "caa", "expir", "tls"]
        ):
            quick_wins.append({
                "severity": f.get("risk", "info"),
                "headline": f.get("headline", ""),
                "confidence": _confidence(f),
            })

    weakest = sorted(applicable, key=lambda p: p["score"] or 0)[:3]
    posture = _level(overall)
    risk = _risk_label(overall)
    weakest_text = (
        ", ".join(f"{p['label']} ({p['score']}/100)" for p in weakest)
        if weakest
        else "no applicable pillars"
    )

    by_severity: dict[str, int] = {}
    penalty = 0
    for finding in findings:
        sev = str(finding.get("risk", "info")).lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        penalty += SEVERITY_PENALTY.get(sev, 0)

    return {
        "overall_score": overall,
        "max_score": 100,
        "technical_score": technical_score,
        "technical_max_score": 1000,
        "posture": posture,
        "risk_level": risk,
        "profile": profile_name,
        "board_summary": (
            f"Overall posture {posture.lower()} with {risk.lower()} risk. "
            f"Weakest pillars: {weakest_text}."
        ),
        "pillars": pillars,
        "weakest_pillars": weakest,
        "top_risks": top_risks,
        "quick_wins": quick_wins,
        "by_severity": by_severity,
    }
