from __future__ import annotations

from datetime import datetime
from typing import Any


CT_ONLY_SOURCES = {"crtsh", "certstream"}


def build_asset_evidence(
    *, source: str, raw_event_id: str | None, observed_at: datetime, summary: str
) -> dict[str, Any]:
    return {
        "source": source,
        "raw_event_id": raw_event_id,
        "observed_at": observed_at.isoformat(),
        "summary": summary,
    }


def build_asset_profile(
    *,
    entity_type: str,
    entity_value: str,
    target_domains: list[str],
    target_asns: list[str] | None = None,
    sources: list[str],
    evidence: list[dict[str, Any]],
    observed_at: datetime,
) -> dict[str, Any]:
    unique_sources = _dedupe_sorted(sources)
    unique_evidence = _dedupe_evidence(evidence)
    confidence = _score_confidence(
        entity_type=entity_type,
        entity_value=entity_value,
        target_domains=target_domains,
        target_asns=target_asns or [],
        sources=unique_sources,
    )
    observed = observed_at.isoformat()

    return {
        "confidence": confidence,
        "lifecycle": {
            "state": "active",
            "first_seen_at": observed,
            "last_seen_at": observed,
            "last_changed_at": observed,
        },
        "sources": unique_sources,
        "evidence": unique_evidence,
        "risk": {"score": 0, "level": "none", "reasons": []},
        "source_of_truth_feed": {
            "eligible": confidence["level"] in {"medium", "high"},
            "last_exported_at": None,
            "last_export_hash": None,
        },
    }


def merge_asset_profiles(
    existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    sources = _dedupe_sorted([*existing.get("sources", []), *incoming.get("sources", [])])
    evidence = _dedupe_evidence(
        [*existing.get("evidence", []), *incoming.get("evidence", [])]
    )
    confidence = _merge_confidence(
        existing.get("confidence", {}),
        incoming.get("confidence", {}),
        sources,
    )
    lifecycle = _merge_lifecycle(
        existing.get("lifecycle", {}),
        incoming.get("lifecycle", {}),
    )

    return {
        "confidence": confidence,
        "lifecycle": lifecycle,
        "sources": sources,
        "evidence": evidence,
        "risk": _merge_risk(existing.get("risk", {}), incoming.get("risk", {})),
        "source_of_truth_feed": {
            "eligible": confidence["level"] in {"medium", "high"},
            "last_exported_at": _prefer_present(
                incoming.get("source_of_truth_feed", {}).get("last_exported_at"),
                existing.get("source_of_truth_feed", {}).get("last_exported_at"),
            ),
            "last_export_hash": _prefer_present(
                incoming.get("source_of_truth_feed", {}).get("last_export_hash"),
                existing.get("source_of_truth_feed", {}).get("last_export_hash"),
            ),
        },
    }


def _score_confidence(
    *,
    entity_type: str,
    entity_value: str,
    target_domains: list[str],
    target_asns: list[str],
    sources: list[str],
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    normalized_type = entity_type.strip().lower()
    normalized_value = _normalize_domain(entity_value)
    normalized_targets = [_normalize_domain(target) for target in target_domains]
    normalized_asns = [_normalize_asn(asn) for asn in target_asns]

    if normalized_type in {"domain", "hostname"} and _matches_target(
        normalized_value, normalized_targets
    ):
        score += 60
        reasons.append("direct_target_match")

    if normalized_type == "asn" and _normalize_asn(entity_value) in normalized_asns:
        score += 60
        reasons.append("direct_target_match")

    if normalized_type == "ip_range" and "asnmap" in sources:
        score += 50
        reasons.append("asn_owned_range")

    if normalized_type == "ip" and "dns" in sources:
        score += 50
        reasons.append("dns_confirmed_ip")

    if len(sources) >= 2:
        score += 25
        reasons.append("multi_source_seen")

    if normalized_type == "domain" and normalized_value in normalized_targets:
        score += 25
        reasons.append("direct_target_domain")

    if sources and set(sources).issubset(CT_ONLY_SOURCES):
        score = min(score, 60)
        reasons.append("certificate_only")

    score = min(score, 100)
    return {
        "score": score,
        "level": _confidence_level(score),
        "reasons": reasons,
    }


def _merge_confidence(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    sources: list[str],
) -> dict[str, Any]:
    reasons = _dedupe_reasons(
        [*existing.get("reasons", []), *incoming.get("reasons", [])]
    )
    if not (sources and set(sources).issubset(CT_ONLY_SOURCES)):
        reasons = [reason for reason in reasons if reason != "certificate_only"]
    if len(sources) >= 2 and "multi_source_seen" not in reasons:
        reasons.append("multi_source_seen")

    score = max(
        int(existing.get("score", 0) or 0),
        int(incoming.get("score", 0) or 0),
        _score_from_reasons(reasons),
    )
    if sources and set(sources).issubset(CT_ONLY_SOURCES):
        score = min(score, 60)
        if "certificate_only" not in reasons:
            reasons.append("certificate_only")

    score = min(score, 100)
    return {
        "score": score,
        "level": _confidence_level(score),
        "reasons": reasons,
    }


def _score_from_reasons(reasons: list[str]) -> int:
    score = 0
    if "direct_target_match" in reasons:
        score += 60
    if "multi_source_seen" in reasons:
        score += 25
    if "direct_target_domain" in reasons:
        score += 25
    if "asn_owned_range" in reasons:
        score += 50
    if "dns_confirmed_ip" in reasons:
        score += 50
    return score


def _merge_lifecycle(
    existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    first_seen = _earliest(
        existing.get("first_seen_at"),
        incoming.get("first_seen_at"),
    )
    last_seen = _latest(
        existing.get("last_seen_at"),
        incoming.get("last_seen_at"),
    )
    last_changed = _latest(
        existing.get("last_changed_at"),
        incoming.get("last_changed_at"),
    )
    return {
        "state": incoming.get("state") or existing.get("state") or "active",
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "last_changed_at": last_changed,
    }


def _merge_risk(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    existing_score = int(existing.get("score", 0) or 0)
    incoming_score = int(incoming.get("score", 0) or 0)
    if incoming_score > existing_score:
        return {
            "score": incoming_score,
            "level": incoming.get("level", "none"),
            "reasons": _dedupe_reasons(incoming.get("reasons", [])),
        }
    return {
        "score": existing_score,
        "level": existing.get("level", "none"),
        "reasons": _dedupe_reasons(
            [*existing.get("reasons", []), *incoming.get("reasons", [])]
        ),
    }


def _matches_target(value: str, targets: list[str]) -> bool:
    return any(value == target or value.endswith(f".{target}") for target in targets)


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_asn(value: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized.startswith("as") else f"as{normalized}"


def _dedupe_sorted(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, Any, Any, Any]] = set()
    deduped: list[dict[str, Any]] = []
    for item in evidence:
        key = (
            item.get("raw_event_id"),
            item.get("source"),
            item.get("summary"),
            item.get("observed_at"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _dedupe_reasons(reasons: list[str]) -> list[str]:
    return list(dict.fromkeys(reason for reason in reasons if reason))


def _confidence_level(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _earliest(first: str | None, second: str | None) -> str | None:
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


def _latest(first: str | None, second: str | None) -> str | None:
    if first is None:
        return second
    if second is None:
        return first
    return max(first, second)


def _prefer_present(incoming: Any, existing: Any) -> Any:
    return incoming if incoming is not None else existing
