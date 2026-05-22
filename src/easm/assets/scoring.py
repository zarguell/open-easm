from __future__ import annotations

from typing import Any


LEVEL_THRESHOLDS = (
    ("critical", 90),
    ("high", 70),
    ("medium", 40),
    ("low", 1),
)
CERTIFICATE_RISK_POINTS = {
    "info": 0,
    "none": 0,
    "low": 25,
    "medium": 45,
    "high": 75,
    "critical": 95,
}
CLOSED_FINDING_STATUSES = {"closed", "resolved", "suppressed"}


def score_asset_exposure(
    entity: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    attributes = _mapping(entity.get("attributes"))

    for finding in findings or []:
        if _is_closed_finding(finding):
            continue
        severity = str(finding.get("severity") or "").lower()
        if severity == "critical":
            score = max(score, 95)
            _append_reason(reasons, "critical_finding")
        elif severity == "high":
            score = max(score, 75)
            _append_reason(reasons, "high_finding")

    if _is_internet_exposed(entity, attributes):
        score = max(score, 45)
        _append_reason(reasons, "internet_exposed_service")

    certificate_profile = _mapping(attributes.get("certificate_profile"))
    certificate_analysis = _mapping(certificate_profile.get("analysis"))
    certificate_risk = str(
        certificate_analysis.get("risk")
        or certificate_analysis.get("risk_level")
        or ""
    ).lower()
    score = max(score, CERTIFICATE_RISK_POINTS.get(certificate_risk, 0))
    certificate_reasons = certificate_analysis.get("reasons")
    if not isinstance(certificate_reasons, list):
        certificate_reasons = []
    for reason in certificate_reasons:
        _append_reason(reasons, f"certificate:{reason}")

    risk = {
        "score": score,
        "level": _level_for_score(score),
        "reasons": reasons,
    }
    confidence_score = _confidence_score(attributes)
    if confidence_score is not None:
        risk["confidence_score"] = confidence_score
    return risk


def _is_closed_finding(finding: dict[str, Any]) -> bool:
    return str(finding.get("status") or "").lower() in CLOSED_FINDING_STATUSES


def _is_internet_exposed(entity: dict[str, Any], attributes: dict[str, Any]) -> bool:
    if entity.get("type") not in {"hostname", "ip"}:
        return False
    if attributes.get("open_ports"):
        return True
    services = attributes.get("services")
    return any(
        isinstance(service, dict) and service.get("port")
        for service in services or []
    )


def _confidence_score(attributes: dict[str, Any]) -> int | None:
    asset_profile = _mapping(attributes.get("asset_profile"))
    confidence = asset_profile.get("confidence_score", asset_profile.get("confidence"))
    return confidence if isinstance(confidence, int) else None


def _level_for_score(score: int) -> str:
    for level, threshold in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "none"


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
