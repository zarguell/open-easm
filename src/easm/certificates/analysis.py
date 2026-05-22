from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}


def analyze_certificate_profile(
    profile: dict[str, Any], now: datetime | None = None
) -> dict[str, Any]:
    observed_at = _as_utc(now or datetime.now(timezone.utc))
    not_after = _parse_datetime(profile.get("not_after"))
    reasons: list[str] = []
    risk = "info"

    deployed = _is_deployed(profile)
    deployment_state = _deployment_state(profile, deployed)
    validity_state, days_until_expiry = _validity(not_after, observed_at)
    strength = _crypto_strength(profile, reasons)

    if validity_state == "expired":
        if deployed:
            risk = _max_risk(risk, "critical")
            reasons.append("expired_deployed")
        else:
            risk = _max_risk(risk, "medium")
            reasons.append("expired_ct_only")
    elif validity_state == "valid":
        if deployed and days_until_expiry is not None:
            if days_until_expiry <= 7:
                risk = _max_risk(risk, "high")
                reasons.append("expires_within_7_days")
            elif days_until_expiry <= 30:
                risk = _max_risk(risk, "medium")
                reasons.append("expires_within_30_days")
        elif deployment_state == "unobserved_candidate":
            reasons.append("valid_ct_only_not_observed")

    if strength == "weak" and deployed:
        risk = _max_risk(risk, "high")

    return {
        "validity_state": validity_state,
        "days_until_expiry": days_until_expiry,
        "deployment_state": deployment_state,
        "strength": strength,
        "risk": risk,
        "reasons": reasons,
    }


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _as_utc(value)
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return None
        return _as_utc(datetime.fromisoformat(normalized.replace("Z", "+00:00")))
    return None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _validity(not_after: datetime | None, now: datetime) -> tuple[str, int | None]:
    if not_after is None:
        return "unknown", None

    days_until_expiry = (not_after - now).days
    if not_after < now:
        return "expired", days_until_expiry
    return "valid", days_until_expiry


def _is_deployed(profile: dict[str, Any]) -> bool:
    deployment = profile.get("deployment")
    if not isinstance(deployment, dict):
        deployment = {}

    if deployment.get("state") == "deployed":
        return True
    if deployment.get("observed_endpoints"):
        return True
    return bool(profile.get("observed_endpoints"))


def _deployment_state(profile: dict[str, Any], deployed: bool) -> str:
    if deployed:
        return "deployed"

    deployment = profile.get("deployment")
    state = deployment.get("state") if isinstance(deployment, dict) else None
    if state == "ct_only" and profile.get("ct", {}).get("seen") is True:
        return "unobserved_candidate"
    return state or "unobserved"


def _crypto_strength(profile: dict[str, Any], reasons: list[str]) -> str:
    public_key = profile.get("public_key")
    signature = profile.get("signature")
    has_public_key = isinstance(public_key, dict) and bool(public_key)
    has_signature = isinstance(signature, dict) and bool(signature)
    weak = False

    if isinstance(public_key, dict):
        algorithm = str(
            public_key.get("algorithm")
            or public_key.get("public_key_algorithm")
            or ""
        ).lower()
        size_bits = public_key.get("size_bits", public_key.get("public_key_size_bits"))
        if algorithm == "rsa" and isinstance(size_bits, int) and size_bits < 2048:
            weak = True
            reasons.append("rsa_key_too_small")

    if isinstance(signature, dict):
        hash_algorithm = signature.get(
            "hash_algorithm", signature.get("signature_hash_algorithm")
        )
        if str(hash_algorithm or "").lower() in WEAK_SIGNATURE_HASHES:
            weak = True
            reasons.append("weak_signature_hash")

    if weak:
        return "weak"
    if has_public_key and has_signature:
        return "strong"
    return "unknown"


def _max_risk(current: str, candidate: str) -> str:
    if RISK_ORDER[candidate] > RISK_ORDER[current]:
        return candidate
    return current
