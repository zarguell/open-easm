from __future__ import annotations

from typing import Any

from easm.correlation.rule import Finding


EXPIRING_SOON_REASONS = {"expires_within_7_days", "expires_within_30_days"}
WEAK_CRYPTO_REASONS = {"rsa_key_too_small", "weak_signature_hash"}


def certificate_inventory_to_findings(
    *,
    org_id: str,
    target_id: str,
    rows: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []

    for row in rows:
        reasons = set(row.get("reasons") or [])
        risk = row.get("risk")
        if risk == "info" and "valid_ct_only_not_observed" not in reasons:
            continue

        rule_id = _rule_id_for_row(row, reasons)
        if rule_id is None:
            continue

        entity_id = row.get("entity_id")
        findings.append(
            Finding(
                org_id=org_id,
                target_id=target_id,
                rule_id=rule_id,
                risk=risk,
                headline=_headline_for_row(row, rule_id),
                description=_description_for_row(row),
                entity_ids=[entity_id] if entity_id else [],
                evidence={"certificate_inventory_row": row},
            )
        )

    return findings


def _rule_id_for_row(row: dict[str, Any], reasons: set[str]) -> str | None:
    deployment_state = row.get("deployment_state")

    if deployment_state == "deployed":
        if "expired_deployed" in reasons or row.get("validity_state") == "expired":
            return "certificate_deployed_expired"
        if reasons & EXPIRING_SOON_REASONS:
            return "certificate_deployed_expiring_soon"
        if reasons & WEAK_CRYPTO_REASONS:
            return "certificate_weak_crypto_deployed"

    if deployment_state == "ct_only":
        if "expired_ct_only" in reasons or row.get("validity_state") == "expired":
            return "certificate_ct_only_expired"
        if "valid_ct_only_not_observed" in reasons:
            return "certificate_unobserved_candidate"

    if "valid_ct_only_not_observed" in reasons:
        return "certificate_unobserved_candidate"

    return None


def _headline_for_row(row: dict[str, Any], rule_id: str) -> str:
    subject = row.get("subject_cn") or row.get("fingerprint_sha256") or "certificate"
    endpoint = _first_endpoint(row.get("observed_endpoints") or [])
    deployed_suffix = f" on {endpoint}" if row.get("deployment_state") == "deployed" and endpoint else ""

    if rule_id == "certificate_deployed_expired":
        return f"Expired certificate {subject}{deployed_suffix}"
    if rule_id == "certificate_deployed_expiring_soon":
        return f"Certificate {subject} expires soon{deployed_suffix}"
    if rule_id == "certificate_weak_crypto_deployed":
        return f"Weak certificate cryptography for {subject}{deployed_suffix}"
    if rule_id == "certificate_ct_only_expired":
        return f"Expired CT-only certificate {subject}"
    if rule_id == "certificate_unobserved_candidate":
        return f"Unobserved certificate candidate {subject}"
    return f"Certificate finding for {subject}{deployed_suffix}"


def _description_for_row(row: dict[str, Any]) -> str:
    issuer = row.get("issuer_organization") or "unknown issuer"
    not_after = row.get("not_after") or "unknown expiration"
    fingerprint = row.get("fingerprint_sha256") or "unknown fingerprint"
    return f"Issued by {issuer}; expires at {not_after}; fingerprint {fingerprint}."


def _first_endpoint(observed_endpoints: list[Any]) -> str | None:
    if not observed_endpoints:
        return None

    endpoint = observed_endpoints[0]
    if isinstance(endpoint, str):
        return endpoint
    if isinstance(endpoint, dict):
        hostname = endpoint.get("hostname")
        port = endpoint.get("port")
        if hostname and port:
            return f"{hostname}:{port}"
        if hostname:
            return str(hostname)
    return None
