from __future__ import annotations

import pytest

from easm.certificates.findings import certificate_inventory_to_findings
from easm.store import Store


def _certificate_profile(
    fingerprint_sha256: str,
    subject_cn: str,
    deployment_state: str,
    risk: str,
    validity_state: str,
    reasons: list[str],
    endpoints: list[dict] | None = None,
    strength: str = "acceptable",
) -> dict:
    return {
        "fingerprint_sha256": fingerprint_sha256,
        "subject": {"common_name": subject_cn},
        "issuer": {"organization": "Example CA"},
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2026-05-01T00:00:00+00:00",
        "deployment": {
            "state": deployment_state,
            "observed_endpoints": endpoints or [],
        },
        "analysis": {
            "validity_state": validity_state,
            "strength": strength,
            "risk": risk,
            "reasons": reasons,
        },
    }


@pytest.mark.asyncio
async def test_certificate_lifecycle_inventory_rows_generate_findings(db_pool):
    store = Store(db_pool)
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "deployed-expired-fingerprint",
        {
            "certificate_profile": _certificate_profile(
                fingerprint_sha256="deployed-expired-fingerprint",
                subject_cn="expired.example.invalid",
                deployment_state="deployed",
                risk="critical",
                validity_state="expired",
                reasons=["expired_deployed"],
                endpoints=[{"hostname": "expired.example.invalid", "port": 443}],
            )
        },
    )
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "ct-only-expired-fingerprint",
        {
            "certificate_profile": _certificate_profile(
                fingerprint_sha256="ct-only-expired-fingerprint",
                subject_cn="old.example.invalid",
                deployment_state="ct_only",
                risk="medium",
                validity_state="expired",
                reasons=["expired_ct_only"],
            )
        },
    )
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "deployed-weak-fingerprint",
        {
            "certificate_profile": _certificate_profile(
                fingerprint_sha256="deployed-weak-fingerprint",
                subject_cn="weak.example.invalid",
                deployment_state="deployed",
                risk="high",
                validity_state="valid",
                strength="weak",
                reasons=["rsa_key_too_small"],
                endpoints=[{"hostname": "weak.example.invalid", "port": 443}],
            )
        },
    )

    rows = await store.list_certificate_inventory(target_id="target-1")
    findings = certificate_inventory_to_findings(
        org_id="default",
        target_id="target-1",
        rows=rows,
    )

    assert [row["risk"] for row in rows] == ["critical", "high", "medium"]
    assert {finding.rule_id for finding in findings} >= {
        "certificate_deployed_expired",
        "certificate_weak_crypto_deployed",
        "certificate_ct_only_expired",
    }
    deployed_expired = next(
        finding
        for finding in findings
        if finding.rule_id == "certificate_deployed_expired"
    )
    assert "expired.example.invalid:443" in deployed_expired.headline
    assert deployed_expired.risk.value == "critical"
