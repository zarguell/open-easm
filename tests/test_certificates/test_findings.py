from __future__ import annotations

from easm.certificates.findings import certificate_inventory_to_findings


def test_deployed_expired_finding_is_critical() -> None:
    findings = certificate_inventory_to_findings(
        org_id="org-1",
        target_id="target-1",
        rows=[
            {
                "entity_id": "00000000-0000-0000-0000-000000000001",
                "fingerprint_sha256": "abc123",
                "deployment_state": "deployed",
                "risk": "critical",
                "validity_state": "expired",
                "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}],
                "reasons": ["expired_deployed"],
                "subject_cn": "app.example.invalid",
                "issuer_organization": "Example CA",
                "not_after": "2026-05-01T00:00:00Z",
            }
        ],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "certificate_deployed_expired"
    assert findings[0].risk.value == "critical"
    assert "app.example.invalid:443" in findings[0].headline


def test_ct_only_expired_finding_is_medium() -> None:
    findings = certificate_inventory_to_findings(
        org_id="org-1",
        target_id="target-1",
        rows=[
            {
                "entity_id": "00000000-0000-0000-0000-000000000002",
                "fingerprint_sha256": "def456",
                "deployment_state": "ct_only",
                "risk": "medium",
                "validity_state": "expired",
                "observed_endpoints": [],
                "reasons": ["expired_ct_only"],
                "subject_cn": "old.example.invalid",
                "issuer_organization": "Example CA",
                "not_after": "2026-04-01T00:00:00Z",
            }
        ],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "certificate_ct_only_expired"
    assert findings[0].risk.value == "medium"


def test_weak_deployed_finding_uses_weak_rule() -> None:
    findings = certificate_inventory_to_findings(
        org_id="org-1",
        target_id="target-1",
        rows=[
            {
                "entity_id": "00000000-0000-0000-0000-000000000003",
                "fingerprint_sha256": "fed789",
                "deployment_state": "deployed",
                "risk": "high",
                "validity_state": "valid",
                "observed_endpoints": [{"hostname": "weak.example.invalid", "port": 443}],
                "reasons": ["rsa_key_too_small"],
                "subject_cn": "weak.example.invalid",
                "issuer_organization": "Example CA",
                "not_after": "2026-08-01T00:00:00Z",
            }
        ],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "certificate_weak_crypto_deployed"


def test_info_without_unobserved_reason_is_skipped() -> None:
    findings = certificate_inventory_to_findings(
        org_id="org-1",
        target_id="target-1",
        rows=[
            {
                "entity_id": "00000000-0000-0000-0000-000000000004",
                "fingerprint_sha256": "aaa999",
                "deployment_state": "deployed",
                "risk": "info",
                "validity_state": "valid",
                "observed_endpoints": [{"hostname": "ok.example.invalid", "port": 443}],
                "reasons": [],
                "subject_cn": "ok.example.invalid",
                "issuer_organization": "Example CA",
                "not_after": "2026-09-01T00:00:00Z",
            }
        ],
    )

    assert findings == []
