from __future__ import annotations

import pytest

from easm.store import Store


def _certificate_profile(
    fingerprint_sha256: str,
    deployment_state: str,
    risk: str,
    endpoints: list[dict] | None = None,
) -> dict:
    return {
        "fingerprint_sha256": fingerprint_sha256,
        "subject": {"common_name": "app.example.invalid"},
        "issuer": {"organization": "Example CA"},
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2026-05-01T00:00:00+00:00",
        "deployment": {
            "state": deployment_state,
            "observed_endpoints": endpoints or [],
        },
        "analysis": {
            "validity_state": "expired",
            "strength": "acceptable",
            "risk": risk,
            "reasons": [f"expired_{deployment_state}"],
        },
    }


async def _seed_certificates(store: Store) -> None:
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "critical-fingerprint",
        {
            "certificate_profile": _certificate_profile(
                "critical-fingerprint",
                "deployed",
                "critical",
                [{"hostname": "app.example.invalid", "port": 443}],
            )
        },
    )
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "medium-fingerprint",
        {
            "certificate_profile": _certificate_profile(
                "medium-fingerprint",
                "ct_only",
                "medium",
            )
        },
    )


@pytest.mark.asyncio
async def test_list_certificate_inventory_orders_by_risk(db_pool):
    store = Store(db_pool)
    await _seed_certificates(store)

    result = await store.list_certificate_inventory(target_id="target-1")
    certificates = result["certificates"]

    assert [cert["risk"] for cert in certificates] == ["critical", "medium"]
    assert certificates[0]["deployment_state"] == "deployed"
    assert certificates[0]["observed_endpoints"] == [
        {"hostname": "app.example.invalid", "port": 443},
    ]


@pytest.mark.asyncio
async def test_summarize_certificate_inventory_groups_counts(db_pool):
    store = Store(db_pool)
    await _seed_certificates(store)

    summary = await store.summarize_certificate_inventory(target_id="target-1")

    assert summary["total"] == 2
    assert summary["by_risk"]["critical"] == 1
    assert summary["by_risk"]["medium"] == 1
    assert summary["by_deployment_state"]["deployed"] == 1
    assert summary["by_deployment_state"]["ct_only"] == 1
    assert summary["by_issuer_organization"]["Example CA"] == 2


@pytest.mark.asyncio
async def test_certificate_inventory_prefers_analyzed_deployment_state(db_pool):
    store = Store(db_pool)
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "candidate-fingerprint",
        {
            "certificate_profile": {
                "fingerprint_sha256": "candidate-fingerprint",
                "subject": {"common_name": "candidate.example.invalid"},
                "issuer": {"organization": "Example CA"},
                "not_after": "2026-06-01T00:00:00+00:00",
                "deployment": {"state": "ct_only", "observed_endpoints": []},
                "analysis": {
                    "deployment_state": "unobserved_candidate",
                    "validity_state": "valid",
                    "strength": "unknown",
                    "risk": "info",
                    "reasons": ["valid_ct_only_not_observed"],
                },
            }
        },
    )

    result = await store.list_certificate_inventory(target_id="target-1")
    certificates = result["certificates"]
    summary = await store.summarize_certificate_inventory(target_id="target-1")

    assert certificates[0]["deployment_state"] == "unobserved_candidate"
    assert summary["by_deployment_state"]["unobserved_candidate"] == 1
