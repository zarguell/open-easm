from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from easm.api import deps
from easm.api.app import create_app
from easm.config import Config, MatchRules, TargetConfig
from easm.store import Store


@pytest.fixture
def test_config():
    return Config(targets=[
        TargetConfig(
            id="test-target",
            name="Test Target",
            type="organization",
            enabled=True,
            match_rules=MatchRules(domains=["example.invalid"]),
            runners={},
        )
    ])


@pytest.fixture
async def test_api(test_config, db_pool, scheduler):
    app = create_app()
    deps.set_config(test_config)
    deps.set_store(Store(db_pool))
    deps.set_scheduler(scheduler)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


def _profile(fingerprint_sha256: str, risk: str) -> dict:
    return {
        "fingerprint_sha256": fingerprint_sha256,
        "subject": {"common_name": "app.example.invalid"},
        "issuer": {"organization": "Example CA"},
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2026-05-01T00:00:00+00:00",
        "deployment": {
            "state": "deployed",
            "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}],
        },
        "analysis": {
            "validity_state": "expired",
            "strength": "acceptable",
            "risk": risk,
            "reasons": ["expired_deployed"],
        },
    }


@pytest.fixture
async def seed_certificates(db_pool):
    store = Store(db_pool)
    await store.upsert_entity(
        "default",
        "test-target",
        "certificate",
        "critical-fingerprint",
        {"certificate_profile": _profile("critical-fingerprint", "critical")},
    )
    await store.upsert_entity(
        "default",
        "test-target",
        "certificate",
        "medium-fingerprint",
        {"certificate_profile": _profile("medium-fingerprint", "medium")},
    )


@pytest.mark.asyncio
async def test_list_certificate_inventory(test_api, seed_certificates):
    resp = await test_api.get("/api/certificates/inventory")

    assert resp.status_code == 200
    data = resp.json()
    assert "certificates" in data
    assert data["certificates"][0]["fingerprint_sha256"] == "critical-fingerprint"
    assert data["certificates"][0]["subject_cn"] == "app.example.invalid"
    assert data["certificates"][0]["risk"] == "critical"


@pytest.mark.asyncio
async def test_summarize_certificate_inventory(test_api, seed_certificates):
    resp = await test_api.get("/api/certificates/summary")

    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert data["by_risk"]["critical"] == 1
    assert data["by_issuer_organization"]["Example CA"] == 2


@pytest.mark.asyncio
async def test_list_certificate_inventory_filters_risk(test_api, seed_certificates):
    resp = await test_api.get("/api/certificates/inventory?risk=critical")

    assert resp.status_code == 200
    data = resp.json()
    assert [cert["risk"] for cert in data["certificates"]] == ["critical"]
