from __future__ import annotations

from datetime import UTC, datetime

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
            id="target-1",
            name="Target One",
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


@pytest.fixture
async def seed_asset(db_pool):
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="target-1",
        entity_type="hostname",
        entity_value="app.example.invalid",
        new_attributes={"source": "subfinder"},
    )
    await store.update_entity_asset_profile(
        entity_id,
        {
            "confidence": {
                "score": 91,
                "level": "high",
                "reasons": ["direct_target_match"],
            },
            "risk": {
                "score": 42,
                "level": "medium",
                "reasons": ["public_service"],
            },
            "source_of_truth_feed": {"eligible": True},
            "sources": ["subfinder"],
            "evidence": [{"source": "subfinder", "summary": "observed hostname"}],
        },
    )
    await store.record_asset_change_event(
        org_id="default",
        target_id="target-1",
        entity_id=entity_id,
        change_type="asset_added",
        summary="hostname appeared in inventory",
        source="subfinder",
        observed_at=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
    )
    return str(entity_id)


@pytest.mark.asyncio
async def test_list_asset_inventory_returns_asset_fields(test_api, seed_asset):
    resp = await test_api.get("/api/assets/inventory")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["assets"]) == 1
    asset = data["assets"][0]
    assert asset["entity_id"] == seed_asset
    assert asset["org_id"] == "default"
    assert asset["target_id"] == "target-1"
    assert asset["entity_type"] == "hostname"
    assert asset["entity_value"] == "app.example.invalid"
    assert asset["confidence_score"] == 91
    assert asset["confidence_level"] == "high"
    assert asset["risk_score"] == 42
    assert asset["risk_level"] == "medium"
    assert asset["feed_eligible"] is True
    assert asset["sources"] == ["subfinder"]
    assert asset["evidence_count"] == 1
    assert asset["first_seen_at"] is not None
    assert asset["last_seen_at"] is not None


@pytest.mark.asyncio
async def test_list_asset_inventory_filters(test_api, seed_asset):
    matching = await test_api.get(
        "/api/assets/inventory?confidence_level=high&risk_level=medium&feed_eligible=true"
    )
    wrong_confidence = await test_api.get("/api/assets/inventory?confidence_level=low")
    wrong_risk = await test_api.get("/api/assets/inventory?risk_level=high")
    wrong_feed = await test_api.get("/api/assets/inventory?feed_eligible=false")

    assert matching.status_code == 200
    assert [asset["entity_id"] for asset in matching.json()["assets"]] == [seed_asset]
    assert wrong_confidence.json()["assets"] == []
    assert wrong_risk.json()["assets"] == []
    assert wrong_feed.json()["assets"] == []


@pytest.mark.asyncio
async def test_list_asset_changes_returns_default_org_change(test_api, seed_asset):
    resp = await test_api.get("/api/assets/changes?target_id=target-1")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["changes"]) == 1
    change = data["changes"][0]
    assert change["org_id"] == "default"
    assert change["target_id"] == "target-1"
    assert change["entity_id"] == seed_asset
    assert change["change_type"] == "asset_added"
    assert change["summary"] == "hostname appeared in inventory"


@pytest.mark.asyncio
async def test_export_assets_ndjson_returns_feed_eligible_assets(test_api, seed_asset):
    resp = await test_api.get("/api/assets/export.ndjson?target_id=target-1")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    assert "open-easm" in resp.text
    assert "app.example.invalid" in resp.text
