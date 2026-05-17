from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from easm.api import deps
from easm.api.app import create_app
from easm.config import Config, TargetConfig, MatchRules
from easm.correlation.rule import Finding
from easm.store import Store


@pytest.fixture
def test_config():
    return Config(targets=[
        TargetConfig(
            id="test-target",
            name="Test Target",
            type="organization",
            enabled=True,
            match_rules=MatchRules(domains=["example.com"]),
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
async def seed_finding(db_pool) -> str:
    store = Store(db_pool)
    f = Finding(
        org_id="default",
        target_id="test-target",
        rule_id="dev_or_test_system",
        risk="medium",
        headline="Development system exposed: dev.example.com",
        entity_ids=[str(uuid.uuid7())],
        evidence={"matched_entities": [{"entity_value": "dev.example.com"}]},
    )
    fid = await store.create_finding(f)
    return str(fid)


@pytest.mark.asyncio
async def test_list_findings_empty(test_api):
    resp = await test_api.get("/api/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert data["findings"] == []


@pytest.mark.asyncio
async def test_list_findings_with_data(test_api, seed_finding):
    resp = await test_api.get("/api/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) == 1
    assert data["findings"][0]["headline"] == "Development system exposed: dev.example.com"


@pytest.mark.asyncio
async def test_list_findings_filter_target_id(test_api, seed_finding):
    resp = await test_api.get("/api/findings?target_id=test-target")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) == 1


@pytest.mark.asyncio
async def test_list_findings_filter_not_found(test_api, seed_finding):
    resp = await test_api.get("/api/findings?target_id=nonexistent")
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"] == []


@pytest.mark.asyncio
async def test_list_findings_filter_risk(test_api, seed_finding):
    resp = await test_api.get("/api/findings?risk=high")
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"] == []


@pytest.mark.asyncio
async def test_list_findings_filter_status(test_api, seed_finding):
    resp = await test_api.get("/api/findings?status=open")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) == 1


@pytest.mark.asyncio
async def test_get_finding(test_api, seed_finding):
    resp = await test_api.get(f"/api/findings/{seed_finding}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["headline"] == "Development system exposed: dev.example.com"
    assert data["risk"] == "medium"
    assert data["rule_id"] == "dev_or_test_system"


@pytest.mark.asyncio
async def test_get_finding_not_found(test_api):
    resp = await test_api.get("/api/findings/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_finding_status(test_api, seed_finding):
    resp = await test_api.patch(
        f"/api/findings/{seed_finding}",
        json={"status": "acknowledged"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "acknowledged"


@pytest.mark.asyncio
async def test_patch_finding_resolve(test_api, seed_finding):
    resp = await test_api.patch(
        f"/api/findings/{seed_finding}",
        json={"status": "resolved"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "resolved"


@pytest.mark.asyncio
async def test_patch_finding_invalid_status(test_api, seed_finding):
    resp = await test_api.patch(
        f"/api/findings/{seed_finding}",
        json={"status": "invalid_status"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_finding_not_found(test_api):
    resp = await test_api.patch(
        "/api/findings/00000000-0000-0000-0000-000000000000",
        json={"status": "acknowledged"},
    )
    assert resp.status_code == 404
