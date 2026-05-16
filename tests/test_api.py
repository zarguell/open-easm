from httpx import ASGITransport, AsyncClient
import pytest

from easm.api.app import create_app
from easm.api import deps
from easm.config import Config, TargetConfig, MatchRules
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


@pytest.mark.asyncio
async def test_healthz(test_api):
    resp = await test_api.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "database" in data


@pytest.mark.asyncio
async def test_list_targets(test_api):
    resp = await test_api.get("/targets")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["id"] == "test-target"


@pytest.mark.asyncio
async def test_get_target_not_found(test_api):
    resp = await test_api.get("/targets/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_events_empty(test_api):
    resp = await test_api.get("/events")
    assert resp.status_code == 200
    data = resp.json()
    assert data == []


@pytest.mark.asyncio
async def test_list_runs_empty(test_api):
    resp = await test_api.get("/runs")
    assert resp.status_code == 200
    data = resp.json()
    assert data == []
