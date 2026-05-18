import pytest
from httpx import ASGITransport, AsyncClient

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
    async with AsyncClient(transport=transport, base_url="http://test/api") as client:
        yield client


@pytest.mark.asyncio
async def test_graph_empty(test_api):
    resp = await test_api.get("/graph/test-target?depth=2")
    assert resp.status_code == 200
    data = resp.json()
    assert "target_id" in data
    assert data["target_id"] == "test-target"
    assert data["max_depth"] == 2
    assert data["nodes"] == []
    assert data["edges"] == []
