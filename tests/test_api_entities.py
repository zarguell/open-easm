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
async def test_list_entities_empty(test_api):
    resp = await test_api.get("/entities")
    assert resp.status_code == 200
    data = resp.json()
    assert "entities" in data
    assert data["entities"] == []
    assert data["next_cursor"] is None


@pytest.mark.asyncio
async def test_list_entities_with_target_filter(test_api):
    resp = await test_api.get("/entities?target_id=test-target")
    assert resp.status_code == 200
    data = resp.json()
    assert "entities" in data


@pytest.mark.asyncio
async def test_list_entities_with_type_filter(test_api):
    resp = await test_api.get("/entities?entity_type=domain")
    assert resp.status_code == 200
    data = resp.json()
    assert "entities" in data


@pytest.mark.asyncio
async def test_get_entity_not_found(test_api):
    resp = await test_api.get("/entities/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_entity_relationships_invalid(test_api):
    resp = await test_api.get("/entities/00000000-0000-0000-0000-000000000000/relationships")
    assert resp.status_code == 200
    data = resp.json()
    assert "relationships" in data
