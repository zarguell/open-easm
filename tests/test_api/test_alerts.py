import pytest
from httpx import ASGITransport, AsyncClient

from easm.api import deps
from easm.api.app import create_app
from easm.config import AlertRule, AlertsConfig, Config
from easm.store import Store


@pytest.fixture
def alert_config():
    return Config(
        targets=[],
        alerts=AlertsConfig(
            rules=[
                AlertRule(name="test_rule", condition="test", severity="high"),
                AlertRule(
                    name="low_rule",
                    condition="port in [22]",
                    severity="low",
                    enabled=False,
                ),
            ],
        ),
    )


@pytest.mark.asyncio
async def test_list_alert_rules(alert_config):
    app = create_app()
    deps.set_config(alert_config)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/alerts/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 2
    assert rules[0]["name"] == "test_rule"
    assert rules[0]["severity"] == "high"
    assert rules[0]["enabled"] is True
    assert rules[1]["name"] == "low_rule"
    assert rules[1]["enabled"] is False


@pytest.mark.asyncio
async def test_alert_feed_empty(alert_config, db_pool):
    app = create_app()
    deps.set_config(alert_config)
    deps.set_store(Store(db_pool))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/alerts/feed")
    assert resp.status_code == 200
    assert resp.json() == []
