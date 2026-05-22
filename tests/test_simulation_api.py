from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from easm.api import deps
from easm.api.app import create_app
from easm.config import load_config
from easm.runtime import configure_runtime
from easm.scheduler import Scheduler
from easm.store import Store

REPO_ROOT = Path(__file__).parents[1]


@pytest.mark.asyncio
@pytest.mark.simulation
@patch("easm.tasks.pivot.execute_pivot")
async def test_offline_manual_subfinder_run_creates_hostname_entity_and_dns_pivot(
    mock_execute_pivot, db_pool,
) -> None:
    defer_mock = AsyncMock()
    configured = MagicMock()
    configured.defer_async = defer_mock
    mock_execute_pivot.configure = MagicMock(return_value=configured)

    config = load_config(REPO_ROOT / "config.offline.yaml")
    configure_runtime(config.runtime)
    store = Store(db_pool)
    scheduler = Scheduler()
    deps.set_config(config)
    deps.set_store(store)
    deps.set_scheduler(scheduler)

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test/api") as client:
        response = await client.post("/runs/offline-local/subfinder")

    assert response.status_code == 200

    entity_rows = await db_pool.fetch(
        """
        SELECT entity_type, entity_value, attributes
        FROM entities
        WHERE target_id = 'offline-local'
        ORDER BY entity_type, entity_value
        """
    )
    assert ("hostname", "app.example.invalid") in [
        (row["entity_type"], row["entity_value"]) for row in entity_rows
    ]

    defer_mock.assert_called()
    dns_calls = [
        c for c in defer_mock.call_args_list
        if c.kwargs.get("pivot_type") == "dns_resolve"
        and c.kwargs.get("entity_value") == "app.example.invalid"
    ]
    assert len(dns_calls) == 1
