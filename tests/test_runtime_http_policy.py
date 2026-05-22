from __future__ import annotations

from pathlib import Path

import pytest

from easm.config import RuntimeConfig
from easm.runtime import Runtime

REPO_ROOT = Path(__file__).parents[1]
FIXTURES = REPO_ROOT / "fixtures" / "simulation"


@pytest.mark.asyncio
@pytest.mark.simulation
async def test_simulation_http_client_returns_fixture() -> None:
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path=str(FIXTURES),
            allow_external_network=False,
        )
    )

    async with runtime.make_http_client() as client:
        response = await client.get("https://crt.sh/?q=%.example.invalid&output=json")

    assert response.status_code == 200
    assert response.json()


@pytest.mark.asyncio
@pytest.mark.simulation
async def test_simulation_http_client_fails_closed_on_missing_fixture() -> None:
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path=str(FIXTURES),
            allow_external_network=False,
        )
    )

    async with runtime.make_http_client() as client:
        response = await client.get("https://missing.example.invalid/data.json")

    assert response.status_code == 599
    assert response.json()["error"] == "simulation fixture missing"


@pytest.mark.asyncio
@pytest.mark.network_mocked
async def test_live_runtime_blocks_http_when_external_network_disabled() -> None:
    runtime = Runtime(
        RuntimeConfig(
            mode="live",
            allow_external_network=False,
        )
    )

    async with runtime.make_http_client() as client:
        response = await client.get("https://example.com")

    assert response.status_code == 599
    assert response.json()["error"] == "external network disabled by runtime policy"
