import asyncio

from easm.config import RuntimeConfig
from easm.runtime import Runtime


def test_simulated_run_pivot_handler_returns_dns_fixture_results():
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path="fixtures/simulation",
        )
    )
    job = {
        "pivot_type": "dns_resolve",
        "entity_value": "app.example.invalid",
    }

    async def live_handler(_job, _pool):
        raise AssertionError("live handler should not run in simulation mode")

    results = asyncio.run(
        runtime.run_pivot_handler(
            "dns_resolve",
            job,
            live_handler,
            pool=None,
        )
    )

    assert results == [
        {
            "hostname": "app.example.invalid",
            "ip": "198.51.100.10",
            "record_type": "A",
        }
    ]
