from __future__ import annotations

import logging

import procrastinate

from easm.queue import app

logger = logging.getLogger(__name__)


@app.task(
    queue="runner",
    retry=procrastinate.RetryStrategy(max_attempts=4, exponential_wait=2),
)
async def execute_runner(
    *,
    runner_name: str,
    target_id: str,
    trigger_type: str,
    org_id: str = "default",
) -> dict:
    from easm.runners import get_all_runners
    from easm.runners.engine import execute_runner as run_fn
    from easm.runtime import get_runtime
    from easm.worker_context import get_config, get_store

    store = get_store()
    config = get_config()

    target = None
    for t in config.targets:
        if t.id == target_id:
            target = t
            break
    if not target:
        raise ValueError(f"Target {target_id} not found in config")

    runners = get_all_runners()
    if runner_name not in runners:
        raise ValueError(f"Runner {runner_name} not registered")

    runner_def = runners[runner_name]
    runtime = get_runtime()
    http_client = runtime.make_http_client()

    try:
        run_id = await run_fn(
            runner_def.source_name,
            runner_def.run_fn,
            target,
            store,
            trigger_type,
            http_client=http_client,
        )
        return {"run_id": str(run_id)}
    finally:
        await http_client.aclose()
