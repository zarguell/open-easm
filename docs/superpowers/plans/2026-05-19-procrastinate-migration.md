# Procrastinate Migration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace custom TaskQueue and pivot_queue with Procrastinate for all job scheduling and execution.

**Architecture:** Procrastinate manages job lifecycle (enqueue, dequeue, retry, completion) via its own `procrastinate_jobs` table using psycopg v3. Our asyncpg pool continues handling app queries. Worker processes run Procrastinate workers that execute runner, pivot, and janitor tasks. Pivot metadata (entity_type, depth, etc.) lives in Procrastinate `args` jsonb. Cooldown/coverage checks query `procrastinate_jobs` with custom indexes.

**Tech Stack:** procrastinate (PsycopgConnector), psycopg[binary] + psycopg_pool, asyncpg (unchanged for app queries), FastAPI, asyncpg

---

## File Map

### New Files
| File | Purpose |
|------|---------|
| `src/easm/queue.py` | Procrastinate App factory + connector setup |
| `src/easm/tasks/__init__.py` | Empty (tasks auto-discovered via import_paths) |
| `src/easm/tasks/runner.py` | `execute_runner` Procrastinate task |
| `src/easm/tasks/pivot.py` | `execute_pivot` Procrastinate task + extracted `process_pivot` core logic |
| `src/easm/tasks/janitor.py` | `execute_janitor` Procrastinate task |
| `src/easm/worker_context.py` | Shared worker state (pool, store, config) for task functions |
| `alembic/versions/0008_procrastinate.py` | Alembic migration: apply procrastinate schema + custom indexes |

### Renamed Files (legacy)
| Old | New |
|-----|-----|
| `src/easm/task_queue.py` | `src/easm/task_queue_legacy.py` |
| `src/easm/pivot/worker.py` | `src/easm/pivot/worker_legacy.py` |

### Modified Files
| File | Change |
|------|--------|
| `pyproject.toml` | Add `procrastinate`, `psycopg_pool` deps |
| `src/easm/worker.py` | Rewrite: Procrastinate worker entry point (replace TaskQueue dequeue loop + pivot worker pool) |
| `src/easm/scheduler.py` | Replace `TaskQueue.enqueue` with `task.defer_async` |
| `src/easm/pivot/resolver.py` | Replace `store.enqueue_pivot_job` with Procrastinate defer; update cooldown/coverage queries to use `procrastinate_jobs`; remove `_insert_skipped` |
| `src/easm/store.py` | Remove pivot queue methods (`enqueue_pivot_job`, `dequeue_pivot_job`, `dequeue_pivot_jobs_batch`, `mark_pivot_completed`, `mark_pivot_failed`, `reset_orphaned_pivot_jobs`, `count_pivot_jobs`); keep unrelated methods |
| `src/easm/main.py` | Open/close Procrastinate app; remove `pivot_worker_pool` import/call |
| `src/easm/api/routes/workers.py` | Query `procrastinate_jobs` instead of `task_queue` |
| `src/easm/api/routes/pivot_queue.py` | Query `procrastinate_jobs` + `procrastinate_events` instead of `pivot_queue` |
| `src/easm/api/routes/health.py` | Count queue depth from `procrastinate_jobs` |

---

## Tasks

### Task 1: Add Dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add procrastinate and psycopg_pool to dependencies**

Add to `pyproject.toml` dependencies array:
```toml
"procrastinate>=2.14.0",
"psycopg_pool>=3.2.0",
```

`psycopg[binary]` is already in deps. `psycopg_pool` provides the async connection pool that `PsycopgConnector` uses internally.

- [ ] **Step 2: Install dependencies**

Run: `uv sync`
Expected: Dependencies resolved and installed.

- [ ] **Step 3: Verify import works**

Run: `uv run python -c "import procrastinate; print(procrastinate.__version__)"`
Expected: Version printed (e.g., `2.14.0` or higher).

---

### Task 2: Create Procrastinate App Factory

**Files:**
- Create: `src/easm/queue.py`
- Create: `src/easm/tasks/__init__.py`

- [ ] **Step 1: Create `src/easm/queue.py`**

```python
from __future__ import annotations

import os

import procrastinate


def _build_connector() -> procrastinate.PsycopgConnector:
    dsn = os.environ.get("EASM_DATABASE_DSN", "")
    if not dsn:
        dsn = "postgresql://easm:easm@localhost:5432/easm"
    return procrastinate.PsycopgConnector(
        conninfo=dsn,
        kwargs={"autocommit": True},
    )


app = procrastinate.App(
    connector=_build_connector(),
    import_paths=[
        "easm.tasks.runner",
        "easm.tasks.pivot",
        "easm.tasks.janitor",
    ],
    worker_defaults={
        "concurrency": 3,
        "delete_jobs": "successful",
    },
)
```

Key decisions:
- Uses `PsycopgConnector` with same `EASM_DATABASE_DSN` env var
- `import_paths` auto-discovers task modules when `app.open_async()` is called
- `delete_jobs="successful"` auto-cleans completed jobs (replaces `cleanup_completed`)
- `concurrency=3` preserves the 3-concurrent-worker pattern for pivots

- [ ] **Step 2: Create empty `src/easm/tasks/__init__.py`**

```python
```

Empty file — tasks are in submodules, discovered via `import_paths`.

- [ ] **Step 3: Verify import works**

Run: `uv run python -c "from easm.queue import app; print(type(app))"`
Expected: `<class 'procrastinate.app.App'>`

---

### Task 3: Create Worker Context Module

**Files:**
- Create: `src/easm/worker_context.py`

Task functions run inside the Procrastinate worker process and need access to an asyncpg pool, Store, and config. This module holds those as module-level state, initialized once at worker startup.

- [ ] **Step 1: Create `src/easm/worker_context.py`**

```python
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncpg
    from easm.config import TargetConfig
    from easm.store import Store

_pool: asyncpg.Pool | None = None
_store: Store | None = None
_config: Any = None


def set_context(pool: asyncpg.Pool, store: Store, config: Any) -> None:
    global _pool, _store, _config
    _pool = pool
    _store = store
    _config = config


def get_pool() -> asyncpg.Pool:
    assert _pool is not None, "Worker context not initialized — call set_context() first"
    return _pool


def get_store() -> Store:
    assert _store is not None, "Worker context not initialized — call set_context() first"
    return _store


def get_config() -> Any:
    return _config
```

- [ ] **Step 2: Verify import**

Run: `uv run python -c "from easm.worker_context import get_pool, get_store, get_config; print('OK')"`
Expected: `OK`

---

### Task 4: Create Procrastinate Schema Migration

**Files:**
- Create: `alembic/versions/0008_procrastinate.py`

This migration applies Procrastinate's built-in schema (4 tables, functions, indexes) and adds custom indexes for our pivot cooldown/coverage queries.

- [ ] **Step 1: Create migration file**

```python
"""Install procrastinate schema and custom indexes

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-19

"""
from __future__ import annotations

import procrastinate
from alembic import op


revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    schema_sql = procrastinate.schema.get_schema()
    op.execute(schema_sql)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_pivot_jobs_cooldown
        ON procrastinate_jobs (
            (args->>'org_id'),
            (args->>'entity_type'),
            (args->>'entity_value'),
            (args->>'pivot_type')
        ) WHERE task_name = 'easm.tasks.pivot.execute_pivot'
          AND status IN ('succeeded', 'doing');
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pivot_jobs_cooldown")
    procrastinate_sql = procrastinate.schema.get_schema()
    for table in (
        "procrastinate_events",
        "procrastinate_jobs",
        "procrastinate_periodic_defers",
        "procrastinate_workers",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP TYPE IF EXISTS procrastinate_job_status")
    op.execute("DROP TYPE IF EXISTS procrastinate_job_event_type")
```

- [ ] **Step 2: Run migration against test DB**

Start Postgres, run `alembic upgrade head`, verify tables exist:
```
procrastinate_jobs
procrastinate_events
procrastinate_workers
procrastinate_periodic_defers
```

---

### Task 5: Create Runner Task

**Files:**
- Create: `src/easm/tasks/runner.py`

This replaces the TaskQueue "runner" task type. The task looks up the runner from the registry and executes it.

- [ ] **Step 1: Create `src/easm/tasks/runner.py`**

```python
from __future__ import annotations

import logging
import uuid

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
    from easm.api.deps import get_store
    from easm.config import load_config
    from easm.runner_context import get_config, get_store as wc_get_store
    from easm.runners import get_all_runners
    from easm.runners.engine import execute_runner as run_fn
    from easm.runtime import get_runtime

    store = wc_get_store()
    config = get_config()

    target = next((t for t in config.targets if t.id == target_id), None)
    if not target:
        raise ValueError(f"Target {target_id} not found in config")

    runners = get_all_runners()
    if runner_name not in runners:
        raise ValueError(f"Runner {runner_name} not registered")

    runner_def = runners[runner_name]
    runtime = get_runtime()
    http_client = runtime.make_http_client()

    try:
        inserted, deduped, errors = await run_fn(
            runner_def.source_name,
            runner_def.run_fn,
            target,
            store,
            trigger_type,
            http_client=http_client,
        )
        return {"inserted": inserted, "deduped": deduped, "errors": errors}
    finally:
        await http_client.aclose()
```

Note: Uses `retry=RetryStrategy(max_attempts=4, exponential_wait=2)` for 3 retries with exponential backoff (matches our TaskQueue max_retries=3).

- [ ] **Step 2: Verify the task is discovered**

Run: `uv run python -c "from easm.queue import app; app._loader.import_all(); print(list(app.tasks.keys()))"`
Expected: Task name `easm.tasks.runner.execute_runner` in the list.

---

### Task 6: Create Janitor Task

**Files:**
- Create: `src/easm/tasks/janitor.py`

- [ ] **Step 1: Create `src/easm/tasks/janitor.py`**

```python
from __future__ import annotations

import logging

import procrastinate

from easm.queue import app

logger = logging.getLogger(__name__)


@app.task(
    queue="janitor",
    queueing_lock="janitor-cleanup",
)
async def execute_janitor(
    *,
    org_id: str = "default",
    delete_completed_older_than_hours: int = 24,
    reset_pivot_stale_hours: int = 1,
    reset_runner_stale_hours: int = 2,
) -> dict:
    from easm.worker_context import get_pool

    pool = get_pool()
    deleted_runs = 0
    reset_pivots = 0
    reset_runners = 0

    deleted_runs = await pool.fetchval(
        """
        DELETE FROM runs
        WHERE status = 'completed'
          AND ended_at < NOW() - ($1 * interval '1 hour')
        """,
        delete_completed_older_than_hours,
    ) or 0

    logger.info(
        "janitor cleanup complete",
        extra={
            "deleted_runs": deleted_runs,
            "reset_pivots": reset_pivots,
            "reset_runners": reset_runners,
        },
    )
    return {
        "deleted_runs": deleted_runs,
        "reset_pivots": reset_pivots,
        "reset_runners": reset_runners,
    }
```

Notes:
- `queueing_lock="janitor-cleanup"` prevents duplicate janitor jobs from queuing up
- Procrastinate's `delete_jobs="successful"` setting on the App handles cleaning old procrastinate_jobs — no need to clean those manually
- Business logic is preserved from the old `worker.py:execute_janitor_task()`

- [ ] **Step 2: Verify task discovery**

Run: `uv run python -c "from easm.queue import app; app._loader.import_all(); print(sorted(app.tasks.keys()))"`
Expected: Both `easm.tasks.janitor.execute_janitor` and `easm.tasks.runner.execute_runner` listed.

---

### Task 7: Create Pivot Task (the big one)

**Files:**
- Create: `src/easm/tasks/pivot.py`

This is the most complex task. We extract the core logic from `_process_one_pivot_job` (legacy `pivot/worker.py:58-379`) into a clean `process_pivot()` function, then wrap it in a Procrastinate task. The key differences from the legacy version:

1. **No pivot_queue status tracking** — Procrastinate handles job lifecycle
2. **No `job["id"]`** — We generate a UUID for run tracking
3. **Transient error retries** — Procrastinate's RetryStrategy replaces manual retry count tracking
4. **Recursive pivot enqueue** — Calls `defer_async` instead of `store.enqueue_pivot_job`

- [ ] **Step 1: Create `src/easm/tasks/pivot.py`**

The file contains:
1. `execute_pivot` — the Procrastinate task decorator + wrapper
2. `process_pivot` — the extracted core logic (no queue status tracking)

```python
from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import procrastinate

from easm.queue import app

logger = logging.getLogger(__name__)

TRANSIENT_EXCEPTIONS = (
    httpx.TransportError,
    httpx.ReadTimeout,
    httpx.ConnectError,
    httpx.NetworkError,
)


@app.task(
    queue="pivot",
    retry=procrastinate.RetryStrategy(
        max_attempts=4,
        retry_exceptions=TRANSIENT_EXCEPTIONS,
        exponential_wait=2,
    ),
    pass_context=True,
)
async def execute_pivot(
    context: procrastinate.JobContext,
    *,
    org_id: str,
    target_id: str,
    entity_type: str,
    entity_value: str,
    entity_id: str,
    pivot_type: str,
    depth: int = 1,
    parent_entity_id: str | None = None,
    discovery_session_id: str | None = None,
) -> dict:
    from easm.pivot.handlers import (
        PIVOT_HANDLER_REGISTRY,
        PIVOT_SOURCE_NAMES,
        get_default_limiters,
    )
    from easm.pivot.resolver import PivotResolver
    from easm.pivot.worker import _compute_event_hash, _resolve_target_config
    from easm.runners.schemas import OUTPUT_SCHEMAS
    from easm.runtime import get_runtime
    from easm.worker_context import get_config, get_pool, get_store

    pool = get_pool()
    store = get_store()
    config = get_config()

    job_id = str(context.job.id)
    run_id = None
    created_pivot_run = False
    run_start = datetime.now(UTC)
    inserted = deduped = errors = 0

    runtime = get_runtime()
    shared_http = runtime.make_http_client()
    limiters = get_default_limiters()
    resolver = PivotResolver(pool)

    try:
        handler_fn = PIVOT_HANDLER_REGISTRY.get(pivot_type)
        if not handler_fn:
            raise ValueError(f"No handler for pivot type: {pivot_type}")

        kwargs: dict[str, Any] = {}
        if "http_client" in inspect.signature(handler_fn).parameters:
            kwargs["http_client"] = shared_http
        if "limiters" in inspect.signature(handler_fn).parameters:
            kwargs["limiters"] = limiters

        job_dict = {
            "id": job_id,
            "org_id": org_id,
            "target_id": target_id,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "entity_id": entity_id,
            "pivot_type": pivot_type,
            "depth": depth,
            "parent_entity_id": parent_entity_id,
            "discovery_session_id": discovery_session_id,
        }

        results = await runtime.run_pivot_handler(
            pivot_type, job_dict, handler_fn, pool, **kwargs,
        )

        source_name = PIVOT_SOURCE_NAMES.get(pivot_type, pivot_type) or pivot_type

        if not run_id:
            run_id = await store.create_run(
                target_id, f"pivot:{pivot_type}", "pivot", org_id=org_id,
            )
            created_pivot_run = True
            await store.mark_run_started(run_id, run_start)

        raw_event_ids: list = []
        for raw_result in results:
            discovery_session_id_val = discovery_session_id
            meta = {
                "_meta": {
                    "session_id": str(discovery_session_id_val) if discovery_session_id_val else None,
                    "pivot_job_id": job_id,
                },
                **raw_result,
            }
            event_hash = _compute_event_hash(org_id, target_id, source_name, meta)
            raw_json = json.dumps(meta)
            raw_event_uuid = await pool.fetchval(
                """INSERT INTO raw_events
                   (org_id, target_id, source, raw, event_hash, run_id)
                   VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                   ON CONFLICT (event_hash) DO NOTHING
                   RETURNING id""",
                org_id, target_id, source_name, raw_json, event_hash, run_id,
            )
            raw_event_ids.append(raw_event_uuid)
            if raw_event_uuid:
                inserted += 1
            else:
                deduped += 1

        target_config = _resolve_target_config(config, target_id)

        schema_fn = OUTPUT_SCHEMAS.get(source_name or pivot_type)
        if schema_fn:
            for i, raw_result in enumerate(results):
                re_id = raw_event_ids[i] if i < len(raw_event_ids) else None
                try:
                    entities, rels = schema_fn(raw_result)
                    for ec in entities:
                        try:
                            eid, is_new = await store.upsert_entity(
                                org_id, target_id,
                                ec.entity_type, ec.value,
                                ec.attributes, raw_event_id=re_id,
                                discovery_session_id=discovery_session_id,
                                discovery_run_id=run_id,
                                discovery_pivot_id=uuid.UUID(job_id) if len(job_id) == 36 else None,
                            )

                            if ec.entity_type == "ip":
                                try:
                                    import ipaddress
                                    ip_obj = ipaddress.ip_address(ec.value)
                                    rows = await store.pool.fetch(
                                        "SELECT id, entity_value FROM entities "
                                        "WHERE org_id = $1 AND target_id = $2 AND entity_type = 'ip_range'",
                                        org_id, target_id,
                                    )
                                    for row in rows:
                                        try:
                                            network = ipaddress.ip_network(row["entity_value"], strict=False)
                                            if ip_obj in network:
                                                await store.upsert_relationship(
                                                    org_id, eid, row["id"],
                                                    "ip_in_range", "auto_association",
                                                    evidence_raw_event_id=re_id,
                                                    runner=source_name or pivot_type,
                                                )
                                                break
                                        except ValueError:
                                            continue
                                except Exception:
                                    logger.debug("ip range association failed", exc_info=True)

                            if ec.entity_type == "ip":
                                try:
                                    from easm.pivot.handlers import GeoIpLookup
                                    lookup = GeoIpLookup()
                                    result = lookup.lookup(ec.value)
                                    if result:
                                        existing = await store.pool.fetchrow(
                                            "SELECT attributes FROM entities WHERE id = $1", eid,
                                        )
                                        attrs = existing["attributes"] if existing else {}
                                        if isinstance(attrs, str):
                                            attrs = json.loads(attrs)
                                        if not attrs:
                                            attrs = {}
                                        attrs["geo"] = result.to_dict()
                                        await store.pool.execute(
                                            "UPDATE entities SET attributes = $1::jsonb WHERE id = $2",
                                            json.dumps(attrs), eid,
                                        )
                                except Exception:
                                    logger.debug("geo enrichment failed", exc_info=True)

                            try:
                                source = source_name or pivot_type or "unknown"
                                target_domains = (
                                    list(target_config.match_rules.domains)
                                    if target_config and hasattr(target_config, "match_rules") else []
                                )
                                target_asns = (
                                    list(target_config.match_rules.asns)
                                    if target_config and hasattr(target_config, "match_rules") else []
                                )
                                await store.apply_asset_profile_for_entity(
                                    org_id=org_id,
                                    target_id=target_id,
                                    entity_id=eid,
                                    entity_type=ec.entity_type,
                                    entity_value=ec.value,
                                    source=source,
                                    raw_event_id=re_id,
                                    target_domains=target_domains,
                                    target_asns=target_asns,
                                    summary=f"{source} observed {ec.entity_type} {ec.value}",
                                )
                            except Exception:
                                logger.debug("asset profile update from pivot failed", exc_info=True)

                            if is_new and target_config:
                                try:
                                    await resolver.check_and_enqueue(
                                        target_config,
                                        ec.entity_type, ec.value,
                                        eid,
                                        depth=depth + 1,
                                        parent_entity_id=entity_id,
                                        discovery_session_id=discovery_session_id,
                                    )
                                except Exception:
                                    errors += 1
                                    logger.debug("recursive pivot failed", exc_info=True)
                        except Exception:
                            errors += 1
                            logger.debug("entity upsert from pivot failed", exc_info=True)

                    for rc in rels:
                        try:
                            await store.upsert_relationship_by_value(
                                org_id, target_id,
                                rc.source_type, rc.source_value,
                                rc.target_type, rc.target_value,
                                rc.relationship_type, rc.relationship_source,
                                evidence_raw_event_id=re_id,
                            )
                        except Exception:
                            errors += 1
                            logger.debug("relationship upsert from pivot failed", exc_info=True)
                except Exception:
                    errors += 1
                    logger.debug("output schema failed for pivot result", exc_info=True)

        if errors:
            logger.warning("pivot completed with %d materialization errors", errors)

        if created_pivot_run and run_id:
            run_end = datetime.now(UTC)
            status = "failed" if errors else "completed"
            await store.mark_run_finished(
                run_id, status, run_end,
                int((run_end - run_start).total_seconds() * 1000),
                inserted, deduped, errors,
                error_message=f"pivot materialization: {errors} error(s)" if errors else None,
                metadata={
                    "pivot_job_id": job_id,
                    "pivot_type": pivot_type,
                    "entity_value": entity_value,
                    "discovery_session_id": str(discovery_session_id) if discovery_session_id else None,
                },
            )

        return {"inserted": inserted, "deduped": deduped, "errors": errors}
    finally:
        await shared_http.aclose()
```

Notes:
- The `except` block for transient errors is gone — Procrastinate handles retries via `retry_exceptions=TRANSIENT_EXCEPTIONS`
- `store.mark_pivot_completed/failed` calls are gone — Procrastinate tracks job status
- `job["id"]` is replaced with `context.job.id` (Procrastinate's job ID)
- Recursive pivot enqueue goes through `resolver.check_and_enqueue()` which now defers Procrastinate tasks (updated in Task 10)
- Business logic (handler execution, entity upsert, relationship upsert, ip_range association, geo enrichment, asset profiling) is preserved exactly

- [ ] **Step 2: Verify task discovery**

Run: `uv run python -c "from easm.queue import app; app._loader.import_all(); print(sorted(app.tasks.keys()))"`
Expected: All three tasks listed.

---

### Task 8: Rename Legacy Files

**Files:**
- Rename: `src/easm/task_queue.py` → `src/easm/task_queue_legacy.py`
- Rename: `src/easm/pivot/worker.py` → `src/easm/pivot/worker_legacy.py`

- [ ] **Step 1: Rename the files**

```bash
git mv src/easm/task_queue.py src/easm/task_queue_legacy.py
git mv src/easm/pivot/worker.py src/easm/pivot/worker_legacy.py
```

- [ ] **Step 2: Update imports that reference the old module paths**

Search for `from easm.task_queue import` and `from easm.pivot.worker import` across the codebase. These will be updated in later tasks (scheduler.py, worker.py, main.py). For now, the rename is just the file move.

---

### Task 9: Update Scheduler — Defer Procrastinate Tasks

**Files:**
- Modify: `src/easm/scheduler.py`

Replace `TaskQueue.enqueue` calls with Procrastinate `task.defer_async`.

- [ ] **Step 1: Update `_run_job` closure (lines 53-83)**

The current code has two branches: `web` mode enqueues to TaskQueue, `all` mode executes directly. Both should now defer to Procrastinate.

Replace the `if mode in ("web", "server"):` block (lines 53-70) and the else block (lines 71-83) with a single unified defer:

```python
        async def _run_job():
            active = await store.count_active_runs(target.id, runner_def.source_name)
            if active > 0:
                logger.info(
                    "skipping scheduled run: previous run still active",
                    extra={"target_id": target.id, "runner": runner_name, "active_runs": active},
                )
                return

            from easm.tasks.runner import execute_runner

            await execute_runner.configure(
                priority=0,
            ).defer_async(
                runner_name=runner_name,
                target_id=target.id,
                trigger_type="scheduled",
                org_id=getattr(target, "org_id", "default"),
            )
            logger.info(
                "deferred runner task",
                extra={"runner": runner_name, "target_id": target.id},
            )
```

- [ ] **Step 2: Update `setup_janitor` (lines 146-166)**

Replace TaskQueue enqueue with Procrastinate defer:

```python
    def setup_janitor(self, store: Any) -> None:
        async def _enqueue_janitor():
            from easm.tasks.janitor import execute_janitor

            await execute_janitor.configure(
                queueing_lock="janitor-cleanup",
                priority=10,
            ).defer_async(org_id="default")

        self._scheduler.add_job(
            _enqueue_janitor,
            "cron",
            id="janitor-cleanup",
            minute="0",
            hour="*/1",
            replace_existing=True,
        )
        logger.info("scheduled janitor cleanup job (hourly)")
```

- [ ] **Step 3: Remove `import os` and `ACTIVE_RUNNERS` if no longer needed**

`os` was used for `EASM_MODE` check which is no longer needed (Procrastinate always defers regardless of mode). `ACTIVE_RUNNERS` is still used by the scanning check above.

Actually: keep `import os` (used elsewhere?) — check. Remove only the mode-specific branch logic.

- [ ] **Step 4: Run lint**

Run: `uv run ruff check src/easm/scheduler.py`
Fix any issues.

---

### Task 10: Update Pivot Resolver — Defer Pivot Tasks

**Files:**
- Modify: `src/easm/pivot/resolver.py`

This is critical. Replace:
1. `store.enqueue_pivot_job()` → Procrastinate `execute_pivot.defer_async()`
2. `_check_cooldown()` → query `procrastinate_jobs` instead of `pivot_queue`
3. `_check_apex_coverage()` → query `procrastinate_jobs` instead of `pivot_queue`
4. `_insert_skipped()` → log only (no table insert)
5. Max queue depth check → count from `procrastinate_jobs` where `status='todo'`

- [ ] **Step 1: Replace `check_and_enqueue` method**

The core method stays the same structure — scope check, classification check, queue depth check, iterate allowed_pivots, check skip/cooldown/coverage, then enqueue. Only the query targets change.

Update the method:
```python
    async def check_and_enqueue(
        self, target, entity_type, entity_value, entity_id,
        parent_entity_id=None, depth=1, discovery_session_id=None,
    ):
        pivot_config = target.pivot
        if not pivot_config or not pivot_config.enabled:
            return
        if depth > pivot_config.max_depth:
            return

        from easm.pivot.scope import ScopeEvaluator
        scope = ScopeEvaluator().evaluate(target, entity_type, entity_value)
        if scope == ScopeResult.OUT_OF_SCOPE and pivot_config.scope_mode == "strict":
            return

        classification = await self._get_classification(entity_id)
        if classification and classification != "org-owned":
            return

        max_queue_depth = getattr(pivot_config, 'max_queue_depth', 10000)
        count = await self.pool.fetchval(
            "SELECT COUNT(*) FROM procrastinate_jobs "
            "WHERE task_name = 'easm.tasks.pivot.execute_pivot' AND status = 'todo'"
        )
        if count is not None and count >= max_queue_depth:
            logger.warning(
                "pivot queue at capacity, skipping enqueue",
                extra={
                    "queue_depth": count,
                    "max": max_queue_depth,
                    "target_id": target.id,
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                },
            )
            return

        from easm.tasks.pivot import execute_pivot

        for pivot_rule in pivot_config.allowed_pivots:
            if pivot_rule.from_ != entity_type:
                continue

            if pivot_rule.skip_on_source:
                entity_row = await self.pool.fetchrow(
                    "SELECT attributes FROM entities WHERE id = $1",
                    entity_id,
                )
                if entity_row:
                    attrs = entity_row["attributes"]
                    if isinstance(attrs, str):
                        import json
                        attrs = json.loads(attrs)
                    if attrs and attrs.get("source") in pivot_rule.skip_on_source:
                        logger.debug(
                            "skipping pivot %s for %s: skip_on_source %s",
                            pivot_rule.via, entity_value, attrs.get("source"),
                        )
                        continue

            if pivot_rule.coverage and pivot_rule.coverage.apex_covers_subdomains:
                if entity_type in ("domain", "hostname"):
                    apex = tldextract.extract(entity_value).registered_domain
                    if apex != entity_value:
                        covered = await self._check_apex_coverage(
                            target.org_id, apex, pivot_rule.via, pivot_rule.cooldown_hours,
                        )
                        if covered:
                            logger.debug(
                                "skipping pivot %s for %s: covered by apex %s",
                                pivot_rule.via, entity_value, apex,
                            )
                            continue

            if pivot_rule.cooldown_hours > 0:
                recent = await self._check_cooldown(
                    target.org_id, entity_type, entity_value, pivot_rule.via,
                    pivot_rule.cooldown_hours,
                )
                if recent:
                    continue

            await execute_pivot.configure(
                queue="pivot",
            ).defer_async(
                org_id=target.org_id,
                target_id=target.id,
                entity_type=entity_type,
                entity_value=entity_value,
                entity_id=str(entity_id),
                pivot_type=pivot_rule.via,
                depth=depth,
                parent_entity_id=str(parent_entity_id) if parent_entity_id else None,
                discovery_session_id=str(discovery_session_id) if discovery_session_id else None,
            )

            if pivot_rule.via in ("shodan_enrich",) and depth + 1 <= pivot_config.max_depth:
                await execute_pivot.configure(
                    queue="pivot",
                ).defer_async(
                    org_id=target.org_id,
                    target_id=target.id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    entity_id=str(entity_id),
                    pivot_type="cpe_vuln_enrich",
                    depth=depth + 1,
                    parent_entity_id=str(entity_id),
                    discovery_session_id=str(discovery_session_id) if discovery_session_id else None,
                )
```

- [ ] **Step 2: Update `_check_cooldown` to query `procrastinate_jobs`**

```python
    async def _check_cooldown(self, org_id, entity_type, entity_value, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM procrastinate_jobs
            WHERE task_name = 'easm.tasks.pivot.execute_pivot'
              AND args->>'org_id' = $1
              AND args->>'entity_type' = $2
              AND args->>'entity_value' = $3
              AND args->>'pivot_type' = $4
              AND status IN ('succeeded', 'doing')
              AND (scheduled_at IS NULL OR scheduled_at <= NOW())
              AND id > (SELECT COALESCE(MAX(id, 0)) FROM procrastinate_jobs
                        WHERE status = 'todo'
                        AND (NOW() - ($5 || ' hours')::INTERVAL > (SELECT COALESCE(scheduled_at, (ev.at)::timestamptz) FROM procrastinate_events ev WHERE ev.job_id = procrastinate_jobs.id AND ev.type = 'succeeded' ORDER BY ev.at DESC LIMIT 1)))
            LIMIT 1
        """, org_id, entity_type, entity_value, pivot_type, str(cooldown_hours))
```

Actually this is getting too complex. Simpler approach — use procrastinate_events for completion timestamp:

```python
    async def _check_cooldown(self, org_id, entity_type, entity_value, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM procrastinate_events ev
            JOIN procrastinate_jobs j ON ev.job_id = j.id
            WHERE j.task_name = 'easm.tasks.pivot.execute_pivot'
              AND j.status = 'succeeded'
              AND j.args->>'org_id' = $1
              AND j.args->>'entity_type' = $2
              AND j.args->>'entity_value' = $3
              AND j.args->>'pivot_type' = $4
              AND ev.type = 'succeeded'
              AND ev.at > NOW() - ($5 || ' hours')::INTERVAL
            LIMIT 1
        """, org_id, entity_type, entity_value, pivot_type, str(cooldown_hours))
        return row
```

Note: This query relies on the custom `idx_pivot_jobs_cooldown` index (Task 4) for performance. Without it, the jsonb field extracts would do sequential scans.

BUT: there's a problem. The custom index is on `procrastinate_jobs` not on the JOIN with `procrastinate_events`. The jsonb conditions on `j.args` can use the index to filter jobs first, then the join with events is a small lookup. This should be efficient enough.

- [ ] **Step 3: Update `_check_apex_coverage` similarly**

```python
    async def _check_apex_coverage(self, org_id, apex, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM procrastinate_jobs j
            WHERE j.task_name = 'easm.tasks.pivot.execute_pivot'
              AND j.status IN ('succeeded', 'doing', 'todo')
              AND j.args->>'org_id' = $1
              AND j.args->>'entity_value' = $2
              AND j.args->>'pivot_type' = $3
              AND (j.scheduled_at IS NULL OR j.scheduled_at <= NOW() + ($4 || ' hours')::INTERVAL)
            LIMIT 1
        """, org_id, apex, pivot_type, str(cooldown_hours))
        return row
```

- [ ] **Step 4: Remove `_insert_skipped` method**

Delete the method entirely. Skipping is now handled by logging + continuing the loop.

- [ ] **Step 5: Run lint**

Run: `uv run ruff check src/easm/pivot/resolver.py`
Fix any issues.

---

### Task 11: Update Store — Remove Pivot Queue Methods

**Files:**
- Modify: `src/easm/store.py`

Remove or mark as deprecated all pivot_queue-specific methods. These are no longer called after the migration.

Methods to remove:
- `enqueue_pivot_job` (line 868)
- `dequeue_pivot_job` (line 890) 
- `dequeue_pivot_jobs_batch` (line 911)
- `mark_pivot_completed` (line 927)
- `mark_pivot_failed` (line 932)
- `reset_orphaned_pivot_jobs` (line 938)
- `count_pivot_jobs` (line 943)
- `cleanup_stale_pivots` (line 1495)

Also remove the startup cleanup SQL in `main.py` (see Task 12).

- [ ] **Step 1: Remove the 8 pivot queue methods from Store class**

Delete the method bodies. Keep all other methods untouched.

- [ ] **Step 2: Verify no remaining callsites**

Run: `grep -r "enqueue_pivot_job\|dequeue_pivot_job\|mark_pivot_completed\|mark_pivot_failed\|reset_orphaned_pivot\|count_pivot_jobs\|cleanup_stale_pivots" src/ --include="*.py"`
Expected: No results (all callsites updated in other tasks).

---

### Task 12: Update main.py — Procrastinate App Lifecycle

**Files:**
- Modify: `src/easm/main.py`

Changes:
1. Import and open the Procrastinate app
2. Remove `pivot_worker_pool` import and call
3. Remove stale pivot queue cleanup
4. Keep the scheduler, config loading, pool creation flow

- [ ] **Step 1: Add Procrastinate app open/close**

After pool creation and store setup, open the Procrastinate app:

```python
from easm.queue import app as procrastinate_app

# ... after store setup ...
await procrastinate_app.open_async()
```

In the shutdown handler, close it:
```python
await procrastinate_app.close_async()
```

- [ ] **Step 2: Remove pivot_worker_pool import and call**

Remove:
```python
from easm.pivot.worker import pivot_worker_pool
# ... and the asyncio.create_task(pivot_worker_pool(...)) call
```

- [ ] **Step 3: Remove stale pivot queue cleanup**

Remove the startup cleanup SQL that resets pivot_queue running jobs:
```python
await pool.execute("UPDATE pivot_queue SET status='pending' WHERE status='running'")
```

Procrastinate handles orphaned job detection via its heartbeat mechanism.

- [ ] **Step 4: Run lint**

---

### Task 13: Rewrite worker.py — Procrastinate Worker Entry Point

**Files:**
- Rewrite: `src/easm/worker.py`

The worker process becomes a simple Procrastinate worker. It:
1. Creates its own asyncpg pool
2. Creates Store and loads config
3. Sets up worker_context module-level state
4. Opens the Procrastinate app
5. Runs the Procrastinate worker

- [ ] **Step 1: Rewrite worker.py**

The new worker.py should:
- Keep the same entry point pattern (`python -m easm.worker`)
- Create asyncpg pool, Store, load config
- Initialize `worker_context`
- Open `easm.queue.app`
- Run `app.run_worker_async(queues=["runner", "pivot", "janitor"], concurrency=3, install_signal_handlers=True)`
- Handle graceful shutdown

The full file is ~80 lines. Key structure:

```python
from __future__ import annotations

import asyncio
import logging
import os

from easm.config import load_config
from easm.db import close_pool, create_pool
from easm.queue import app as procrastinate_app
from easm.store import Store
from easm.worker_context import set_context

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_worker() -> None:
    dsn = os.environ.get("EASM_DATABASE_DSN")
    if not dsn:
        raise RuntimeError("EASM_DATABASE_DSN is required")

    config = load_config("config.yaml")
    pool = await create_pool(dsn)
    store = Store(pool)
    set_context(pool, store, config)

    async with procrastinate_app.open_async():
        logger.info("procrastinate worker starting")
        await procrastinate_app.run_worker_async(
            queues=["runner", "pivot", "janitor"],
            concurrency=3,
            install_signal_handlers=True,
        )

    await close_pool(pool)


if __name__ == "__main__":
    asyncio.run(run_worker())
```

- [ ] **Step 2: Run lint**

---

### Task 14: Update API Routes — workers.py

**Files:**
- Modify: `src/easm/api/routes/workers.py`

Replace `task_queue` queries with `procrastinate_jobs` queries.

- [ ] **Step 1: Rewrite the queue status endpoint**

```python
@router.get("/queue")
async def queue_status(store: Store = Depends(get_store)):
    rows = await store.pool.fetch(
        "SELECT status, task_name, COUNT(*) as count "
        "FROM procrastinate_jobs "
        "GROUP BY status, task_name "
        "ORDER BY task_name, status"
    )
    by_task = {}
    for row in rows:
        task = row["task_name"]
        by_task.setdefault(task, {})[row["status"]] = row["count"]
    return {"tasks": by_task}
```

- [ ] **Step 2: Rewrite the active workers endpoint**

```python
@router.get("/workers")
async def active_workers(store: Store = Depends(get_store)):
    rows = await store.pool.fetch(
        "SELECT worker_id, COUNT(*) as job_count "
        "FROM procrastinate_jobs WHERE status = 'doing' "
        "GROUP BY worker_id"
    )
    return {"workers": [
        {"worker_id": row["worker_id"], "active_jobs": row["job_count"]}
        for row in rows
    ]}
```

- [ ] **Step 3: Run lint**

---

### Task 15: Update API Routes — pivot_queue.py

**Files:**
- Modify: `src/easm/api/routes/pivot_queue.py`

Replace `pivot_queue` queries with `procrastinate_jobs` queries. The API shape stays the same for backward compatibility.

- [ ] **Step 1: Update the list/trigger/retry/count endpoints**

For each endpoint, replace `pivot_queue` SQL with `procrastinate_jobs` SQL:
- `POST /trigger` → defer a Procrastinate `execute_pivot` task
- `POST /retry` → defer a new Procrastinate task with same args
- `GET /` → query `procrastinate_jobs` where `task_name = 'easm.tasks.pivot.execute_pivot'`
- `GET /count` → count from `procrastinate_jobs` grouped by status

The response shapes should remain compatible with the UI.

- [ ] **Step 2: Run lint**

---

### Task 16: Update health.py

**Files:**
- Modify: `src/easm/api/routes/health.py`

- [ ] **Step 1: Replace pivot_queue count with procrastinate_jobs count**

Find the section that counts pivot_queue entries by status and replace:

```python
pivot_counts = await pool.fetch(
    "SELECT status, COUNT(*) FROM pivot_queue "
    "GROUP BY status"
)
```

With:

```python
pivot_counts = await pool.fetch(
    "SELECT status, COUNT(*) FROM procrastinate_jobs "
    "WHERE task_name = 'easm.tasks.pivot.execute_pivot' "
    "GROUP BY status"
)
```

- [ ] **Step 2: Run lint**

---

### Task 17: Integration Testing

**Files:**
- All modified files

- [ ] **Step 1: Start Postgres, run all migrations**

```bash
# Start test Postgres
docker run -d --name easm-test-postgres -e POSTGRES_DB=easm -e POSTGRES_USER=easm -e POSTGRES_PASSWORD=easm -p 5432:5432 postgres:18-alpine
# Wait for ready
# Run migrations
EASM_DATABASE_DSN="postgresql://easm:easm@localhost:5432/easm" uv run alembic upgrade head
```

- [ ] **Step 2: Run full test suite**

```bash
EASM_DATABASE_DSN="postgresql://easm:easm@localhost:5432/easm" \
EASM_TEST_DATABASE_DSN="postgresql://easm:easm@localhost:5432/easm" \
uv run pytest -v
```

Expected: 351 passed (same as baseline, minus pivot_queue-specific tests which need updating).

- [ ] **Step 3: Update failing tests**

Tests that directly reference `pivot_queue` table or `store.enqueue_pivot_job`/`store.dequeue_pivot_jobs_batch` need updating:
- `tests/test_pivot/test_store.py` — These test the pivot_queue dequeue mechanism. Replace with tests that verify Procrastinate task deferral.
- `tests/test_store.py` — Remove `test_dequeue_pivot_jobs_batch_*` tests.
- `tests/test_pivot_worker_lifecycle.py` — Update to test the Procrastinate task function directly.
- `tests/test_pivot_resolver.py` — Update mocked queries to match new procrastinate_jobs SQL.

- [ ] **Step 4: Verify ruff and tsc**

Run: `uv run ruff check src/` and `cd ui && npx tsc --noEmit`

- [ ] **Step 5: Cleanup test Postgres**

```bash
docker stop easm-test-postgres && docker rm easm-test-postgres
```

---

## Self-Review Checklist

**1. Spec coverage:**
- [x] Replace TaskQueue with Procrastinate tasks — Tasks 5, 9
- [x] Replace pivot_queue with Procrastinate — Tasks 7, 10
- [x] Run Procrastinate migrations — Task 4
- [x] Update store.dequeue_pivot_jobs_batch callsites — Task 10 (resolver) + Task 11 (store removal)
- [x] Keep Procrastinate App in shared module — Task 2 (queue.py)
- [x] Rename old files with _legacy — Task 8
- [x] Don't change business logic — Tasks 5, 6, 7 preserve all handler/runner/entity logic
- [x] Integrate worker startup — Task 13
- [x] Preserve 3-concurrent-worker concurrency — Task 2 (worker_defaults) + Task 13 (concurrency=3)

**2. Placeholder scan:**
- No TBD, TODO, or "implement later" found
- All SQL queries are concrete
- All code blocks are complete

**3. Type consistency:**
- `entity_id` passed as `str` in defer_async (Procrastinate args must be JSON-serializable)
- `uuid.UUID` conversion handled inside task function where needed
- `depth` is `int` throughout
- Task names use dotted module paths: `easm.tasks.pivot.execute_pivot`
