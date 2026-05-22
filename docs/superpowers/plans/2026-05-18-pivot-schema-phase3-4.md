# Pivot Worker And Schema Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make simulated pivot execution observable and reliable, then remove schema registry ambiguity so “runner/pivot ran but produced no entities” becomes a tested failure mode instead of a surprise.

**Architecture:** First extract a one-batch pivot worker helper so tests can process queued jobs without starting an infinite worker pool. Then define explicit pivot materialization failure semantics. Finally collapse duplicate output schemas and add registry contracts requiring every runner/pivot source to have either an output schema or an explicit raw-only allowlist entry.

**Tech Stack:** Python 3.14, pytest, pytest-asyncio, asyncpg, Docker Compose, FastAPI-independent store/pivot tests.

**Constraints:**
- Do not make git commits.
- Do not run active scans or public target traffic.
- Keep all new dynamic behavior fixture-backed or DB-local.
- Preserve the canonical backend gate: `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test`.
- Any test needing Postgres must run through Docker with `EASM_TEST_DATABASE_DSN`.

---

## Scope

This plan covers Phase 3 and Phase 4 from [2026-05-18-test-gap-remediation.md](C:/Users/Zachary.Arguelles/code/open-easm/docs/superpowers/plans/2026-05-18-test-gap-remediation.md).

It intentionally does not cover:
- Runtime policy enforcement for live DNS/socket/subprocess pivots.
- UI tests.
- Ruff/mypy cleanup.
- Real external scanner binary integration.

---

## File Structure

**Create:**
- `tests/test_simulation_pivot_worker_integration.py` - DB-backed simulated pivot drain.
- `tests/test_pivot_worker_lifecycle.py` - missing handler, handler exception, and materialization failure semantics.
- `tests/test_schema_contracts.py` - output schema uniqueness and pivot source contract tests.
- `tests/test_runners/test_registry_contracts.py` - configured runner registry contract tests.

**Modify:**
- `src/easm/pivot/worker.py` - extract one-batch processing helper and fail materialization errors visibly.
- `src/easm/store.py` - make `dequeue_pivot_job()` atomic and return running status.
- `src/easm/runners/schemas.py` - remove duplicate function/schema block and add missing schema entries or explicit raw-only contract.
- `src/easm/runners/__init__.py` - attach schemas to legacy runner definitions where appropriate.
- `tests/test_pivot/test_store.py` - add single dequeue returned-status regression test.
- `AGENTS.md` - document raw-only runner/pivot sources after contract is finalized.

---

## Design Decisions

1. **Pivot worker helper:** Add `process_pivot_job_batch(pool, config, limit=20) -> int`. It processes at most one batch and returns the number of dequeued jobs. This is testable and lets `pivot_worker_pool()` keep its infinite loop.

2. **Materialization failure semantics:** If a pivot handler returns results but output schema, entity upsert, relationship upsert, or recursive enqueue fails, mark the pivot job `failed`. Raw events may still exist, but the job should not report `completed` when entity graph materialization failed.

3. **Schema source contract:** Every source in `PIVOT_SOURCE_NAMES.values()` and every registered runner name must be either in `OUTPUT_SCHEMAS` or in a named raw-only allowlist in tests and docs.

4. **Duplicate schemas:** `src/easm/runners/schemas.py` should define each schema function once and `OUTPUT_SCHEMAS` once.

---

## Task 1: Extract One-Batch Pivot Worker Helper

**Files:**
- Modify: `src/easm/pivot/worker.py`
- Create: `tests/test_simulation_pivot_worker_integration.py`

- [ ] **Step 1: Write failing integration test**

Create `tests/test_simulation_pivot_worker_integration.py`:

```python
from __future__ import annotations

import pytest

from easm.config import load_config
from easm.pivot.worker import process_pivot_job_batch
from easm.runtime import configure_runtime
from easm.store import Store


@pytest.mark.asyncio
@pytest.mark.db
@pytest.mark.simulation
async def test_simulated_dns_pivot_batch_writes_raw_event_and_ip_entity(db_pool) -> None:
    config = load_config("config.offline.yaml")
    configure_runtime(config.runtime)
    store = Store(db_pool)

    entity_id, _ = await store.upsert_entity(
        "default",
        "offline-local",
        "hostname",
        "app.example.invalid",
        {"source": "test"},
    )
    await store.enqueue_pivot_job(
        org_id="default",
        target_id="offline-local",
        entity_type="hostname",
        entity_value="app.example.invalid",
        entity_id=entity_id,
        pivot_type="dns_resolve",
        depth=1,
    )

    processed = await process_pivot_job_batch(db_pool, config, limit=20)

    assert processed == 1
    status = await db_pool.fetchval("SELECT status FROM pivot_queue")
    assert status == "completed"
    raw_count = await db_pool.fetchval(
        "SELECT COUNT(*) FROM raw_events WHERE source = 'dns'"
    )
    assert raw_count == 1
    ip_count = await db_pool.fetchval(
        """
        SELECT COUNT(*)
        FROM entities
        WHERE entity_type = 'ip'
          AND entity_value = '198.51.100.10'
        """
    )
    assert ip_count == 1
```

- [ ] **Step 2: Verify test fails for missing helper**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_pivot_worker_integration.py"
```

Expected:

```text
ImportError: cannot import name 'process_pivot_job_batch'
```

- [ ] **Step 3: Extract lower-level helper**

In `src/easm/pivot/worker.py`, add:

```python
async def _process_pivot_jobs(
    *,
    pool: Any,
    store: Store,
    config: Any | None,
    shared_http: httpx.AsyncClient,
    limiters: Any,
    resolver: PivotResolver,
    limit: int,
) -> int:
    jobs = await store.dequeue_pivot_jobs_batch(limit=limit)
    if not jobs:
        return 0

    for job in jobs:
        await _process_one_pivot_job(
            pool=pool,
            store=store,
            config=config,
            shared_http=shared_http,
            limiters=limiters,
            resolver=resolver,
            job=job,
        )

    first = jobs[0]
    await _run_correlation(store, first["org_id"], first["target_id"])
    return len(jobs)
```

Then extract the existing per-job body into:

```python
async def _process_one_pivot_job(
    *,
    pool: Any,
    store: Store,
    config: Any | None,
    shared_http: httpx.AsyncClient,
    limiters: Any,
    resolver: PivotResolver,
    job: dict[str, Any],
) -> None:
    ...
```

Move the existing `for job in jobs:` body into this function without changing behavior yet.

- [ ] **Step 4: Add public one-batch helper**

Add:

```python
async def process_pivot_job_batch(
    pool: Any,
    config: Any | None = None,
    *,
    limit: int = 20,
) -> int:
    store = Store(pool)
    runtime = get_runtime()
    shared_http = runtime.make_http_client()
    limiters = get_default_limiters()
    resolver = PivotResolver(pool)
    try:
        return await _process_pivot_jobs(
            pool=pool,
            store=store,
            config=config,
            shared_http=shared_http,
            limiters=limiters,
            resolver=resolver,
            limit=limit,
        )
    finally:
        await shared_http.aclose()
```

- [ ] **Step 5: Update infinite worker loop**

Inside `pivot_worker_pool.worker_loop()`, replace direct dequeue/per-job processing with:

```python
processed = await _process_pivot_jobs(
    pool=pool,
    store=store,
    config=config,
    shared_http=shared_http,
    limiters=limiters,
    resolver=resolver,
    limit=20,
)
if not processed:
    await asyncio.sleep(batch_interval_ms / 1000)
```

- [ ] **Step 6: Verify focused test passes**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_pivot_worker_integration.py"
```

Expected:

```text
1 passed
```

---

## Task 2: Define Pivot Worker Failure Semantics

**Files:**
- Create: `tests/test_pivot_worker_lifecycle.py`
- Modify: `src/easm/pivot/worker.py`

- [ ] **Step 1: Write missing-handler test**

In `tests/test_pivot_worker_lifecycle.py`:

```python
from __future__ import annotations

import pytest

from easm.pivot.worker import process_pivot_job_batch
from easm.store import Store


@pytest.mark.asyncio
@pytest.mark.db
async def test_pivot_batch_marks_unknown_handler_failed(db_pool) -> None:
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        "default", "target-1", "hostname", "app.example.invalid", {"source": "test"}
    )
    await store.enqueue_pivot_job(
        org_id="default",
        target_id="target-1",
        entity_type="hostname",
        entity_value="app.example.invalid",
        entity_id=entity_id,
        pivot_type="missing_handler",
        depth=1,
    )

    processed = await process_pivot_job_batch(db_pool, None, limit=20)

    assert processed == 1
    row = await db_pool.fetchrow("SELECT status, error_message FROM pivot_queue")
    assert row["status"] == "failed"
    assert "no handler" in row["error_message"]
```

- [ ] **Step 2: Write materialization-failure test**

Add:

```python
@pytest.mark.asyncio
@pytest.mark.db
async def test_pivot_batch_marks_schema_materialization_error_failed(
    db_pool, monkeypatch
) -> None:
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        "default", "target-1", "hostname", "app.example.invalid", {"source": "test"}
    )
    await store.enqueue_pivot_job(
        org_id="default",
        target_id="target-1",
        entity_type="hostname",
        entity_value="app.example.invalid",
        entity_id=entity_id,
        pivot_type="dns_resolve",
        depth=1,
    )

    async def fake_run_pivot_handler(*args, **kwargs):
        return [{"hostname": "app.example.invalid", "ip": "198.51.100.10"}]

    async def broken_upsert_entity(*args, **kwargs):
        raise RuntimeError("entity upsert boom")

    monkeypatch.setattr(
        "easm.pivot.worker.get_runtime",
        lambda: type(
            "RuntimeStub",
            (),
            {
                "make_http_client": lambda self: _NoopAsyncClient(),
                "run_pivot_handler": fake_run_pivot_handler,
            },
        )(),
    )
    monkeypatch.setattr(Store, "upsert_entity", broken_upsert_entity)

    processed = await process_pivot_job_batch(db_pool, None, limit=20)

    assert processed == 1
    row = await db_pool.fetchrow("SELECT status, error_message FROM pivot_queue")
    assert row["status"] == "failed"
    assert "pivot materialization failed" in row["error_message"]
```

Include helper:

```python
class _NoopAsyncClient:
    async def aclose(self) -> None:
        return None
```

- [ ] **Step 3: Verify materialization test fails under current behavior**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_pivot_worker_lifecycle.py"
```

Expected current failure:

```text
assert 'completed' == 'failed'
```

- [ ] **Step 4: Implement fail-on-materialization-errors**

In `src/easm/pivot/worker.py`, replace:

```python
await store.mark_pivot_completed(job["id"])
```

With:

```python
if errors:
    await store.mark_pivot_failed(
        job["id"],
        f"pivot materialization failed: {errors} error(s)",
    )
else:
    await store.mark_pivot_completed(job["id"])
```

When finishing a created pivot run, set:

```python
run_status = "failed" if errors else "completed"
run_error = f"pivot materialization failed: {errors} error(s)" if errors else None
```

Then pass `run_status` and `error_message=run_error` into `mark_run_finished()`.

- [ ] **Step 5: Verify lifecycle tests pass**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_pivot_worker_lifecycle.py"
```

Expected:

```text
2 passed
```

---

## Task 3: Make Single Pivot Dequeue Atomic

**Files:**
- Modify: `src/easm/store.py`
- Modify: `tests/test_pivot/test_store.py`

- [ ] **Step 1: Write returned-status regression test**

Add to `tests/test_pivot/test_store.py`:

```python
@pytest.mark.asyncio
@pytest.mark.db
async def test_dequeue_pivot_job_returns_running_status(db_pool):
    store = Store(db_pool)
    entity_id = uuid.uuid4()
    job_id = await store.enqueue_pivot_job(
        "default",
        "target-1",
        "hostname",
        "app.example.invalid",
        entity_id,
        "dns_resolve",
        1,
    )

    job = await store.dequeue_pivot_job()

    assert job is not None
    assert job["id"] == job_id
    assert job["status"] == "running"
```

- [ ] **Step 2: Verify test fails with stale status**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_pivot/test_store.py::test_dequeue_pivot_job_returns_running_status"
```

Expected:

```text
assert 'pending' == 'running'
```

- [ ] **Step 3: Replace implementation with atomic update**

In `src/easm/store.py`, replace `dequeue_pivot_job()` with:

```python
async def dequeue_pivot_job(self) -> dict[str, Any] | None:
    row = await self.pool.fetchrow(
        """
        WITH picked AS (
            SELECT id
            FROM pivot_queue
            WHERE status = 'pending'
            ORDER BY enqueued_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        UPDATE pivot_queue pq
        SET status = 'running',
            started_at = NOW()
        FROM picked
        WHERE pq.id = picked.id
        RETURNING pq.*
        """
    )
    return dict(row) if row else None
```

- [ ] **Step 4: Verify store pivot tests**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_pivot/test_store.py tests/test_store.py::test_dequeue_pivot_jobs_batch_returns_multiple tests/test_store.py::test_dequeue_pivot_jobs_batch_empty"
```

Expected:

```text
passed
```

---

## Task 4: Collapse Duplicate Output Schemas

**Files:**
- Modify: `src/easm/runners/schemas.py`
- Create: `tests/test_schema_contracts.py`

- [ ] **Step 1: Write duplicate guard test**

Create `tests/test_schema_contracts.py`:

```python
from __future__ import annotations

from pathlib import Path


SCHEMAS_PATH = Path(__file__).parents[1] / "src" / "easm" / "runners" / "schemas.py"


def test_output_schemas_assigned_once() -> None:
    source = SCHEMAS_PATH.read_text(encoding="utf-8")
    assert source.count("OUTPUT_SCHEMAS") == 1


def test_schema_functions_are_not_redefined() -> None:
    source = SCHEMAS_PATH.read_text(encoding="utf-8")
    for name in [
        "dns",
        "reverse_dns",
        "domain_extract",
        "geoip",
        "tls_cert",
        "dns_mail_records",
        "shodan",
        "abuseipdb",
        "greynoise",
        "urlscan",
        "censys",
        "passive_dns",
        "cloud_bucket",
        "searchengine",
        "subdomain_takeover",
        "_noop",
    ]:
        assert source.count(f"def {name}(") == 1
```

- [ ] **Step 2: Verify test fails**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schema_contracts.py"
```

Expected:

```text
FAILED tests/test_schema_contracts.py::test_output_schemas_assigned_once
```

- [ ] **Step 3: Remove duplicate lower block**

In `src/easm/runners/schemas.py`, remove the second block beginning at:

```python
# --- pivot/enrichment schemas (used by pivot worker, not runners) ---
```

through the second `OUTPUT_SCHEMAS = { ... }`.

Keep the first, typed `OUTPUT_SCHEMAS: dict[str, OutputSchemaFn] = { ... }`.

- [ ] **Step 4: Verify schema guard passes**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schema_contracts.py tests/test_schemas.py"
```

Expected:

```text
passed
```

---

## Task 5: Add Runner And Pivot Source Schema Contracts

**Files:**
- Create or modify: `tests/test_schema_contracts.py`
- Create: `tests/test_runners/test_registry_contracts.py`
- Modify: `src/easm/runners/schemas.py`
- Modify: `src/easm/runners/__init__.py`
- Modify: `AGENTS.md`

- [ ] **Step 1: Add configured runner registry test**

Create `tests/test_runners/test_registry_contracts.py`:

```python
from __future__ import annotations

from easm.config import VALID_RUNNER_NAMES
from easm.runners import get_all_runners
from easm.runners.schemas import OUTPUT_SCHEMAS


RAW_ONLY_RUNNERS = {
    "paste_monitor",
    "gist_monitor",
    "stackoverflow_monitor",
    "discord_monitor",
    "github_scan",
    "breach_monitor",
}


def test_all_configured_runner_names_are_registered() -> None:
    registered = set(get_all_runners())
    assert set(VALID_RUNNER_NAMES) <= registered


def test_registered_runner_sources_have_schema_or_raw_only_reason() -> None:
    missing = [
        name
        for name in get_all_runners()
        if name not in OUTPUT_SCHEMAS and name not in RAW_ONLY_RUNNERS
    ]
    assert missing == []
```

- [ ] **Step 2: Add pivot source schema contract**

Append to `tests/test_schema_contracts.py`:

```python
from easm.pivot.handlers import PIVOT_SOURCE_NAMES
from easm.runners.schemas import OUTPUT_SCHEMAS


RAW_ONLY_PIVOT_SOURCES = {
    "reverse_whois",
}


def test_pivot_sources_have_output_schemas_or_raw_only_reason() -> None:
    missing = sorted(
        source
        for source in set(PIVOT_SOURCE_NAMES.values())
        if source not in OUTPUT_SCHEMAS and source not in RAW_ONLY_PIVOT_SOURCES
    )
    assert missing == []
```

- [ ] **Step 3: Verify contract fails on current missing schemas**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schema_contracts.py tests/test_runners/test_registry_contracts.py"
```

Expected initial failure includes:

```text
['cpe_vuln_enrich', 'domain_rdap', 'rdap']
```

- [ ] **Step 4: Add minimal RDAP schemas**

In `src/easm/runners/schemas.py`, add:

```python
def rdap(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    value = raw.get("ip", "").strip() or raw.get("domain", "").strip()
    rdap_data = raw.get("rdap", raw)
    if not value or not rdap_data:
        return [], []
    entity_type = "ip" if raw.get("ip") else "domain"
    return [
        EntityCandidate(
            entity_type,
            normalize_entity_value(entity_type, value),
            {"source": "rdap", "rdap": rdap_data},
        )
    ], []


def domain_rdap(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    rdap_data = raw.get("rdap", raw)
    if not domain or not rdap_data:
        return [], []
    return [
        EntityCandidate(
            "domain",
            normalize_entity_value("domain", domain),
            {"source": "domain_rdap", "rdap": rdap_data},
        )
    ], []
```

Add to `OUTPUT_SCHEMAS`:

```python
"rdap": rdap,
"domain_rdap": domain_rdap,
```

- [ ] **Step 5: Decide `cpe_vuln_enrich` contract**

Preferred minimal schema:

```python
def cpe_vuln_enrich(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    cpe = raw.get("cpe", "").strip()
    vulnerabilities = raw.get("vulnerabilities", [])
    if not hostname or not cpe:
        return [], []
    return [
        EntityCandidate(
            "hostname",
            normalize_entity_value("hostname", hostname),
            {
                "source": "cpe_vuln_enrich",
                "cpe": cpe,
                "vulnerabilities": vulnerabilities,
            },
        )
    ], []
```

Add:

```python
"cpe_vuln_enrich": cpe_vuln_enrich,
```

If the actual handler returns a different shape, update this schema to match the handler rather than forcing the handler into this example.

- [ ] **Step 6: Attach schemas to legacy runner definitions where expected**

In `src/easm/runners/__init__.py`, when creating `RunnerDef` for legacy classes, set:

```python
output_schema=OUTPUT_SCHEMAS.get(name),
```

Import `OUTPUT_SCHEMAS` at the top:

```python
from easm.runners.schemas import OUTPUT_SCHEMAS
```

This is metadata only unless legacy adapters later use schema ingestion.

- [ ] **Step 7: Document raw-only sources**

In `AGENTS.md`, add:

```markdown
Raw-only sources currently allowed by schema contracts:
- `paste_monitor`, `gist_monitor`, `stackoverflow_monitor`, `discord_monitor`, `github_scan`, `breach_monitor`: monitor findings are stored as raw events today.
- `reverse_whois`: raw enrichment retained until ownership/entity modeling is defined.
```

- [ ] **Step 8: Verify contracts pass**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schema_contracts.py tests/test_runners/test_registry_contracts.py"
```

Expected:

```text
passed
```

---

## Final Verification

- [ ] **Step 1: Run focused Phase 3/4 tests**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_pivot_worker_integration.py tests/test_pivot_worker_lifecycle.py tests/test_pivot/test_store.py tests/test_schema_contracts.py tests/test_runners/test_registry_contracts.py"
```

Expected:

```text
passed
```

- [ ] **Step 2: Run canonical backend gate**

Run:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

Expected:

```text
all tests passed, no skipped/xfail/xpass tests
```

- [ ] **Step 3: Clean Docker resources**

Run:

```powershell
docker compose -f docker-compose.test.yml down
```

Expected:

```text
Network open-easm_easm_test  Removed
```

---

## Subagent Ownership Map

Use disjoint workers:

1. **Worker A: Pivot Batch Helper**
   - Owns `src/easm/pivot/worker.py`
   - Owns `tests/test_simulation_pivot_worker_integration.py`

2. **Worker B: Pivot Failure Semantics**
   - Owns `tests/test_pivot_worker_lifecycle.py`
   - May edit `src/easm/pivot/worker.py` after Worker A lands

3. **Worker C: Store Atomic Dequeue**
   - Owns `src/easm/store.py`
   - Owns `tests/test_pivot/test_store.py`

4. **Worker D: Schema Dedup And Contracts**
   - Owns `src/easm/runners/schemas.py`
   - Owns `tests/test_schema_contracts.py`
   - Owns `tests/test_runners/test_registry_contracts.py`
   - Owns `src/easm/runners/__init__.py`
   - Owns `AGENTS.md`

Run Worker A before Worker B because both touch `src/easm/pivot/worker.py`.

---

## Self-Review

- No task requires real network or scanner execution.
- No task asks for commits.
- Every new dynamic behavior is tested through Docker/Postgres or fixture-backed simulation.
- The plan directly targets the original symptom: subdomain enum runs, pivot jobs exist, and then nothing visible happens.
- The plan makes schema absence explicit instead of letting raw-only sources quietly look successful.
