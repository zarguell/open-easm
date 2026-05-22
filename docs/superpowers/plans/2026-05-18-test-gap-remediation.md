# Test Gap Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` for parallel execution or `executing-plans` for inline execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the current green Docker pytest run into a trustworthy offline quality gate, then close the highest-risk simulation, runner/schema, and pivot lifecycle gaps found during the multi-agent review.

**Architecture:** The repo keeps its offline-first posture. The first phase makes the Docker test command unambiguous and fail-closed. The second phase adds black-box simulation coverage. Later phases harden schema contracts, runtime containment, pivot lifecycle semantics, and static quality gates.

**Tech Stack:** Python 3.14, pytest, pytest-asyncio, asyncpg, Alembic, FastAPI/HTTPX ASGITransport, Docker Compose, Ruff, mypy.

**Non-Negotiable Constraints:**
- Do not make git commits.
- Do not run active scans against public targets.
- Keep Docker test/runtime networks internal where possible.
- Prefer fixture-backed simulation over real network/subprocess behavior.
- Use `example.invalid`, `198.51.100.0/24`, `203.0.113.0/24`, or `192.0.2.0/24` test data.

---

## Current Baseline

The canonical backend test command currently passes:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

Expected current result:

```text
280 passed
```

Known blind spots:
- `ruff check src tests` currently fails with 244 findings.
- `mypy src/easm` currently fails with 212 errors.
- Docker pytest does not run lint, typecheck, coverage, warnings-as-errors, or UI build.
- `OUTPUT_SCHEMAS` is defined twice in `src/easm/runners/schemas.py`.
- Runtime network/subprocess policy is not a universal boundary for pivot handlers.
- No black-box test exercises app startup, API manual run, and pivot worker drain together.

---

## File Structure

**Create:**
- `scripts/test_backend.py` - single Docker-internal backend quality entrypoint.
- `tests/test_offline_harness_config.py` - validates real offline config and fixtures.
- `tests/test_runtime_http_policy.py` - tests simulation and blocked HTTP transports.
- `tests/test_simulation_api.py` - ASGI-level offline manual run tests.
- `tests/test_simulation_pivot_worker_integration.py` - DB-backed one-batch pivot worker test.
- `tests/test_runners/test_registry_contracts.py` - runner/schema registry contract tests.
- `tests/test_schema_contracts.py` - table-driven output schema contract tests.
- `tests/test_pivot_worker_lifecycle.py` - pivot worker lifecycle/error contract tests.

**Modify:**
- `pyproject.toml` - pytest strict config, markers, optional coverage dependency later.
- `docker-compose.test.yml` - run the backend quality entrypoint instead of an inline shell string.
- `Dockerfile.test` - copy new scripts and install any added dev dependencies.
- `tests/conftest.py` - fail on missing required DB dependency, schema-driven cleanup.
- `alembic/env.py` - safer test DSN precedence.
- `src/easm/runtime.py` - runtime helpers for policy-enforced DNS/socket/subprocess where needed.
- `src/easm/pivot/handlers.py` - route side-effectful pivots through runtime policy or classify them.
- `src/easm/pivot/worker.py` - expose a one-batch helper and define error semantics.
- `src/easm/store.py` - atomic single-job dequeue, idempotent pivot enqueue, concurrency-safe entity upsert.
- `src/easm/runners/schemas.py` - remove duplicate definitions and add missing schemas or explicit no-op list.
- `src/easm/runners/__init__.py` - attach output schemas for legacy runners where entity materialization is expected.
- `src/easm/api/routes/pivot_queue.py` - add policy validation and optionally summary endpoint.
- `src/easm/api/routes/entities.py` - implement or remove `new_since_run_id`.
- `AGENTS.md` and `README.md` - document canonical commands and intentional blind spots.

---

## Phase 1: Make The Test Harness Honest

### Task 1: Add A Single Backend Test Entrypoint

**Files:**
- Create: `scripts/test_backend.py`
- Modify: `docker-compose.test.yml`
- Modify: `Dockerfile.test`
- Test: Docker compose full backend suite

- [ ] **Step 1: Create `scripts/test_backend.py`**

```python
from __future__ import annotations

import os
import subprocess
import sys


def run(cmd: list[str]) -> None:
    print(f"+ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True)


def require_matching_test_dsn() -> None:
    test_dsn = os.environ.get("EASM_TEST_DATABASE_DSN")
    app_dsn = os.environ.get("EASM_DATABASE_DSN")
    if not test_dsn:
        raise SystemExit("EASM_TEST_DATABASE_DSN is required for Docker tests")
    if app_dsn and app_dsn != test_dsn:
        raise SystemExit(
            "EASM_DATABASE_DSN and EASM_TEST_DATABASE_DSN differ; refusing to "
            "migrate one database and test another"
        )


def main() -> None:
    require_matching_test_dsn()
    run(["alembic", "upgrade", "head"])
    run(["python", "-m", "pytest", "-ra", "-q"])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
```

- [ ] **Step 2: Update `docker-compose.test.yml`**

Replace:

```yaml
command: >
  sh -c "alembic upgrade head && python -m pytest -q"
```

With:

```yaml
command: ["python", "scripts/test_backend.py"]
```

- [ ] **Step 3: Update `Dockerfile.test`**

Add after copying tests:

```dockerfile
COPY scripts/ scripts/
```

- [ ] **Step 4: Verify Docker test still passes**

Run:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

Expected:

```text
280 passed
```

- [ ] **Step 5: Clean up containers**

Run:

```powershell
docker compose -f docker-compose.test.yml down
```

Expected:

```text
Network open-easm_easm_test  Removed
```

### Task 2: Fail Closed On Accidental Skips And Unknown Markers

**Files:**
- Modify: `pyproject.toml`
- Modify: `tests/conftest.py`
- Test: Docker compose full backend suite

- [ ] **Step 1: Add strict pytest config**

In `[tool.pytest.ini_options]`, change to:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "-ra --strict-config --strict-markers"
markers = [
    "unit: pure unit tests with no database or external process dependency",
    "db: tests that require the Postgres test database",
    "simulation: tests that exercise fixture-backed simulation mode",
    "network_mocked: tests that exercise network code through mocked clients/transports",
    "integration: multi-component tests that still avoid public target traffic",
]
```

- [ ] **Step 2: Stop skipping DB tests when `asyncpg` is missing**

In `tests/conftest.py`, replace the optional `asyncpg` import block:

```python
try:
    import asyncpg
except ModuleNotFoundError:
    asyncpg = None
```

With:

```python
import asyncpg
```

Then remove this branch from `db_pool`:

```python
if asyncpg is None:
    pytest.skip("asyncpg is not installed; skipping database-backed test")
```

- [ ] **Step 3: Verify no skips or unknown marker failures**

Run:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

Expected:

```text
280 passed
```

The summary must not include skipped or xfailed tests.

### Task 3: Make Database Cleanup Schema-Driven

**Files:**
- Modify: `tests/conftest.py`
- Test: `tests/test_store.py`, `tests/test_store_integration.py`, full Docker suite

- [ ] **Step 1: Replace fixed table truncation**

Add helper in `tests/conftest.py`:

```python
async def _truncate_app_tables(conn) -> None:
    rows = await conn.fetch(
        """
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename <> 'alembic_version'
        ORDER BY tablename
        """
    )
    tables = [f'"{row["tablename"]}"' for row in rows]
    if tables:
        await conn.execute(f"TRUNCATE TABLE {', '.join(tables)} CASCADE")
```

Then change `db_pool` cleanup to:

```python
async with pool.acquire() as conn:
    await _truncate_app_tables(conn)
```

- [ ] **Step 2: Verify DB-backed tests**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test python scripts/test_backend.py
```

Expected:

```text
280 passed
```

---

## Phase 2: Black-Box Safe Simulation Coverage

### Task 4: Validate Real Offline Config And Fixtures

**Files:**
- Create: `tests/test_offline_harness_config.py`
- Test: focused test and full Docker suite

- [ ] **Step 1: Add offline config test**

```python
from __future__ import annotations

from pathlib import Path

from easm.config import load_config


def test_offline_config_is_safe_and_fixture_backed() -> None:
    config = load_config("config.offline.yaml")

    assert config.runtime.mode == "simulate"
    assert config.runtime.allow_external_network is False
    assert config.runtime.allow_subprocess is False
    assert config.runtime.allow_active_scanning is False
    assert config.runtime.refresh_kev_on_startup is False

    target = next(t for t in config.targets if t.id == "offline-local")
    assert target.match_rules.domains == ["example.invalid"]
    assert target.runners["subfinder"].enabled is True
    assert target.runners["crtsh"].enabled is True

    fixtures = Path(config.runtime.fixtures_path)
    assert (fixtures / "runners" / "subfinder.jsonl").is_file()
    assert (fixtures / "http" / "crtsh.json").is_file()
    assert (fixtures / "pivots" / "dns_resolve.json").is_file()
```

- [ ] **Step 2: Run focused test**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_offline_harness_config.py"
```

Expected:

```text
1 passed
```

### Task 5: Test Runtime HTTP Policy

**Files:**
- Create: `tests/test_runtime_http_policy.py`
- Test: focused test and full Docker suite

- [ ] **Step 1: Add policy tests**

```python
from __future__ import annotations

import pytest

from easm.config import RuntimeConfig
from easm.runtime import Runtime


@pytest.mark.asyncio
async def test_simulation_http_client_returns_fixture() -> None:
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path="fixtures/simulation",
            allow_external_network=False,
        )
    )

    async with runtime.make_http_client() as client:
        response = await client.get("https://crt.sh/?q=%.example.invalid&output=json")

    assert response.status_code == 200
    assert response.json()


@pytest.mark.asyncio
async def test_simulation_http_client_fails_closed_on_missing_fixture() -> None:
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path="fixtures/simulation",
            allow_external_network=False,
        )
    )

    async with runtime.make_http_client() as client:
        response = await client.get("https://missing.example.invalid/data.json")

    assert response.status_code == 599
    assert response.json()["error"] == "simulation fixture missing"


@pytest.mark.asyncio
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
```

- [ ] **Step 2: Run focused test**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_runtime_http_policy.py"
```

Expected:

```text
3 passed
```

### Task 6: Add API-Level Offline Manual Run Tests

**Files:**
- Create: `tests/test_simulation_api.py`
- Modify only if needed: `src/easm/api/routes/runs.py`
- Test: focused API simulation test and full Docker suite

- [ ] **Step 1: Add ASGI test for manual subfinder run**

```python
from __future__ import annotations

from httpx import ASGITransport, AsyncClient
import pytest

from easm.api import deps
from easm.api.app import create_app
from easm.config import load_config
from easm.runtime import configure_runtime
from easm.scheduler import Scheduler
from easm.store import Store


@pytest.mark.asyncio
async def test_offline_manual_subfinder_run_creates_hostname_entity(db_pool) -> None:
    config = load_config("config.offline.yaml")
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

    rows = await db_pool.fetch(
        """
        SELECT entity_type, entity_value, attributes
        FROM entities
        WHERE target_id = 'offline-local'
        ORDER BY entity_type, entity_value
        """
    )
    assert ("hostname", "app.example.invalid") in [
        (row["entity_type"], row["entity_value"]) for row in rows
    ]
```

- [ ] **Step 2: Verify pivot enqueue assertion**

Extend the same test with:

```python
    queued = await db_pool.fetchval(
        """
        SELECT COUNT(*)
        FROM pivot_queue
        WHERE target_id = 'offline-local'
          AND pivot_type = 'dns_resolve'
          AND entity_value = 'app.example.invalid'
        """
    )
    assert queued == 1
```

- [ ] **Step 3: Run focused test**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_api.py"
```

Expected:

```text
1 passed
```

---

## Phase 3: Pivot Worker Lifecycle And Store Correctness

### Task 7: Expose A One-Batch Pivot Worker Helper

**Files:**
- Modify: `src/easm/pivot/worker.py`
- Create: `tests/test_simulation_pivot_worker_integration.py`
- Test: focused pivot integration test and full Docker suite

- [ ] **Step 1: Extract one-batch helper**

In `src/easm/pivot/worker.py`, extract the body that processes `jobs = await store.dequeue_pivot_jobs_batch(limit=20)` into:

```python
async def process_pivot_job_batch(
    pool,
    config: Any | None,
    *,
    limit: int = 20,
) -> int:
    """Process one available batch of pivot jobs and return number of jobs seen."""
    store = Store(pool)
    runtime = get_runtime()
    shared_http = runtime.make_http_client()
    try:
        return await _process_pivot_job_batch_with_client(
            pool,
            store,
            config,
            shared_http,
            limit=limit,
        )
    finally:
        await shared_http.aclose()
```

Then make `pivot_worker_pool()` call the lower-level helper from its loop.

- [ ] **Step 2: Add DB-backed simulation pivot worker test**

```python
from __future__ import annotations

import pytest

from easm.config import load_config
from easm.runtime import configure_runtime
from easm.store import Store
from easm.pivot.worker import process_pivot_job_batch


@pytest.mark.asyncio
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
        entity_id=entity_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        pivot_type="dns_resolve",
        depth=1,
    )

    processed = await process_pivot_job_batch(db_pool, config, limit=20)

    assert processed == 1
    status = await db_pool.fetchval("SELECT status FROM pivot_queue")
    assert status == "completed"
    ip_count = await db_pool.fetchval(
        "SELECT COUNT(*) FROM entities WHERE entity_type = 'ip' AND entity_value = '198.51.100.10'"
    )
    assert ip_count == 1
```

- [ ] **Step 3: Run focused test**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_pivot_worker_integration.py"
```

Expected:

```text
1 passed
```

### Task 8: Define Pivot Failure Semantics

**Files:**
- Create: `tests/test_pivot_worker_lifecycle.py`
- Modify: `src/easm/pivot/worker.py`
- Test: lifecycle tests and full Docker suite

- [ ] **Step 1: Add tests for missing handler and handler exception**

Add tests that enqueue a job with an unknown `pivot_type`, call `process_pivot_job_batch()`, and assert:

```python
assert status == "failed"
assert "no handler" in error_message
```

Add a monkeypatched handler that raises `ValueError("boom")`, then assert:

```python
assert status == "failed"
assert error_message == "see logs"
```

- [ ] **Step 2: Add test for schema/upsert error behavior**

Choose explicit semantics:

```text
If the handler succeeds but schema/entity/relationship materialization fails,
the pivot job must be marked failed because raw-only success caused silent
"it ran but nothing happened" behavior.
```

Add a test that monkeypatches `Store.upsert_entity` to raise and assert:

```python
assert status == "failed"
assert "entity upsert" in error_message
```

- [ ] **Step 3: Implement minimal worker behavior**

In `src/easm/pivot/worker.py`, after schema processing, replace unconditional completion:

```python
await store.mark_pivot_completed(job["id"])
```

With:

```python
if errors:
    await store.mark_pivot_failed(job["id"], f"pivot materialization failed: {errors} error(s)")
else:
    await store.mark_pivot_completed(job["id"])
```

When an entity upsert fails, include `"entity upsert"` in the accumulated error context.

- [ ] **Step 4: Verify focused lifecycle tests**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_pivot_worker_lifecycle.py"
```

Expected:

```text
3 passed
```

### Task 9: Harden Store Atomicity And Idempotency

**Files:**
- Modify: `src/easm/store.py`
- Add tests to: `tests/test_pivot/test_store.py`
- Add tests to: `tests/test_store_integration.py`

- [ ] **Step 1: Replace single-job dequeue with atomic update**

Change `dequeue_pivot_job()` to use the same atomic pattern as batch dequeue:

```sql
WITH next_job AS (
    SELECT id
    FROM pivot_queue
    WHERE status = 'pending'
    ORDER BY enqueued_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE pivot_queue
SET status = 'running',
    started_at = NOW()
WHERE id IN (SELECT id FROM next_job)
RETURNING *
```

- [ ] **Step 2: Add returned-status test**

In `tests/test_pivot/test_store.py`, assert:

```python
job = await store.dequeue_pivot_job()
assert job["status"] == "running"
```

- [ ] **Step 3: Add duplicate pending pivot guard**

Add a partial unique index migration if duplicate pending/running jobs should be disallowed:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_pivot_job
ON pivot_queue (org_id, target_id, entity_id, pivot_type, depth)
WHERE status IN ('pending', 'running');
```

Then update enqueue to use `ON CONFLICT DO NOTHING` with that index.

- [ ] **Step 4: Make `upsert_entity` concurrency-safe**

Replace select-then-insert with `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING id`.

Acceptance criteria:

```python
entity_id_a, is_new_a = await store.upsert_entity(...)
entity_id_b, is_new_b = await store.upsert_entity(...)
assert entity_id_a == entity_id_b
assert sorted([is_new_a, is_new_b]) == [False, True]
```

---

## Phase 4: Runner And Schema Contracts

### Task 10: Collapse Duplicate Output Schema Definitions

**Files:**
- Modify: `src/easm/runners/schemas.py`
- Create: `tests/test_schema_contracts.py`
- Test: schema contracts and full Docker suite

- [ ] **Step 1: Remove duplicate lower half**

Keep one definition of each schema function and one `OUTPUT_SCHEMAS` dict. Remove the duplicate block starting at the second `# --- pivot/enrichment schemas` section.

- [ ] **Step 2: Add no duplicate definition test**

```python
from __future__ import annotations

import inspect

import easm.runners.schemas as schemas


def test_output_schemas_defined_once_at_module_level() -> None:
    source = inspect.getsource(schemas)
    assert source.count("OUTPUT_SCHEMAS") == 1
```

- [ ] **Step 3: Run schema tests**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schemas.py tests/test_schema_contracts.py"
```

Expected:

```text
passed
```

### Task 11: Add Registry And Pivot Source Schema Contracts

**Files:**
- Create: `tests/test_runners/test_registry_contracts.py`
- Modify: `src/easm/runners/schemas.py`
- Modify as needed: `src/easm/pivot/handlers.py`

- [ ] **Step 1: Add runner registry contract test**

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


def test_registered_sources_have_schema_or_raw_only_reason() -> None:
    for name in get_all_runners():
        assert name in OUTPUT_SCHEMAS or name in RAW_ONLY_RUNNERS
```

- [ ] **Step 2: Add pivot source contract test**

```python
from __future__ import annotations

from easm.pivot.handlers import PIVOT_SOURCE_NAMES
from easm.runners.schemas import OUTPUT_SCHEMAS


RAW_ONLY_PIVOT_SOURCES = {"reverse_whois"}


def test_pivot_sources_have_output_schemas_or_raw_only_reason() -> None:
    missing = []
    for source in PIVOT_SOURCE_NAMES.values():
        if source not in OUTPUT_SCHEMAS and source not in RAW_ONLY_PIVOT_SOURCES:
            missing.append(source)

    assert missing == []
```

- [ ] **Step 3: Add missing schemas or explicit raw-only reasons**

Preferred schemas:
- `rdap` -> update `domain` or `ip` entity with RDAP attributes.
- `domain_rdap` -> update `domain` entity with RDAP attributes.
- `cpe_vuln_enrich` -> update hostname/software entity with vulnerability attributes, or create `finding`-style entity if the existing model supports it.

If a source is intentionally raw-only, add it to `RAW_ONLY_PIVOT_SOURCES` and document the reason in `AGENTS.md`.

### Task 12: Add Realistic Runner Fixtures

**Files:**
- Add: `fixtures/simulation/runners/asnmap.jsonl`
- Add: `fixtures/simulation/runners/dnstwist.jsonl`
- Add: `fixtures/simulation/runners/nuclei.jsonl`
- Add: `fixtures/simulation/runners/wappalyzer.jsonl`
- Add or adjust: `fixtures/simulation/http/commoncrawl.json`
- Modify: `src/easm/runtime.py`
- Add tests to: `tests/test_simulation_api.py`

- [ ] **Step 1: Add fixture content**

`fixtures/simulation/runners/asnmap.jsonl`:

```jsonl
{"asn":64500,"as_number":"64500","as_name":"EXAMPLE-NET","as_country":"ZZ","as_range":[{"ipv4":"198.51.100.0/24"}]}
```

`fixtures/simulation/runners/dnstwist.jsonl`:

```jsonl
{"domain":"examp1e.invalid","fuzzer":"homoglyph","registered":false,"dns":{}}
```

`fixtures/simulation/runners/nuclei.jsonl`:

```jsonl
{"template-id":"exposure-test","info":{"name":"Test Exposure","severity":"high","description":"Fixture exposure"},"matched-at":"https://app.example.invalid","curl-command":"curl https://app.example.invalid"}
```

`fixtures/simulation/runners/wappalyzer.jsonl`:

```jsonl
[{"name":"nginx","version":"1.24.0","categories":[{"name":"Web servers"}]}]
```

- [ ] **Step 2: Fix Common Crawl fixture routing**

In `Runtime._http_fixture_for()`, special-case Common Crawl:

```python
if host == "index.commoncrawl.org":
    name = "commoncrawl"
```

- [ ] **Step 3: Add simulation API tests for each fixture-backed runner**

For each runner, call:

```python
response = await client.post(f"/runs/offline-local/{runner_name}")
assert response.status_code == 200
```

Then assert at least one raw event exists:

```python
count = await db_pool.fetchval(
    "SELECT COUNT(*) FROM raw_events WHERE target_id = 'offline-local' AND source = $1",
    runner_name,
)
assert count >= 1
```

---

## Phase 5: Runtime Policy Enforcement

### Task 13: Classify Pivot Handler Capabilities

**Files:**
- Modify: `src/easm/pivot/handlers.py`
- Modify: `src/easm/api/routes/pivot_queue.py`
- Create: `tests/test_runtime_policy_pivots.py`

- [ ] **Step 1: Add pivot capability metadata**

In `src/easm/pivot/handlers.py`:

```python
PIVOT_REQUIRES_NETWORK = {
    "dns_resolve",
    "reverse_dns",
    "tls_cert_grab",
    "crtsh_search",
    "passive_dns",
    "rdap_lookup",
    "reverse_whois",
    "domain_rdap",
    "shodan_enrich",
    "abuseipdb_enrich",
    "greynoise_enrich",
    "urlscan_enrich",
    "censys_enrich",
    "ip_to_asn",
}

PIVOT_REQUIRES_SUBPROCESS = {
    "subdomain_enum",
}
```

- [ ] **Step 2: Reject unsafe manual pivot triggers**

In `src/easm/api/routes/pivot_queue.py`, before enqueuing:

```python
runtime = get_runtime()
if req.pivot_type in PIVOT_REQUIRES_NETWORK and not runtime.config.allow_external_network:
    raise HTTPException(
        status_code=403,
        detail="pivot requires external network but runtime policy disables it",
    )
if req.pivot_type in PIVOT_REQUIRES_SUBPROCESS and not runtime.config.allow_subprocess:
    raise HTTPException(
        status_code=403,
        detail="pivot requires subprocess execution but runtime policy disables it",
    )
```

- [ ] **Step 3: Add API tests**

Assert restricted runtime rejects manual `dns_resolve` in live/no-network mode and permits it in simulation mode where fixtures are used.

### Task 14: Route Side-Effectful Handler Paths Through Runtime

**Files:**
- Modify: `src/easm/runtime.py`
- Modify: `src/easm/pivot/handlers.py`
- Test: `tests/test_runtime_policy_pivots.py`

- [ ] **Step 1: Add runtime helpers**

Add helper methods to `Runtime`:

```python
def require_external_network(self, operation: str) -> None:
    if self.is_simulation:
        return
    if not self.config.allow_external_network:
        raise RuntimeError(f"{operation} blocked by runtime policy")


def require_subprocess(self, operation: str) -> None:
    if self.is_simulation:
        return
    if not self.config.allow_subprocess:
        raise RuntimeError(f"{operation} blocked by runtime policy")
```

- [ ] **Step 2: Apply guards in handlers**

Before direct DNS/socket operations:

```python
get_runtime().require_external_network("dns_resolve")
```

Before direct subprocess operations:

```python
get_runtime().require_subprocess("subdomain_enum")
```

- [ ] **Step 3: Verify restricted live mode fails closed**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_runtime_policy_pivots.py"
```

Expected:

```text
passed
```

---

## Phase 6: API Contract Drift

### Task 15: Implement Or Remove `new_since_run_id`

**Files:**
- Modify: `src/easm/api/routes/entities.py`
- Add tests to: `tests/test_api_entities.py`

- [ ] **Step 1: Add failing test**

Create two runs and two entities with different `discovery_run_id` values. Query:

```text
GET /entities?new_since_run_id=<old_run_id>
```

Expected: only entities from newer runs are returned.

- [ ] **Step 2: Implement query filter**

Add SQL condition:

```sql
AND e.discovery_run_id IS NOT NULL
AND e.first_seen_at > (
    SELECT COALESCE(finished_at, started_at, created_at)
    FROM runs
    WHERE id = $N
)
```

If `new_since_run_id` does not exist, return `400` with `invalid_run_id`.

### Task 16: Add Pivot Queue Summary Or Fix Docs/UI Contract

**Files:**
- Option A modify: `src/easm/api/routes/pivot_queue.py`
- Option A modify: `ui/src/api/pivot-queue.ts`
- Option B modify: `docs/superpowers/*`, `README.md`, `AGENTS.md`

- [ ] **Step 1: Choose contract**

Preferred: implement backend summary endpoint:

```text
GET /api/pivot-queue/summary
```

Response:

```json
{
  "pending": 0,
  "running": 0,
  "completed": 0,
  "failed": 0,
  "top_failures": []
}
```

- [ ] **Step 2: Add tests**

Add API test that inserts pivot jobs in multiple statuses and asserts summary counts.

---

## Phase 7: Static Gates After Structural Cleanup

### Task 17: Add Ruff Gate After Formatting Cleanup

**Files:**
- Modify many existing Python files
- Modify: `scripts/test_backend.py`
- Test: Docker backend suite

- [ ] **Step 1: Run safe auto-fixes**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test ruff check src tests --fix
```

Expected: import sorting and safe unused import cleanup.

- [ ] **Step 2: Manually fix remaining high-signal lint issues**

Prioritize:
- `F` errors.
- duplicate definitions.
- ambiguous variables.
- obvious bugbear warnings not caused by FastAPI idioms.

- [ ] **Step 3: Add Ruff to backend entrypoint**

In `scripts/test_backend.py`, before pytest:

```python
run(["ruff", "check", "src", "tests"])
```

- [ ] **Step 4: Verify full suite**

Run canonical Docker command. Expected:

```text
ruff passes
280+ pytest tests pass
```

### Task 18: Stage Mypy Instead Of Big-Bang Strictness

**Files:**
- Modify: `pyproject.toml`
- Modify: `scripts/test_backend.py`
- Modify typed modules incrementally

- [ ] **Step 1: Add a targeted mypy gate**

Start with modules that should already be close:

```python
run([
    "mypy",
    "src/easm/config.py",
    "src/easm/runtime.py",
    "src/easm/entity_store.py",
    "src/easm/cpe_mapper.py",
])
```

- [ ] **Step 2: Fix typed module errors**

Use precise annotations like:

```python
dict[str, Any]
list[dict[str, Any]]
```

Do not silence errors with broad `ignore_errors = true`.

- [ ] **Step 3: Expand mypy module list**

Add modules in this order:
1. `src/easm/store.py`
2. `src/easm/runners/engine.py`
3. `src/easm/runners/schemas.py`
4. `src/easm/pivot/resolver.py`
5. `src/easm/pivot/worker.py`
6. `src/easm/api/routes`

### Task 19: Add Coverage After Black-Box Tests Exist

**Files:**
- Modify: `pyproject.toml`
- Modify: `scripts/test_backend.py`

- [ ] **Step 1: Add dependency**

In `[project.optional-dependencies].dev`, add:

```toml
"pytest-cov>=6.0.0",
```

- [ ] **Step 2: Add coverage config**

```toml
[tool.coverage.run]
source = ["src/easm"]
branch = true

[tool.coverage.report]
show_missing = true
skip_covered = true
fail_under = 65
```

- [ ] **Step 3: Change pytest command**

In `scripts/test_backend.py`:

```python
run(["python", "-m", "pytest", "-ra", "-q", "--cov=easm", "--cov-report=term-missing"])
```

Expected initial threshold: `65`. Raise only after meaningful integration coverage is added.

---

## Phase 8: Documentation Alignment

### Task 20: Document The Real Architecture

**Files:**
- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `docs/offline-harness.md`
- Modify: `docs/superpowers/specs/2026-05-16-open-easm-v1-design.md`

- [ ] **Step 1: Document direct schema ingestion**

Add:

```markdown
Current ingestion architecture is direct: runners and pivot workers write raw events,
then materialize entities through `src/easm/runners/schemas.py`. The older parser/backfill
design in planning docs is historical unless explicitly reintroduced.
```

- [ ] **Step 2: Document canonical commands**

Add:

```markdown
Canonical backend verification:
`docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test`
```

Add warning:

```markdown
Do not run `docker compose run --rm test python -m pytest` directly unless Alembic
has already run in that same test database.
```

- [ ] **Step 3: Document intentional raw-only sources**

List each raw-only runner/pivot source and why it is raw-only.

---

## Recommended Execution Order

1. Task 1
2. Task 2
3. Task 3
4. Task 4
5. Task 5
6. Task 6
7. Task 7
8. Task 10
9. Task 11
10. Task 13
11. Task 8
12. Task 9
13. Task 12
14. Task 15
15. Task 16
16. Task 20
17. Task 17
18. Task 18
19. Task 19

This order gets trustworthy signal early, then fixes the “runs but nothing happens” pivot concern, then makes static gates enforceable without burying the important behavioral work under style noise.

---

## Verification Matrix

| Gate | Command | Expected |
| --- | --- | --- |
| Backend Docker suite | `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test` | Pass, no skips |
| Focused simulation API | `docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_api.py"` | Pass |
| Pivot worker integration | `docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_pivot_worker_integration.py"` | Pass |
| Schema contracts | `docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schema_contracts.py tests/test_runners/test_registry_contracts.py"` | Pass |
| Runtime policy | `docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_runtime_http_policy.py tests/test_runtime_policy_pivots.py"` | Pass |
| Ruff gate | `docker compose -f docker-compose.test.yml run --rm test ruff check src tests` | Pass after Task 17 |
| Mypy staged gate | `docker compose -f docker-compose.test.yml run --rm test mypy <staged module list>` | Pass after Task 18 |

---

## Open Decisions

1. **Pivot materialization failures:** This plan chooses fail-closed for schema/entity/relationship errors. If raw-only partial success is preferred, the worker must persist warnings visibly and tests must assert that behavior.
2. **Raw-only sources:** Monitor and enrichment sources need explicit owner decisions: materialize entities now or document raw-only behavior.
3. **Parser/backfill architecture:** Current code does not implement the old parser/backfill design. Either update docs to current direct-ingestion architecture or create a separate migration plan to reintroduce parser/backfill.
4. **UI gate:** Backend reliability comes first. Add UI build/typecheck after backend quality gates are stable.

---

## Self-Review

- No task requires public target scanning.
- No task asks workers to commit.
- Every task includes exact files and commands.
- The plan starts with harness honesty before deeper behavioral fixes.
- Static gates are delayed until duplicate schemas and high-risk behavior are fixed, preventing style debt from hiding correctness work.
