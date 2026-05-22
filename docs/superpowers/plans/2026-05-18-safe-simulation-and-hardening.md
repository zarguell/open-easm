# Safe Simulation And Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a safe, fixture-backed simulation mode for Open EASM, use it to reproduce full discovery-to-pivot cascades without external network or active scanning, then harden the code paths that currently make pivots appear to do nothing.

**Architecture:** Add a central runtime boundary that can run in `live` or `simulate` mode. In simulate mode, subprocess, HTTP, DNS/socket-like pivots, startup refreshes, and active scanner paths fail closed or return fixtures, while the real ingestion, entity, pivot queue, worker, API, and UI logic still runs. Then fix the bugs exposed by the simulation and add diagnostics so future failures are visible.

**Tech Stack:** Python 3.14, FastAPI, asyncpg/Postgres 18, APScheduler, Alembic, pytest/pytest-asyncio, Docker Compose, React/Vite.

**User Constraints:** Do not make git commits. Do not run active scans. Do not send traffic to real targets. Prefer isolated Docker networks and fixture-backed simulation. Agents may edit files, but they must not commit.

---

## File Structure

Core runtime and configuration:
- Modify `src/easm/config.py`: add `RuntimeConfig` and optional top-level `runtime`.
- Create `src/easm/runtime.py`: central live/simulate runtime helpers for subprocess, HTTP client construction, fixture loading, and pivot handler execution.
- Modify `src/easm/main.py`: honor runtime mode for startup side effects.
- Modify `src/easm/scheduler.py`: use runtime-created HTTP clients.
- Modify `src/easm/api/routes/runs.py`: use runtime-created HTTP clients for manual runner triggers.
- Modify `src/easm/api/routes/health.py`: expose simulation state and avoid binary version subprocesses in simulation.

Runner and pivot correctness:
- Modify `src/easm/runners/engine.py`: pass pool/session provenance into ingestion; use runtime subprocess seam.
- Modify `src/easm/runners/base.py`: use runtime subprocess seam for legacy runners.
- Modify `src/easm/runners/__init__.py`: ensure legacy runner output can be ingested consistently or explicitly marked raw-only.
- Modify `src/easm/runners/schemas.py`: fix subfinder/subdomain typing and add missing schema coverage for pivot sources where needed.
- Modify `src/easm/pivot/resolver.py`: fix cooldown/coverage returns and skipped-job insert.
- Modify `src/easm/pivot/worker.py`: use simulation pivot handler seam, atomic dequeue, correct run lifecycle, structured failure semantics, and provenance.
- Modify `src/easm/store.py`: add atomic pivot dequeue and helper queries for diagnostics.

Simulation harness:
- Modify `config.offline.yaml`: convert from inert-only config to safe simulation config with reserved targets.
- Modify `docker-compose.offline.yml`: include fixtures and simulation env.
- Modify `docs/offline-harness.md`: document safe simulation runbook.
- Create `fixtures/simulation/runners/*.jsonl`: deterministic runner outputs.
- Create `fixtures/simulation/http/*.json`: deterministic HTTP responses.
- Create `fixtures/simulation/pivots/*.json`: deterministic pivot results.

API/UI diagnostics:
- Modify `src/easm/api/routes/pivot_queue.py`: validation, summary endpoint, better retry behavior.
- Modify `src/easm/api/schemas.py`: typed pivot queue summary/schema objects if needed.
- Modify `ui/src/api/pivot-queue.ts`: add summary type/client.
- Modify `ui/src/components/targets/PivotQueueTable.tsx`: display error, skip reason, run id, session id, auto-refresh.

Tests:
- Create `tests/unit/` or `tests/no_db/` as a dependency-light suite.
- Modify `tests/conftest.py`: stop forcing DB cleanup onto non-DB unit tests.
- Create `tests/test_simulation_runtime.py`.
- Create `tests/test_simulation_runner_flow.py`.
- Create `tests/test_simulation_pivot_worker.py`.
- Create or extend `tests/test_pivot_resolver.py`.
- Create or extend `tests/test_pivot_worker.py`.
- Create or extend `tests/test_api.py`, `tests/test_api_graph.py`, and pivot API tests.

---

## Task 0: Preserve Current Work And Baseline The Failure

**Files:**
- Inspect: `src/easm/runners/engine.py`
- Inspect: `tests/test_runners/test_engine.py`
- Inspect: `config.offline.yaml`
- Inspect: `docker-compose.offline.yml`
- Inspect: `docs/offline-harness.md`

- [ ] **Step 1: Record current working tree**

Run:

```bash
git status --short
git diff --stat
```

Expected: working tree may include the earlier pivot enqueue patch plus offline harness files. Do not revert these unless explicitly instructed by the user.

- [ ] **Step 2: Capture the known pivot-stop hypothesis**

Write a short note in the task log:

```text
Known suspected blockers:
1. Standard runner ingestion previously did not pass a DB pool into pivot enqueue.
2. Subfinder/subdomain results are typed as domain while downstream pivots are usually hostname-based.
3. Legacy runners can insert raw_events without entity ingestion or pivot enqueue.
4. Pivot worker can mark jobs completed while parse/upsert/recursive enqueue silently fail.
```

- [ ] **Step 3: Verify syntax only**

Run:

```bash
python -m compileall -q src tests
```

Expected: command exits 0. If this fails, fix syntax before continuing.

---

## Task 1: Add Runtime Configuration

**Files:**
- Modify: `src/easm/config.py`
- Test: `tests/test_config.py` or `tests/no_db/test_runtime_config.py`
- Modify: `config.offline.yaml`

- [ ] **Step 1: Write failing config tests**

Add tests covering defaults and simulation config:

```python
def test_runtime_config_defaults_to_live(tmp_path):
    path = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": False,
            "match_rules": {},
            "runners": {},
        }],
    })
    config = load_config(path)
    assert config.runtime.mode == "live"
    assert config.runtime.allow_external_network is True
    assert config.runtime.allow_subprocess is True
    assert config.runtime.allow_active_scanning is False
    assert config.runtime.refresh_kev_on_startup is True


def test_runtime_config_parses_simulation_mode(tmp_path):
    path = make_yaml(tmp_path, {
        "runtime": {
            "mode": "simulate",
            "fixtures_path": "fixtures/simulation",
            "allow_external_network": False,
            "allow_subprocess": False,
            "allow_active_scanning": False,
            "refresh_kev_on_startup": False,
        },
        "targets": [{
            "id": "offline",
            "name": "Offline",
            "type": "organization",
            "enabled": True,
            "match_rules": {"domains": ["example.invalid"]},
            "runners": {},
        }],
    })
    config = load_config(path)
    assert config.runtime.mode == "simulate"
    assert str(config.runtime.fixtures_path).endswith("fixtures/simulation")
    assert config.runtime.allow_external_network is False
    assert config.runtime.refresh_kev_on_startup is False
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_config.py::test_runtime_config_defaults_to_live tests/test_config.py::test_runtime_config_parses_simulation_mode -q
```

Expected: FAIL because `Config.runtime` does not exist.

- [ ] **Step 3: Implement `RuntimeConfig`**

In `src/easm/config.py`, add:

```python
class RuntimeConfig(BaseModel):
    mode: Literal["live", "simulate"] = "live"
    fixtures_path: str = "fixtures/simulation"
    allow_external_network: bool = True
    allow_subprocess: bool = True
    allow_active_scanning: bool = False
    refresh_kev_on_startup: bool = True
```

Then add to `Config`:

```python
runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
```

- [ ] **Step 4: Update offline config**

Add this block to `config.offline.yaml`:

```yaml
runtime:
  mode: simulate
  fixtures_path: fixtures/simulation
  allow_external_network: false
  allow_subprocess: false
  allow_active_scanning: false
  refresh_kev_on_startup: false
```

- [ ] **Step 5: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_config.py -q
python -m compileall -q src tests
```

Expected: runtime config tests pass if dependencies are installed. If local async plugin/deps are missing, record the blocker and keep compileall green.

---

## Task 2: Create Fixture-Backed Runtime Module

**Files:**
- Create: `src/easm/runtime.py`
- Create: `tests/test_simulation_runtime.py`
- Create: `fixtures/simulation/runners/subfinder.jsonl`
- Create: `fixtures/simulation/http/crtsh.json`
- Create: `fixtures/simulation/pivots/dns_resolve.json`

- [ ] **Step 1: Create fixture files**

Create `fixtures/simulation/runners/subfinder.jsonl`:

```jsonl
{"host":"app.example.invalid","source":"simulation"}
{"host":"api.example.invalid","source":"simulation"}
```

Create `fixtures/simulation/http/crtsh.json`:

```json
[
  {
    "name_value": "app.example.invalid\napi.example.invalid",
    "issuer_name_id": "simulation-ca",
    "not_before": "2026-01-01",
    "not_after": "2027-01-01",
    "serial_number": "sim-001",
    "fingerprint": "SIMULATEDFINGERPRINT001"
  }
]
```

Create `fixtures/simulation/pivots/dns_resolve.json`:

```json
[
  {"match": {"entity_value": "app.example.invalid"}, "results": [{"hostname": "app.example.invalid", "ip": "198.51.100.10", "record_type": "A"}]},
  {"match": {"entity_value": "api.example.invalid"}, "results": [{"hostname": "api.example.invalid", "ip": "198.51.100.11", "record_type": "A"}]}
]
```

- [ ] **Step 2: Write failing runtime tests**

Create `tests/test_simulation_runtime.py`:

```python
import pytest

from easm.config import RuntimeConfig
from easm.runtime import Runtime


@pytest.mark.asyncio
async def test_simulated_subprocess_returns_fixture(tmp_path):
    fixture_dir = tmp_path / "fixtures" / "runners"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "subfinder.jsonl").write_text('{"host":"app.example.invalid"}\n')

    runtime = Runtime(RuntimeConfig(mode="simulate", fixtures_path=str(tmp_path / "fixtures"), allow_subprocess=False))

    ok, stdout, stderr = await runtime.exec_subprocess(["subfinder", "-d", "example.invalid"])

    assert ok is True
    assert '{"host":"app.example.invalid"}' in stdout
    assert stderr == ""


@pytest.mark.asyncio
async def test_simulated_subprocess_fails_closed_when_fixture_missing(tmp_path):
    runtime = Runtime(RuntimeConfig(mode="simulate", fixtures_path=str(tmp_path), allow_subprocess=False))

    ok, stdout, stderr = await runtime.exec_subprocess(["subfinder", "-d", "example.invalid"])

    assert ok is False
    assert stdout == ""
    assert "simulation fixture missing" in stderr
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_runtime.py -q
```

Expected: FAIL because `easm.runtime` does not exist.

- [ ] **Step 4: Implement `src/easm/runtime.py`**

Create:

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from easm.config import RuntimeConfig


class Runtime:
    def __init__(self, config: RuntimeConfig | None = None):
        self.config = config or RuntimeConfig()

    @property
    def is_simulation(self) -> bool:
        return self.config.mode == "simulate"

    @property
    def fixtures_path(self) -> Path:
        return Path(self.config.fixtures_path)

    async def exec_subprocess(self, cmd: list[str], timeout: int = 300, logger_fn=None) -> tuple[bool, str, str]:
        if not self.is_simulation:
            return False, "", "runtime live subprocess delegation not implemented here"
        binary = Path(cmd[0]).name
        fixture = self.fixtures_path / "runners" / f"{binary}.jsonl"
        if not fixture.exists():
            return False, "", f"simulation fixture missing: {fixture}"
        text = fixture.read_text()
        if logger_fn:
            for line in text.splitlines():
                logger_fn(f"[simulation stdout] {line}")
        return True, text, ""

    def load_pivot_results(self, pivot_type: str, entity_value: str) -> list[dict[str, Any]]:
        fixture = self.fixtures_path / "pivots" / f"{pivot_type}.json"
        if not fixture.exists():
            raise FileNotFoundError(f"simulation fixture missing: {fixture}")
        rows = json.loads(fixture.read_text())
        for row in rows:
            match = row.get("match", {})
            if match.get("entity_value") == entity_value:
                return list(row.get("results", []))
        return []

    def make_http_client(self) -> httpx.AsyncClient:
        if not self.is_simulation:
            return httpx.AsyncClient(timeout=30.0)

        def handler(request: httpx.Request) -> httpx.Response:
            stem = request.url.host.split(".")[0] if request.url.host else "response"
            fixture = self.fixtures_path / "http" / f"{stem}.json"
            if fixture.exists():
                return httpx.Response(200, text=fixture.read_text())
            return httpx.Response(599, json={"error": "simulation fixture missing", "url": str(request.url)})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=30.0)
```

- [ ] **Step 5: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_runtime.py -q
python -m compileall -q src tests
```

Expected: tests pass where dependencies are present.

---

## Task 3: Wire Runtime Into Runner Execution

**Files:**
- Modify: `src/easm/runners/engine.py`
- Modify: `src/easm/runners/base.py`
- Modify: `src/easm/scheduler.py`
- Modify: `src/easm/api/routes/runs.py`
- Test: `tests/test_runners/test_engine.py`
- Test: `tests/test_simulation_runner_flow.py`

- [ ] **Step 1: Write failing subprocess simulation test**

Add to `tests/test_simulation_runner_flow.py`:

```python
import uuid
from unittest.mock import AsyncMock

import pytest

from easm.config import RuntimeConfig, TargetConfig
from easm.runtime import Runtime
from easm.runners.engine import standard_subprocess_run
from easm.runners.schemas import subfinder


@pytest.mark.asyncio
async def test_simulated_subfinder_ingests_entities_and_calls_pivot_enqueue(tmp_path, monkeypatch):
    runners_dir = tmp_path / "runners"
    runners_dir.mkdir()
    (runners_dir / "subfinder.jsonl").write_text('{"host":"app.example.invalid"}\n')

    runtime = Runtime(RuntimeConfig(mode="simulate", fixtures_path=str(tmp_path), allow_subprocess=False))
    monkeypatch.setattr("easm.runners.engine.get_runtime", lambda: runtime)

    target = TargetConfig(
        id="sim",
        name="Simulation",
        type="organization",
        match_rules={"domains": ["example.invalid"]},
        runners={},
        pivot={"enabled": True, "max_depth": 2, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )
    store = AsyncMock()
    store.pool = AsyncMock()
    store.insert_raw_event.return_value = uuid.uuid4()
    store.upsert_entity.return_value = (uuid.uuid4(), True)

    inserted, deduped, errors = await standard_subprocess_run(
        target,
        store,
        "manual",
        uuid.uuid4(),
        lambda _: None,
        None,
        source_name="subfinder",
        binary="subfinder",
        args_template=["-d", "[item]", "-json"],
        iterate_over=lambda t: t.match_rules.domains,
        output_schema=subfinder,
    )

    assert (inserted, deduped, errors) == (1, 0, 0)
    store.upsert_entity.assert_awaited()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_runner_flow.py -q
```

Expected: FAIL until runtime accessor and runner wiring exist.

- [ ] **Step 3: Add global runtime accessor**

In `src/easm/runtime.py`, add:

```python
_runtime: Runtime = Runtime()


def configure_runtime(config: RuntimeConfig) -> None:
    global _runtime
    _runtime = Runtime(config)


def get_runtime() -> Runtime:
    return _runtime
```

- [ ] **Step 4: Wire standard runner subprocess**

In `src/easm/runners/engine.py`, change `exec_subprocess` so simulation is checked before `asyncio.create_subprocess_exec`:

```python
from easm.runtime import get_runtime

runtime = get_runtime()
if runtime.is_simulation:
    return await runtime.exec_subprocess(cmd, timeout=timeout, logger_fn=logger_fn)
```

- [ ] **Step 5: Wire legacy runner subprocess**

In `src/easm/runners/base.py`, update `_exec_subprocess` with the same simulation branch:

```python
from easm.runtime import get_runtime

runtime = get_runtime()
if runtime.is_simulation:
    return await runtime.exec_subprocess(cmd, timeout=timeout, logger_fn=None)
```

- [ ] **Step 6: Wire HTTP clients**

In `src/easm/scheduler.py` and `src/easm/api/routes/runs.py`, replace:

```python
http_client = httpx.AsyncClient(timeout=30.0)
```

with:

```python
from easm.runtime import get_runtime

http_client = get_runtime().make_http_client()
```

- [ ] **Step 7: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_runtime.py tests/test_simulation_runner_flow.py -q
python -m compileall -q src tests
```

Expected: simulation runner test passes where dependencies are present.

---

## Task 4: Fix Subfinder/Subdomain Entity Typing

**Files:**
- Modify: `src/easm/runners/schemas.py`
- Test: `tests/test_schemas.py`
- Test: `tests/test_simulation_runner_flow.py`

- [ ] **Step 1: Write failing schema test**

Add:

```python
def test_subfinder_outputs_hostname_for_subdomain():
    from easm.runners.schemas import subfinder

    entities, relationships = subfinder({"host": "app.example.invalid"})

    assert len(entities) == 1
    assert entities[0].entity_type == "hostname"
    assert entities[0].value == "app.example.invalid"
    assert entities[0].attributes["source"] == "subfinder"
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_schemas.py::test_subfinder_outputs_hostname_for_subdomain -q
```

Expected: FAIL because `subfinder` currently returns a `domain`.

- [ ] **Step 3: Change schema**

In `src/easm/runners/schemas.py`, change the `subfinder` entity candidate from `domain` to `hostname`:

```python
return [EntityCandidate(
    "hostname",
    normalize_entity_value("hostname", host),
    {"source": "subfinder"},
)], []
```

- [ ] **Step 4: Add domain relationship if useful**

If the code already has a domain extraction schema pattern, add relationship output:

```python
registered = tldextract.extract(host).registered_domain
relationships = []
if registered and registered != host:
    relationships.append(RelationshipCandidate(
        "domain",
        registered,
        "hostname",
        host,
        "has_hostname",
        "subfinder",
    ))
return [hostname_entity], relationships
```

Only add this if required by graph behavior; otherwise keep the change minimal.

- [ ] **Step 5: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_schemas.py tests/test_simulation_runner_flow.py -q
python -m compileall -q src tests
```

Expected: subfinder now creates hostname entities, enabling hostname pivots.

---

## Task 5: Fix Pivot Resolver Logic

**Files:**
- Modify: `src/easm/pivot/resolver.py`
- Test: `tests/test_pivot_resolver.py`
- Test: `tests/test_pivot/test_resolver.py`

- [ ] **Step 1: Write failing cooldown test**

Add:

```python
@pytest.mark.asyncio
async def test_check_cooldown_returns_recent_row():
    pool = AsyncMock()
    pool.fetchval.return_value = 1
    resolver = PivotResolver(pool)

    result = await resolver._check_cooldown("default", "hostname", "app.example.invalid", "dns_resolve", 24)

    assert result == 1
```

- [ ] **Step 2: Write failing skipped insert test**

Add:

```python
@pytest.mark.asyncio
async def test_insert_skipped_includes_required_entity_id():
    pool = AsyncMock()
    resolver = PivotResolver(pool)

    await resolver._insert_skipped(
        "default",
        "sim",
        "domain",
        "app.example.invalid",
        uuid.uuid4(),
        "crtsh_search",
        "covered_by_apex:example.invalid",
    )

    sql = pool.execute.await_args.args[0]
    assert "entity_id" in sql
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_pivot_resolver.py -q
```

Expected: FAIL because helper methods do not return rows and skipped insert lacks `entity_id`.

- [ ] **Step 4: Implement resolver fixes**

Return rows:

```python
return row
```

Update `_insert_skipped` signature:

```python
async def _insert_skipped(self, org_id, target_id, entity_type, entity_value, entity_id, pivot_type, reason):
```

Update SQL:

```python
INSERT INTO pivot_queue (org_id, target_id, entity_type, entity_value, entity_id, pivot_type, status, skip_reason)
VALUES ($1, $2, $3, $4, $5, $6, 'skipped_covered', $7)
```

Update call site to pass `entity_id`.

- [ ] **Step 5: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_pivot_resolver.py tests/test_pivot/test_resolver.py -q
python -m compileall -q src tests
```

Expected: resolver tests pass where dependencies are installed.

---

## Task 6: Make Pivot Worker Simulation-Safe And Diagnosable

**Files:**
- Modify: `src/easm/pivot/worker.py`
- Modify: `src/easm/runtime.py`
- Test: `tests/test_simulation_pivot_worker.py`
- Test: `tests/test_pivot_worker.py`

- [ ] **Step 1: Write failing worker simulation test**

Create `tests/test_simulation_pivot_worker.py`:

```python
import uuid
from unittest.mock import AsyncMock

import pytest

from easm.config import RuntimeConfig
from easm.runtime import Runtime


@pytest.mark.asyncio
async def test_runtime_returns_simulated_pivot_results(tmp_path):
    pivots = tmp_path / "pivots"
    pivots.mkdir()
    (pivots / "dns_resolve.json").write_text(
        '[{"match":{"entity_value":"app.example.invalid"},"results":[{"hostname":"app.example.invalid","ip":"198.51.100.10","record_type":"A"}]}]'
    )
    runtime = Runtime(RuntimeConfig(mode="simulate", fixtures_path=str(tmp_path)))

    results = runtime.load_pivot_results("dns_resolve", "app.example.invalid")

    assert results == [{"hostname": "app.example.invalid", "ip": "198.51.100.10", "record_type": "A"}]
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_pivot_worker.py -q
```

Expected: FAIL until runtime fixture support exists.

- [ ] **Step 3: Add runtime pivot execution helper**

In `src/easm/runtime.py`, add:

```python
async def run_pivot_handler(self, pivot_type: str, job: dict, live_handler, pool, **kwargs):
    if self.is_simulation:
        return self.load_pivot_results(pivot_type, job["entity_value"])
    return await live_handler(job, pool, **kwargs)
```

- [ ] **Step 4: Wire worker to runtime**

In `src/easm/pivot/worker.py`, replace:

```python
results = await handler_fn(job, pool, **kwargs)
```

with:

```python
from easm.runtime import get_runtime

results = await get_runtime().run_pivot_handler(
    job["pivot_type"],
    job,
    handler_fn,
    pool,
    **kwargs,
)
```

- [ ] **Step 5: Improve worker failure state**

Move `mark_pivot_completed` until after raw event insert, schema parsing, entity upsert, relationships, and recursive enqueue have all finished. On schema/upsert/enqueue exceptions, call `mark_pivot_failed(job["id"], "...specific message...")` instead of only debug logging.

Use messages like:

```text
output schema failed: <source_name>
entity upsert failed: <entity_type>/<entity_value>
recursive pivot enqueue failed: <entity_type>/<entity_value>
```

- [ ] **Step 6: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_pivot_worker.py tests/test_pivot_worker.py -q
python -m compileall -q src tests
```

Expected: simulation pivot helper works and worker no longer hides downstream failures.

---

## Task 7: Fix Provenance And Run Counters

**Files:**
- Modify: `src/easm/runners/engine.py`
- Modify: `src/easm/pivot/worker.py`
- Modify: `src/easm/store.py`
- Test: `tests/test_simulation_runner_flow.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write failing provenance test**

Add a unit-level test around `_ingest_entities` using mocked store:

```python
@pytest.mark.asyncio
async def test_ingest_entities_passes_discovery_provenance():
    store = AsyncMock()
    store.pool = AsyncMock()
    entity_id = uuid.uuid4()
    run_id = uuid.uuid4()
    session_id = uuid.uuid4()
    store.upsert_entity.return_value = (entity_id, True)

    await _ingest_entities(
        store,
        lambda raw: ([EntityCandidate("hostname", "app.example.invalid", {})], []),
        {"host": "app.example.invalid"},
        run_id,
        "default",
        "sim",
        target=_target_with_pivots(),
        pool=store.pool,
        raw_event_id=uuid.uuid4(),
        discovery_session_id=session_id,
    )

    kwargs = store.upsert_entity.await_args.kwargs
    assert kwargs["discovery_session_id"] == session_id
    assert kwargs["discovery_run_id"] == run_id
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_runner_flow.py::test_ingest_entities_passes_discovery_provenance -q
```

Expected: FAIL until `_ingest_entities` accepts/passes provenance.

- [ ] **Step 3: Add provenance args to `_ingest_entities`**

Add parameters:

```python
discovery_session_id: uuid.UUID | None = None
```

Pass into `store.upsert_entity`:

```python
discovery_session_id=discovery_session_id,
discovery_run_id=run_id,
```

When enqueueing pivots, pass the same `discovery_session_id`, not `run_id`.

- [ ] **Step 4: Fetch session id in `execute_runner`**

Before runner execution:

```python
run_data = await store.get_run(run_id)
discovery_session_id = uuid.UUID(run_data["discovery_session_id"]) if run_data and run_data.get("discovery_session_id") else run_id
```

Thread it through standard runner calls where needed.

- [ ] **Step 5: Set pivot entity provenance**

In `pivot_worker_pool`, when upserting entities from pivot results:

```python
discovery_session_id=job.get("discovery_session_id"),
discovery_pivot_id=job["id"],
discovery_run_id=run_id,
```

- [ ] **Step 6: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_simulation_runner_flow.py tests/test_store.py -q
python -m compileall -q src tests
```

Expected: provenance is consistent and counters can work.

---

## Task 8: Make Pivot Dequeue Atomic

**Files:**
- Modify: `src/easm/store.py`
- Test: `tests/test_pivot/test_store.py`

- [ ] **Step 1: Write failing atomic dequeue test**

Add a test that calls `dequeue_pivot_jobs_batch(limit=2)` and asserts a single SQL statement uses `UPDATE ... FROM ... RETURNING` or that an explicit transaction is used.

Mock-level version:

```python
@pytest.mark.asyncio
async def test_dequeue_pivot_jobs_batch_uses_atomic_update():
    pool = AsyncMock()
    pool.fetch.return_value = []
    store = Store(pool)

    await store.dequeue_pivot_jobs_batch(limit=2)

    sql = pool.fetch.await_args.args[0]
    assert "UPDATE pivot_queue" in sql
    assert "RETURNING" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_pivot/test_store.py::test_dequeue_pivot_jobs_batch_uses_atomic_update -q
```

Expected: FAIL because current implementation selects then updates in separate calls.

- [ ] **Step 3: Implement atomic dequeue**

Replace batch dequeue with:

```sql
WITH picked AS (
    SELECT id
    FROM pivot_queue
    WHERE status = 'pending'
    ORDER BY enqueued_at
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE pivot_queue pq
SET status = 'running', started_at = NOW()
FROM picked
WHERE pq.id = picked.id
RETURNING pq.*
```

Return `dict(row)` for each returned row.

- [ ] **Step 4: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_pivot/test_store.py -q
python -m compileall -q src tests
```

Expected: atomic dequeue test passes where dependencies are available.

---

## Task 9: Add Schema Coverage Tests And Missing Schemas

**Files:**
- Modify: `src/easm/runners/schemas.py`
- Modify: `src/easm/pivot/handlers.py`
- Test: `tests/test_schemas.py`
- Test: `tests/test_pivot_worker.py`

- [ ] **Step 1: Write failing schema coverage test**

Add:

```python
def test_all_non_raw_pivot_sources_have_output_schemas():
    from easm.pivot.handlers import PIVOT_SOURCE_NAMES
    from easm.runners.schemas import OUTPUT_SCHEMAS

    raw_only = {
        "cpe_vuln_enrich",
    }
    missing = sorted(
        source
        for pivot_type, source in PIVOT_SOURCE_NAMES.items()
        if source and source not in OUTPUT_SCHEMAS and source not in raw_only
    )

    assert missing == []
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_schemas.py::test_all_non_raw_pivot_sources_have_output_schemas -q
```

Expected: FAIL for sources such as `rdap` and `domain_rdap`.

- [ ] **Step 3: Add minimal output schemas**

Add functions for `rdap`, `domain_rdap`, and other missing non-raw sources. Minimal schema:

```python
def domain_rdap(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain") or raw.get("ldhName") or raw.get("name")
    if not domain:
        return [], []
    return [EntityCandidate("domain", normalize_entity_value("domain", domain), {"source": "domain_rdap", **raw})], []
```

Register:

```python
OUTPUT_SCHEMAS["domain_rdap"] = domain_rdap
OUTPUT_SCHEMAS["rdap"] = rdap
```

- [ ] **Step 4: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_schemas.py tests/test_pivot_worker.py -q
python -m compileall -q src tests
```

Expected: missing schemas are either implemented or explicitly marked raw-only.

---

## Task 10: Add Pivot Diagnostics API

**Files:**
- Modify: `src/easm/store.py`
- Modify: `src/easm/api/routes/pivot_queue.py`
- Modify: `src/easm/api/schemas.py`
- Test: `tests/test_api.py` or `tests/test_api_pivot_queue.py`

- [ ] **Step 1: Write failing summary endpoint test**

Add:

```python
@pytest.mark.asyncio
async def test_pivot_queue_summary_endpoint(test_config, db_pool, scheduler):
    from httpx import ASGITransport, AsyncClient
    from easm.api import deps
    from easm.api.app import create_app
    from easm.store import Store

    deps.set_config(test_config)
    deps.set_store(Store(db_pool))
    deps.set_scheduler(scheduler)

    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test") as client:
        response = await client.get("/api/pivot-queue/summary")

    assert response.status_code == 200
    body = response.json()
    assert "counts_by_status" in body
    assert "oldest_pending_at" in body
    assert "failed_recent" in body
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m pytest tests/test_api_pivot_queue.py::test_pivot_queue_summary_endpoint -q
```

Expected: FAIL because endpoint does not exist.

- [ ] **Step 3: Add store helper**

In `Store`, add:

```python
async def get_pivot_queue_summary(self) -> dict[str, Any]:
    counts = await self.pool.fetch("SELECT status, COUNT(*) AS count FROM pivot_queue GROUP BY status")
    oldest_pending = await self.pool.fetchval("SELECT MIN(enqueued_at) FROM pivot_queue WHERE status = 'pending'")
    oldest_running = await self.pool.fetchval("SELECT MIN(started_at) FROM pivot_queue WHERE status = 'running'")
    failed_recent = await self.pool.fetch(
        "SELECT pivot_type, error_message, COUNT(*) AS count FROM pivot_queue WHERE status = 'failed' GROUP BY pivot_type, error_message ORDER BY count DESC LIMIT 10"
    )
    return {
        "counts_by_status": {r["status"]: r["count"] for r in counts},
        "oldest_pending_at": oldest_pending.isoformat() if oldest_pending else None,
        "oldest_running_at": oldest_running.isoformat() if oldest_running else None,
        "failed_recent": [dict(r) for r in failed_recent],
    }
```

- [ ] **Step 4: Add endpoint**

In `pivot_queue.py`:

```python
@router.get("/summary")
async def pivot_queue_summary():
    store = get_store()
    return await store.get_pivot_queue_summary()
```

- [ ] **Step 5: Harden validation**

For retry:

```python
try:
    uid = uuid.UUID(job_id)
except ValueError:
    raise HTTPException(status_code=400, detail={"error": "invalid_id", "detail": "Invalid pivot job ID format"}) from None
```

For trigger, reject unknown pivot types:

```python
from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY
if req.pivot_type not in PIVOT_HANDLER_REGISTRY:
    raise HTTPException(status_code=400, detail={"error": "unknown_pivot_type", "detail": req.pivot_type})
```

- [ ] **Step 6: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest tests/test_api_pivot_queue.py -q
python -m compileall -q src tests
```

Expected: endpoint and validation tests pass where DB test environment exists.

---

## Task 11: Improve Pivot UI Diagnostics

**Files:**
- Modify: `ui/src/api/pivot-queue.ts`
- Modify: `ui/src/components/targets/PivotQueueTable.tsx`
- Modify: `ui/src/components/targets/TargetsView.tsx` if summary placement is needed.

- [ ] **Step 1: Add API client type**

In `ui/src/api/pivot-queue.ts`, add:

```ts
export interface PivotQueueSummary {
  counts_by_status: Record<string, number>;
  oldest_pending_at: string | null;
  oldest_running_at: string | null;
  failed_recent: Array<{
    pivot_type: string;
    error_message: string | null;
    count: number;
  }>;
}

export async function fetchPivotQueueSummary(): Promise<PivotQueueSummary> {
  return client.get("pivot-queue/summary").json<PivotQueueSummary>();
}
```

- [ ] **Step 2: Display hidden diagnostic fields**

In `PivotQueueTable.tsx`, add visible columns or expandable row content for:

```text
error_message
skip_reason
run_id
discovery_session_id
started_at
completed_at
```

Use compact text; keep the table scannable.

- [ ] **Step 3: Add auto-refresh**

Use the existing auto-refresh hook if available:

```ts
useAutoRefresh(refetch, 5000, true);
```

Only auto-refresh the pivot queue view, not the whole app.

- [ ] **Step 4: Run UI verification**

Run:

```bash
npm --prefix ui run build
```

Expected: build passes when UI dependencies are installed. If `tsc` is unavailable locally, record the dependency blocker.

---

## Task 12: Make Startup Safe In Simulation

**Files:**
- Modify: `src/easm/main.py`
- Modify: `src/easm/api/routes/health.py`
- Modify: `docker-compose.offline.yml`
- Modify: `docs/offline-harness.md`
- Test: `tests/test_config.py`
- Test: `tests/test_api.py`

- [ ] **Step 1: Configure runtime at startup**

In `main.py`, after loading config:

```python
from easm.runtime import configure_runtime, get_runtime

configure_runtime(config.runtime)
runtime = get_runtime()
```

- [ ] **Step 2: Skip startup network side effects**

Wrap KEV refresh:

```python
if config.runtime.refresh_kev_on_startup:
    from easm.vuln_cache import refresh_kev_cache
    try:
        kev_count = await refresh_kev_cache(pool)
        logger.info("initial kev cache populated", count=kev_count)
    except Exception:
        logger.exception("initial kev cache population failed (non-fatal)")
else:
    logger.info("skipping initial kev cache refresh", runtime_mode=config.runtime.mode)
```

Do not write PDCP provider config in simulation unless explicitly allowed.

- [ ] **Step 3: Health endpoint reports runtime**

In `/healthz`, include:

```python
"runtime": {
    "mode": get_runtime().config.mode,
    "allow_external_network": get_runtime().config.allow_external_network,
    "allow_subprocess": get_runtime().config.allow_subprocess,
}
```

In simulation mode, do not run binary `--version` subprocess checks; report:

```python
{"ok": True, "simulated": True, "path": None, "version": None}
```

- [ ] **Step 4: Update offline compose**

Add:

```yaml
    environment:
      EASM_DATABASE_DSN: postgresql://easm:easm@postgres:5432/easm
      EASM_CONFIG_PATH: /app/config.yaml
```

Mount fixtures:

```yaml
    volumes:
      - ./config.offline.yaml:/app/config.yaml:ro
      - ./fixtures/simulation:/app/fixtures/simulation:ro
```

- [ ] **Step 5: Run static verification**

Run:

```bash
docker compose -f docker-compose.offline.yml config
python -m compileall -q src tests
```

Expected: compose config and compileall pass. Do not run `up` until the user approves and required images are available.

---

## Task 13: Split Unit Tests From DB Integration Tests

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/unit/conftest.py` if helpful.
- Modify: `pyproject.toml`
- Test: non-DB tests under `tests/test_config.py`, `tests/test_schemas.py`, `tests/test_simulation_runtime.py`.

- [ ] **Step 1: Mark DB tests explicitly**

Add to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
markers = [
    "db: requires migrated PostgreSQL 18",
]
```

- [ ] **Step 2: Change DB fixtures to not autouse globally**

Replace:

```python
@pytest_asyncio.fixture(autouse=True)
async def clean_db(db_pool):
```

with:

```python
@pytest_asyncio.fixture
async def clean_db(db_pool):
```

Then add `clean_db` fixture usage only to DB tests that need it.

- [ ] **Step 3: Add dependency-light test command**

Document:

```bash
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_config.py tests/test_schemas.py tests/test_simulation_runtime.py -q
```

- [ ] **Step 4: Add DB test command**

Document:

```bash
PYTHONPATH=src python -m pytest -m db -q
```

Only run this when Postgres 18 is up and migrations have been applied.

- [ ] **Step 5: Run available verification**

Run:

```bash
python -m compileall -q src tests
```

Expected: compileall passes. If pytest-asyncio or asyncpg are missing, record as environment blockers.

---

## Task 14: Fix Config History And Reload Trust Issues

**Files:**
- Modify: `src/easm/api/routes/config.py`
- Test: `tests/test_api.py` or `tests/test_config.py`

- [ ] **Step 1: Write failing config history test**

Add an API test that saves a config snapshot then calls `/api/config/history` and expects 200.

Expected body:

```json
[
  {
    "id": "...",
    "target_count": 1,
    "created_at": "..."
  }
]
```

- [ ] **Step 2: Fix query**

Change:

```sql
SELECT id, snapshot->'targets' AS targets, created_at
FROM config_snapshots
```

to:

```sql
SELECT id, raw_config->'targets' AS targets, loaded_at
FROM config_snapshots
```

Map:

```python
created_at=r["loaded_at"].isoformat()
```

- [ ] **Step 3: Honor `EASM_CONFIG_PATH` in reload**

Replace:

```python
new_config = load_config("config.yaml")
raw = yaml.safe_load(open("config.yaml"))
```

with:

```python
config_path = os.environ.get("EASM_CONFIG_PATH", "config.yaml")
new_config = load_config(config_path)
raw = yaml.safe_load(Path(config_path).read_text())
```

- [ ] **Step 4: Return modified target IDs**

Compute config hashes per target or compare `model_dump(mode="json")`:

```python
old_targets = {t.id: t.model_dump(mode="json") for t in config.targets}
new_targets = {t.id: t.model_dump(mode="json") for t in new_config.targets}
modified = [tid for tid in old_targets.keys() & new_targets.keys() if old_targets[tid] != new_targets[tid]]
```

Return `modified`.

- [ ] **Step 5: Run verification**

Run:

```bash
PYTHONPATH=src python -m pytest tests/test_api.py tests/test_config.py -q
python -m compileall -q src tests
```

Expected: config history and reload tests pass when DB deps exist.

---

## Task 15: Run Safe Simulation And Bug-Squashing Pass

**Files:**
- Exercise: `config.offline.yaml`
- Exercise: `docker-compose.offline.yml`
- Exercise: API endpoints `/api/runs`, `/api/entities`, `/api/pivot-queue`, `/api/pivot-queue/summary`, `/api/graph/{target_id}`

- [ ] **Step 1: Preflight**

Run:

```bash
docker images
docker compose -f docker-compose.offline.yml config
```

Expected: compose config passes. If required base images are missing and no network is allowed, do not build; record that image preload is required.

- [ ] **Step 2: Start simulation only when approved**

Run only after approval:

```bash
docker compose -f docker-compose.offline.yml up --build
```

Expected: app starts, health reports `runtime.mode = simulate`, no real target traffic is possible from the internal network, and KEV startup refresh is skipped.

- [ ] **Step 3: Trigger simulated runner**

Use UI or API:

```bash
curl -X POST http://127.0.0.1:8000/api/runs/sim/subfinder
```

Expected:

```text
run status completed
inserted_count > 0
new_entity_count > 0
pivot_queue pending count > 0
```

- [ ] **Step 4: Observe pivot cascade**

Check:

```bash
curl http://127.0.0.1:8000/api/pivot-queue/summary
curl http://127.0.0.1:8000/api/entities?target_id=sim
curl http://127.0.0.1:8000/api/graph/sim
```

Expected: fixture hostnames become entities, `dns_resolve` fixture creates IP entities, recursive pivots either enqueue or are explicitly skipped with visible reasons.

- [ ] **Step 5: File bugs from simulation results**

For every unexpected stop, record:

```text
Checkpoint:
- raw_event inserted?
- entity inserted?
- entity type/value?
- pivot rules matching?
- scope result?
- classification?
- pivot_queue row?
- worker status?
- source_name?
- output schema?
- downstream entity inserted?
Root cause:
Fix task:
Test added:
```

---

## Parallel Subagent Execution Plan

Once Tasks 1-3 establish the runtime skeleton, dispatch implementation workers in parallel with disjoint ownership:

- **Worker A, Simulation Runtime:** Owns `src/easm/runtime.py`, fixtures, `tests/test_simulation_runtime.py`.
- **Worker B, Runner Ingestion:** Owns `src/easm/runners/engine.py`, `src/easm/runners/base.py`, runner-flow tests.
- **Worker C, Schema And Entity Types:** Owns `src/easm/runners/schemas.py`, schema tests, subfinder hostname fix.
- **Worker D, Pivot Resolver:** Owns `src/easm/pivot/resolver.py`, resolver tests.
- **Worker E, Pivot Worker Reliability:** Owns `src/easm/pivot/worker.py`, `src/easm/store.py` atomic dequeue, worker tests.
- **Worker F, API Diagnostics:** Owns `src/easm/api/routes/pivot_queue.py`, `src/easm/api/routes/config.py`, API tests.
- **Worker G, UI Diagnostics:** Owns `ui/src/api/pivot-queue.ts`, `ui/src/components/targets/PivotQueueTable.tsx`.
- **Worker H, Test Environment:** Owns `tests/conftest.py`, pytest markers, docs for dependency-light and DB suites.

All workers must follow these constraints:

```text
Do not make commits.
Do not start scans.
Do not run commands that send traffic to public targets.
Do not pull images or install dependencies without explicit approval.
Do not overwrite unrelated dirty files.
Return changed file paths, tests run, and blockers.
```

---

## Final Verification Matrix

Run in this order:

```bash
python -m compileall -q src tests
docker compose -f docker-compose.offline.yml config
PYTHONPATH=src python -m pytest --confcutdir=tests tests/test_config.py tests/test_schemas.py tests/test_simulation_runtime.py tests/test_simulation_runner_flow.py tests/test_simulation_pivot_worker.py -q
```

When dependencies and Postgres 18 are available:

```bash
PYTHONPATH=src alembic upgrade head
PYTHONPATH=src python -m pytest -m db -q
npm --prefix ui run build
```

Manual safe simulation, only after approval:

```bash
docker compose -f docker-compose.offline.yml up --build
```

Success criteria:
- Simulation mode visibly reports `runtime.mode = simulate`.
- Startup performs no KEV refresh, no PDCP config write, no real scanner subprocess.
- Simulated runner output creates raw events, entities, pivot jobs, and downstream entities.
- Every stopped pivot has visible status, error message, or skip reason in API and UI.
- Run counters and discovery session IDs correctly tie runner results to pivot results.
- No commits are created.
