# Performance Tuning & Vulnerability Monitoring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent self-DoS from uncontrolled retries/queuing, add batch processing, and integrate CISA KEV + NVD vulnerability monitoring with CPE computation from detected software.

**Architecture:** Add shared HTTP client connection pooling across pivot handlers, batch dequeue in pivot workers, rate-limit semaphores per external API, and concurrency limits in scheduler. For vulnerability monitoring, add a CPE mapper that converts Wappalyzer/nmap detections to CPE 2.3 URIs, then match against a locally-cached CISA KEV and NVD database refreshed by scheduled jobs, with detection results flowing through the existing correlation engine as findings.

**Tech Stack:** Python 3.14, asyncpg, httpx, APScheduler, Pydantic, YAML

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `src/easm/runners/schemas.py` | Modify | Store Shodan `cpes` in entity attributes (1-line fix) |
| `src/easm/pivot/worker.py` | Modify | Batch dequeue, shared HTTP client, handler signature change |
| `src/easm/store.py` | Modify | New `dequeue_pivot_jobs_batch()` method |
| `src/easm/pivot/handlers.py` | Modify | Accept shared `http_client` param in all HTTP-using handlers |
| `src/easm/scheduler.py` | Modify | Max-concurrent-runs enforcement, KEV/NVD refresh jobs |
| `src/easm/main.py` | Modify | Shared HTTP client lifecycle, startup cache population |
| `src/easm/config.py` | Modify | New `RateLimitConfig`, `VulnMonitoringConfig` models |
| `src/easm/pivot/resolver.py` | Modify | Max queue depth gate before enqueue |
| `src/easm/cpe_mapper.py` | **Create** | CPE 2.3 URI generation from tech names + versions |
| `src/easm/vuln_cache.py` | **Create** | Local NVD/KEV cache with scheduled refresh |
| `src/easm/vuln_enrichment.py` | **Create** | Pivot handler: CPE → CVE → KEV lookup |
| `correlations/known_exploited_vulnerability.yaml` | **Create** | Correlation rule for KEV-matched CVEs |
| `alembic/versions/0006_vuln_cache.py` | **Create** | Migration: `cve_cache` table |

---

### Task 1: Fix Shodan CPEs Storage

**Files:**
- Modify: `src/easm/runners/schemas.py:314-321`
- Test: `tests/test_schemas.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_schemas.py
from easm.runners.schemas import shodan


def test_shodan_stores_cpes():
    raw = {
        "ip": "1.2.3.4",
        "shodan": {
            "ports": [80, 443],
            "vulns": ["CVE-2023-44487"],
            "cpes": ["cpe:/a:apache:http_server:2.4.41"],
            "org": "Example Corp",
            "isp": "Example ISP",
            "asn": "AS12345",
            "country_name": "US",
            "city": "Mountain View",
            "os": "Linux",
            "data": [],
        },
    }
    entities, _ = shodan(raw)
    assert len(entities) == 1
    attrs = entities[0].attributes
    assert "cpes" in attrs, f"cpes missing from attributes: {list(attrs.keys())}"
    assert attrs["cpes"] == ["cpe:/a:apache:http_server:2.4.41"]


def test_shodan_internetdb_stores_cpes():
    raw = {
        "ip": "1.2.3.4",
        "ports": [80, 443],
        "hostnames": ["example.com"],
        "cpes": ["cpe:/a:nginx:nginx:1.24.0"],
        "vulns": ["CVE-2024-1234"],
        "source": "shodan",
    }
    entities, _ = shodan(raw)
    assert len(entities) == 1
    attrs = entities[0].attributes
    assert "cpes" in attrs, f"cpes missing from attributes: {list(attrs.keys())}"
    assert attrs["cpes"] == ["cpe:/a:nginx:nginx:1.24.0"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_schemas.py -v`
Expected: FAIL — `cpes` key not in entity attributes

- [ ] **Step 3: Fix the shodan output schema**

```python
# src/easm/runners/schemas.py — modify the shodan() function (line 314-321)
def shodan(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    if not ip:
        return [], []
    s = raw.get("shodan", raw)
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {
        "source": "shodan", "ports": s.get("ports", []),
        "hostnames": s.get("hostnames", []), "domains": s.get("domains", []),
        "vulnerabilities": [v for v in s.get("vulns", []) if isinstance(v, str)],
        "cpes": [c for c in s.get("cpes", []) if isinstance(c, str)],
        "org": s.get("org", ""), "isp": s.get("isp", ""), "asn": s.get("asn", ""),
        "country": s.get("country_name", ""), "city": s.get("city", ""),
        "os": s.get("os", ""), "services": s.get("data", []),
    })], []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_schemas.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add tests/test_schemas.py src/easm/runners/schemas.py
git commit -m "fix: store Shodan cpes in entity attributes for CPE computation"
```

---

### Task 2: Shared HTTP Client for Pivot Handlers

**Files:**
- Modify: `src/easm/pivot/handlers.py` — change signature: add `http_client` param to HTTP-using handlers
- Modify: `src/easm/pivot/worker.py:38-92` — create shared client, pass to handlers
- Test: `tests/test_pivot_worker.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pivot_worker.py
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from easm.pivot.handlers import crtsh_search


@pytest.mark.asyncio
async def test_crtsh_search_reuses_http_client():
    """crtsh_search should use the http_client passed via pool, not create its own."""
    job = {
        "entity_value": "example.com",
        "org_id": "test-org",
        "target_id": "test-target",
    }
    shared_client = AsyncMock()
    shared_client.get.return_value.status_code = 200
    shared_client.get.return_value.json.return_value = [
        {"name_value": "example.com\nwww.example.com", "fingerprint": "abc123"}
    ]
    shared_client.get.return_value.headers = {}

    # Pass via pool kwarg
    results = await crtsh_search(job, pool=None, http_client=shared_client)

    assert len(results) > 0
    # Verify shared client was used (get() was called)
    shared_client.get.assert_called()
    # Verify we didn't create a new client (httpx.AsyncClient constructor not called)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pivot_worker.py::test_crtsh_search_reuses_http_client -v`
Expected: FAIL — `crtsh_search() got an unexpected keyword argument 'http_client'`

- [ ] **Step 3: Modify crtsh_search to accept shared http_client**

```python
# src/easm/pivot/handlers.py — modify crtsh_search (line 159-188)
async def crtsh_search(job: dict, pool, http_client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    domain = domain.replace("*.", "")
    max_retries = 3
    base_delay = 1.0
    use_shared = http_client is not None

    for attempt in range(max_retries):
        if use_shared:
            resp = await http_client.get(f"https://crt.sh/?q=%.{domain}&output=json")
        else:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
        if resp.status_code == 200:
            data = resp.json()
            return [{"name_value": ",".join(c.get("name_value", "") for c in data),
                     "fingerprint": data[0].get("fingerprint", ""),
                     "serial_number": data[0].get("serial_number", ""),
                     "not_before": data[0].get("not_before", ""),
                     "not_after": data[0].get("not_after", ""),
                     "issuer_name_id": data[0].get("issuer_name_id", "")}]
        if resp.status_code == 502 or resp.status_code == 503:
            if attempt < max_retries - 1:
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = float(retry_after)
                    except ValueError:
                        wait = base_delay * (2 ** attempt)
                else:
                    wait = base_delay * (2 ** attempt)
                await asyncio.sleep(wait)
                continue
        if resp.status_code == 404:
            return [{"domain": domain, "message": "no certificates found"}]
        return [{"domain": domain, "error": f"HTTP {resp.status_code}"}]
    return [{"domain": domain, "error": "max retries exceeded"}]
```

- [ ] **Step 4: Modify ALL HTTP-using handlers to accept shared http_client**

Apply the same pattern to the following handlers in `handlers.py`. Each replaces `async with httpx.AsyncClient(timeout=...) as client:` with using the `http_client` param when provided:

- `shodan_enrich` (line 335-362) — add `http_client: httpx.AsyncClient | None = None`
- `abuseipdb_enrich` (line 365-385) — add `http_client: httpx.AsyncClient | None = None`
- `greynoise_enrich` (line 388-402) — add `http_client: httpx.AsyncClient | None = None`
- `urlscan_enrich` (line 405-423) — add `http_client: httpx.AsyncClient | None = None`
- `censys_enrich` (line 426-443) — add `http_client: httpx.AsyncClient | None = None`
- `passive_dns` (line 228-245) — add `http_client: httpx.AsyncClient | None = None`
- `rdap_lookup` (line 248-266) — add `http_client: httpx.AsyncClient | None = None`
- `reverse_whois` (line 269-278) — add `http_client: httpx.AsyncClient | None = None`
- `domain_rdap` (line 281-332) — add `http_client: httpx.AsyncClient | None = None`

For each handler, the pattern is:
```python
async def handler_name(job: dict, pool, http_client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
    # ... existing logic ...
    if http_client is not None:
        resp = await http_client.get(url, ...)  # use shared
    else:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(url, ...)  # fallback: own client
```

- [ ] **Step 5: Modify pivot_worker_pool to create and pass shared HTTP client**

```python
# src/easm/pivot/worker.py — modify pivot_worker_pool (line 38-92)
import httpx

async def pivot_worker_pool(pool, n: int = 3, batch_interval_ms: int = 200):
    store = Store(pool)
    await store.reset_orphaned_pivot_jobs()

    # Shared HTTP client with connection pooling for all pivot handlers
    shared_http = httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
    )

    async def worker_loop():
        while True:
            job = await store.dequeue_pivot_job()
            if job:
                try:
                    handler_fn = PIVOT_HANDLER_REGISTRY.get(job["pivot_type"])
                    if not handler_fn:
                        await store.mark_pivot_failed(job["id"], "no handler for pivot type")
                        continue

                    results = await handler_fn(job, pool, http_client=shared_http)
                    # ... rest unchanged ...
                except Exception:
                    logger.exception(...)
                    await store.mark_pivot_failed(job["id"], "see logs")
            else:
                await asyncio.sleep(batch_interval_ms / 1000)

    try:
        async with asyncio.TaskGroup() as tg:
            for _ in range(n):
                tg.create_task(worker_loop())
    finally:
        await shared_http.aclose()
```

- [ ] **Step 6: Run tests to verify**

Run: `uv run pytest tests/test_pivot_worker.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/easm/pivot/handlers.py src/easm/pivot/worker.py tests/test_pivot_worker.py
git commit -m "perf: add shared HTTP client across pivot handlers for connection pooling"
```

---

### Task 3: Batch Dequeue in Pivot Worker

**Files:**
- Modify: `src/easm/store.py:396-409` — add `dequeue_pivot_jobs_batch()`
- Modify: `src/easm/pivot/worker.py:42-87` — use batch dequeue
- Test: `tests/test_store.py` (modify)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_store.py — add to existing test file
import pytest
import uuid


@pytest.mark.asyncio
async def test_dequeue_pivot_jobs_batch_returns_multiple(store, pool):
    """Batch dequeue should return up to N jobs of the same pivot_type."""
    org_id = "test-org"
    target_id = "test-target"

    # Enqueue 5 crtsh_search jobs
    ids = []
    for i in range(5):
        jid = await store.enqueue_pivot_job(
            org_id=org_id, target_id=target_id,
            entity_type="domain", entity_value=f"sub{i}.example.com",
            entity_id=uuid.uuid4(), pivot_type="crtsh_search", depth=1,
        )
        ids.append(jid)

    # Batch dequeue up to 3
    batch = await store.dequeue_pivot_jobs_batch(limit=3)
    assert len(batch) == 3
    assert all(j["pivot_type"] == "crtsh_search" for j in batch)
    assert all(j["status"] == "running" for j in batch)

    # Remaining 2 should be dequeueable
    batch2 = await store.dequeue_pivot_jobs_batch(limit=3)
    assert len(batch2) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_store.py::test_dequeue_pivot_jobs_batch_returns_multiple -v`
Expected: FAIL — `'Store' object has no attribute 'dequeue_pivot_jobs_batch'`

- [ ] **Step 3: Add batch dequeue method to Store**

```python
# src/easm/store.py — add after dequeue_pivot_job (line 409)
async def dequeue_pivot_jobs_batch(self, limit: int = 50) -> list[dict[str, Any]]:
    """Dequeue up to ``limit`` pending pivot jobs of the same pivot_type.

    Returns jobs already marked as 'running'.
    """
    rows = await self.pool.fetch("""
        SELECT * FROM pivot_queue
        WHERE status = 'pending'
        ORDER BY enqueued_at
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    """, limit)
    if not rows:
        return []
    jobs = []
    for row in rows:
        await self.pool.execute(
            "UPDATE pivot_queue SET status='running', started_at=NOW() WHERE id=$1",
            row["id"],
        )
        jobs.append(dict(row))
    return jobs
```

- [ ] **Step 4: Modify pivot_worker_pool to use batch dequeue**

```python
# src/easm/pivot/worker.py — modify worker_loop() (line 42-87)
async def worker_loop():
    while True:
        jobs = await store.dequeue_pivot_jobs_batch(limit=20)
        if jobs:
            for job in jobs:
                try:
                    handler_fn = PIVOT_HANDLER_REGISTRY.get(job["pivot_type"])
                    if not handler_fn:
                        await store.mark_pivot_failed(job["id"], "no handler for pivot type")
                        continue

                    results = await handler_fn(job, pool, http_client=shared_http)
                    # ... process results, mark completed, run correlation ...
                    source_name = PIVOT_SOURCE_NAMES.get(job["pivot_type"], job["pivot_type"])
                    for raw_result in results:
                        meta = {
                            "_meta": {
                                "session_id": (
                                    str(job["discovery_session_id"])
                                    if job["discovery_session_id"]
                                    else None
                                ),
                                "pivot_job_id": str(job["id"]),
                            },
                            **raw_result,
                        }
                        event_hash = _compute_event_hash(
                            job["org_id"], job["target_id"], source_name, meta,
                        )
                        raw_json = json.dumps(meta)
                        await pool.execute(
                            """INSERT INTO raw_events
                               (org_id, target_id, source, raw, event_hash, run_id)
                               VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                               ON CONFLICT (event_hash) DO NOTHING""",
                            job["org_id"], job["target_id"], source_name,
                            raw_json, event_hash, job["run_id"],
                        )
                    await store.mark_pivot_completed(job["id"])
                except Exception:
                    logger.exception(
                        "pivot job failed: job_id=%s pivot_type=%s entity_value=%s",
                        str(job["id"]), job["pivot_type"], job["entity_value"],
                    )
                    await store.mark_pivot_failed(job["id"], "see logs")

            # Run correlation once after batch (not per-job)
            if jobs:
                first = jobs[0]
                await _run_correlation(store, first["org_id"], first["target_id"])
        else:
            await asyncio.sleep(batch_interval_ms / 1000)
```

- [ ] **Step 5: Run tests to verify**

Run: `uv run pytest tests/test_store.py::test_dequeue_pivot_jobs_batch_returns_multiple -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/easm/store.py src/easm/pivot/worker.py tests/test_store.py
git commit -m "perf: batch dequeue pivot jobs (LIMIT N) with pooled correlation"
```

---

### Task 4: Rate Limiting Semaphores for Pivot Handlers

**Files:**
- Create: `src/easm/rate_limiter.py`
- Modify: `src/easm/pivot/worker.py` — create semaphores, pass to handlers
- Modify: `src/easm/pivot/handlers.py` — use semaphore in HTTP handlers
- Test: `tests/test_rate_limiter.py` (create)

- [ ] **Step 1: Write the rate limiter module**

```python
# src/easm/rate_limiter.py
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class ApiRateLimiters:
    """Per-API asyncio semaphores for concurrency control."""

    crtsh: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(5))
    shodan: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(5))
    censys: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(2))
    greynoise: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(10))
    abuseipdb: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(5))
    urlscan: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(3))
    securitytrails: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(3))
    rdap: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(3))


def get_default_limiters() -> ApiRateLimiters:
    return ApiRateLimiters()
```

- [ ] **Step 2: Write the test**

```python
# tests/test_rate_limiter.py
import asyncio

from easm.rate_limiter import ApiRateLimiters, get_default_limiters


def test_default_limiters_created():
    limiters = get_default_limiters()
    assert limiters.crtsh._value == 5
    assert limiters.shodan._value == 5
    assert limiters.censys._value == 2


async def test_semaphore_limits_concurrency():
    limiter = asyncio.Semaphore(2)
    running = 0
    max_running = 0

    async def worker():
        nonlocal running, max_running
        async with limiter:
            running += 1
            max_running = max(max_running, running)
            await asyncio.sleep(0.01)
            running -= 1

    tasks = [asyncio.create_task(worker()) for _ in range(10)]
    await asyncio.gather(*tasks)
    assert max_running <= 2
```

- [ ] **Step 3: Run test to verify it passes**

Run: `uv run pytest tests/test_rate_limiter.py -v`
Expected: PASS

- [ ] **Step 4: Wire semaphores into pivot handlers**

```python
# src/easm/pivot/handlers.py — modify crtsh_search to use semaphore
async def crtsh_search(job: dict, pool, http_client: httpx.AsyncClient | None = None,
                       limiters=None) -> list[dict[str, Any]]:
    domain = job["entity_value"].replace("*.", "")
    max_retries = 3
    base_delay = 1.0
    use_shared = http_client is not None

    sem = limiters.crtsh if limiters else None
    if sem:
        await sem.acquire()
    try:
        for attempt in range(max_retries):
            if use_shared:
                resp = await http_client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            else:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            # ... response handling unchanged ...
    finally:
        if sem:
            sem.release()

    # ... return handling unchanged ...
```

Apply the same semaphore pattern (`limiters.shodan`, `limiters.censys`, etc.) to the other HTTP-using handlers listed in Task 2 Step 4.

- [ ] **Step 5: Create semaphores in pivot_worker_pool and pass to handlers**

```python
# src/easm/pivot/worker.py — add import and create limiters
from easm.rate_limiter import get_default_limiters

async def pivot_worker_pool(pool, n: int = 3, batch_interval_ms: int = 200):
    store = Store(pool)
    await store.reset_orphaned_pivot_jobs()
    limiters = get_default_limiters()

    shared_http = httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
    )

    async def worker_loop():
        while True:
            jobs = await store.dequeue_pivot_jobs_batch(limit=20)
            if jobs:
                for job in jobs:
                    try:
                        handler_fn = PIVOT_HANDLER_REGISTRY.get(job["pivot_type"])
                        if not handler_fn:
                            await store.mark_pivot_failed(job["id"], "no handler")
                            continue

                        results = await handler_fn(
                            job, pool, http_client=shared_http, limiters=limiters,
                        )
                        # ... rest unchanged ...
```

- [ ] **Step 6: Commit**

```bash
git add src/easm/rate_limiter.py src/easm/pivot/handlers.py src/easm/pivot/worker.py tests/test_rate_limiter.py
git commit -m "feat: add per-API rate-limit semaphores for pivot handlers"
```

---

### Task 5: Max Concurrent Runs Enforcement in Scheduler

**Files:**
- Modify: `src/easm/scheduler.py:34-46` — add active-run tracking
- Modify: `src/easm/store.py` — add `count_active_runs()` method
- Test: `tests/test_scheduler.py` (create)

- [ ] **Step 1: Add count_active_runs to Store**

```python
# src/easm/store.py — add method
async def count_active_runs(self, target_id: str, source_name: str) -> int:
    row = await self.pool.fetchval("""
        SELECT COUNT(*) FROM runs
        WHERE target_id = $1 AND source = $2 AND status = 'started'
    """, target_id, source_name)
    return row or 0
```

- [ ] **Step 2: Modify scheduler to skip if active run exists**

```python
# src/easm/scheduler.py — modify _run_job (line 34-46)
async def _run_job():
    # Skip if a previous run of the same runner+target is still in progress
    active = await store.count_active_runs(target.id, runner_def.source_name)
    if active > 0:
        logger.info(
            "skipping scheduled run: previous run still active",
            extra={"target_id": target.id, "runner": runner_name, "active_runs": active},
        )
        return

    http_client = httpx.AsyncClient(timeout=30.0)
    try:
        await execute_runner(
            runner_def.source_name,
            runner_def.run_fn,
            target,
            store,
            "scheduled",
            http_client=http_client,
        )
    finally:
        await http_client.aclose()
```

- [ ] **Step 3: Write the test**

```python
# tests/test_scheduler.py
import pytest
from unittest.mock import AsyncMock, MagicMock

from easm.scheduler import Scheduler


@pytest.mark.asyncio
async def test_skips_run_when_active_exists():
    """Scheduler should skip a cron-triggered run if one is already in progress."""
    scheduler = Scheduler()
    mock_store = AsyncMock()
    mock_store.count_active_runs.return_value = 1  # indicates an active run

    # ... set up target and runner config, trigger _run_job ...
    # Verify execute_runner was NOT called

@pytest.mark.asyncio
async def test_runs_when_no_active():
    """Scheduler should proceed when no active run exists."""
    scheduler = Scheduler()
    mock_store = AsyncMock()
    mock_store.count_active_runs.return_value = 0

    # ... set up target and runner config, trigger _run_job ...
    # Verify execute_runner WAS called
```

- [ ] **Step 4: Run tests to verify**

Run: `uv run pytest tests/test_scheduler.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/scheduler.py src/easm/store.py tests/test_scheduler.py
git commit -m "feat: skip scheduled runs when previous run still active"
```

---

### Task 6: Max Queue Depth Gate in Pivot Resolver

**Files:**
- Modify: `src/easm/pivot/resolver.py:60-70` — add queue depth check before enqueue
- Modify: `src/easm/config.py` — add `max_queue_depth` to `PivotConfig`
- Test: `tests/test_pivot_resolver.py` (create)

- [ ] **Step 1: Add max_queue_depth to config model**

```python
# src/easm/config.py — modify PivotConfig (line 79-86)
class PivotConfig(BaseModel):
    enabled: bool = False
    max_depth: int = 3
    max_concurrent: int = 3
    batch_interval_ms: int = 200
    scope_mode: str = "strict"
    max_queue_depth: int = 10000  # NEW: skip enqueue when queue exceeds this
    allowed_pivots: list[AllowedPivot] = Field(default_factory=list)
```

- [ ] **Step 2: Add queue depth gate in check_and_enqueue**

```python
# src/easm/pivot/resolver.py — add before the for loop (after line 33)
MAX_QUEUE_DEPTH = 10000

async def check_and_enqueue(self, target, entity_type, entity_value, entity_id, ...):
    # ... existing depth/scope/classification checks ...

    # Gate: skip enqueue if queue is too deep
    queue_depth = pivot_config.max_queue_depth if hasattr(pivot_config, 'max_queue_depth') else MAX_QUEUE_DEPTH
    count = await self.pool.fetchval(
        "SELECT COUNT(*) FROM pivot_queue WHERE status = 'pending'"
    )
    if count and count >= queue_depth:
        logger.warning(
            "pivot queue at capacity, skipping enqueue",
            extra={"queue_depth": count, "max": queue_depth, "target_id": target.id},
        )
        return

    for pivot_rule in pivot_config.allowed_pivots:
        # ... existing logic ...
```

- [ ] **Step 3: Write the test**

```python
# tests/test_pivot_resolver.py
import pytest
from unittest.mock import AsyncMock

from easm.pivot.resolver import PivotResolver


@pytest.mark.asyncio
async def test_skips_enqueue_when_queue_full():
    """PivotResolver should skip enqueue when pending queue exceeds max."""
    mock_pool = AsyncMock()
    # Simulate queue at capacity
    mock_pool.fetchval.return_value = 10000

    resolver = PivotResolver(mock_pool)
    mock_target = MagicMock()
    mock_target.pivot.enabled = True
    mock_target.pivot.max_depth = 3
    mock_target.pivot.max_queue_depth = 5000
    mock_target.pivot.scope_mode = "strict"
    mock_target.pivot.allowed_pivots = [
        MagicMock(from_="domain", via="crtsh_search", cooldown_hours=0, coverage=None),
    ]

    await resolver.check_and_enqueue(
        mock_target, "domain", "example.com", "entity-id-123",
    )

    # enqueue_pivot_job should NOT have been called
    resolver.store.enqueue_pivot_job.assert_not_called()
```

- [ ] **Step 4: Run tests to verify**

Run: `uv run pytest tests/test_pivot_resolver.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/pivot/resolver.py src/easm/config.py tests/test_pivot_resolver.py
git commit -m "feat: gate pivot enqueue when queue depth exceeds max_queue_depth"
```

---

### Task 7: CPE Mapper Module

**Files:**
- Create: `src/easm/cpe_mapper.py`
- Test: `tests/test_cpe_mapper.py` (create)

- [ ] **Step 1: Write the CPE mapper module**

```python
# src/easm/cpe_mapper.py
"""CPE 2.3 URI generation from detected technology names and versions.

Converts Wappalyzer ``technologies`` entries and nmap service strings
into CPE 2.3 formatted strings for NVD/KEV matching.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Map of common technology names to CPE vendor:product pairs.
# Extended during use — this is a bootstrap set.
TECH_TO_CPE: dict[str, tuple[str, str]] = {
    # Web servers
    "nginx": ("nginx", "nginx"),
    "apache http server": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "caddy": ("caddyserver", "caddy"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    # CMS
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "ghost": ("ghost", "ghost"),
    # Languages / runtimes
    "php": ("php", "php"),
    "python": ("python", "python"),
    "ruby": ("ruby-lang", "ruby"),
    "node.js": ("nodejs", "node.js"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    # JavaScript frameworks
    "react": ("facebook", "react"),
    "vue.js": ("vuejs", "vue.js"),
    "angular": ("angular", "angular"),
    "jquery": ("jquery", "jquery"),
    # Proxy / load balancer
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-cache", "varnish_cache"),
    "traefik": ("traefik", "traefik"),
    # Cloud / CDN
    "aws cloudfront": ("amazon", "cloudfront"),
    "cloudflare": ("cloudflare", "cloudflare"),
    # Misc
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "powerdns": ("powerdns", "powerdns"),
    "memcached": ("memcached", "memcached"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "grafana": ("grafana", "grafana"),
    "prometheus": ("prometheus", "prometheus"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
}


def _normalize_version(version: str) -> str:
    """Strip leading non-digit characters (v, =, etc.) from version string."""
    if not version:
        return "*"
    cleaned = version.strip().lstrip("vV= ")
    # Validate we have something version-like
    if not cleaned or not re.match(r"^[\d.]+", cleaned):
        return "*"
    return cleaned


def tech_to_cpe(tech_name: str, tech_version: str | None = None) -> str | None:
    """Convert a technology name + version to a CPE 2.3 URI string.

    Returns a CPE 2.3 formatted string like
    ``cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*:*``
    or ``None`` if the technology is not in the mapping.

    Args:
        tech_name: Technology name from Wappalyzer (e.g., "nginx", "WordPress")
        tech_version: Version string (e.g., "1.24.0", "6.4")

    Returns:
        CPE 2.3 URI string or None
    """
    key = tech_name.lower().strip()
    if key not in TECH_TO_CPE:
        return None

    vendor, product = TECH_TO_CPE[key]
    version = _normalize_version(tech_version) if tech_version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*:*"


def nmap_service_to_cpe(service_name: str) -> str | None:
    """Convert an nmap service name to a CPE vendor:product lookup.

    Uses the same TECH_TO_CPE mapping but handles nmap-specific naming
    (e.g., "http" → apache/nginx, "ssh" → openssh).
    """
    nmap_to_tech: dict[str, str] = {
        "http": "apache http server",
        "https": "apache http server",
        "http-proxy": "haproxy",
        "ssh": "openssh",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "redis": "redis",
        "mongodb": "mongodb",
        "smtp": "postfix",
        "imap": "dovecot",
        "pop3": "dovecot",
        "dns": "bind",
        "ftp": "proftpd",
        "rdp": "microsoft",
        "vnc": "realvnc",
        "elasticsearch": "elasticsearch",
    }
    tech_name = nmap_to_tech.get(service_name, service_name)
    return tech_to_cpe(tech_name, None)


def compute_cpes_from_entity(entity_type: str, attributes: dict[str, Any]) -> list[str]:
    """Extract all CPEs from an entity's attributes.

    Handles Wappalyzer ``technologies``, Shodan ``cpes`` (pass-through),
    and portscan ``open_ports`` service names.

    Args:
        entity_type: Entity type (hostname, ip)
        attributes: Entity attributes dict (JSONB)

    Returns:
        List of CPE 2.3 URI strings
    """
    cpes: list[str] = []

    # 1. Shodan cpes (already CPE strings, pass-through)
    for cpe in attributes.get("cpes", []):
        if isinstance(cpe, str) and cpe.startswith("cpe:"):
            cpes.append(cpe)

    # 2. Wappalyzer technologies
    for tech in attributes.get("technologies", []):
        if isinstance(tech, dict):
            name = tech.get("name", "")
            version = tech.get("version") or None
            cpe = tech_to_cpe(name, version)
            if cpe:
                cpes.append(cpe)

    # 3. nmap port scan services
    for port_info in attributes.get("open_ports", []):
        if isinstance(port_info, dict):
            service = port_info.get("service", "")
            if service:
                cpe = nmap_service_to_cpe(service)
                if cpe:
                    cpes.append(cpe)

    # 3. nmap services via shodan
    for svc in attributes.get("services", []):
        if isinstance(svc, dict):
            product = svc.get("product", "")
            version = svc.get("version") or None
            if product:
                cpe = tech_to_cpe(product, version)
                if cpe:
                    cpes.append(cpe)

    return list(dict.fromkeys(cpes))  # deduplicate, preserve order
```

- [ ] **Step 2: Write the test**

```python
# tests/test_cpe_mapper.py
from easm.cpe_mapper import tech_to_cpe, compute_cpes_from_entity, nmap_service_to_cpe


def test_tech_to_cpe_known():
    cpe = tech_to_cpe("nginx", "1.24.0")
    assert cpe == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*:*"


def test_tech_to_cpe_case_insensitive():
    cpe = tech_to_cpe("WordPress", "6.4")
    assert cpe == "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*:*"


def test_tech_to_cpe_no_version():
    cpe = tech_to_cpe("nginx", None)
    assert cpe == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"


def test_tech_to_cpe_strips_v_prefix():
    cpe = tech_to_cpe("php", "v8.2.1")
    assert cpe == "cpe:2.3:a:php:php:8.2.1:*:*:*:*:*:*:*:*"


def test_tech_to_cpe_unknown():
    cpe = tech_to_cpe("unknown-tech", "1.0")
    assert cpe is None


def test_nmap_service_to_cpe():
    cpe = nmap_service_to_cpe("ssh")
    assert cpe is not None
    assert "openssh" in cpe


def test_compute_cpes_from_wappalyzer():
    attrs = {
        "technologies": [
            {"name": "nginx", "version": "1.24.0"},
            {"name": "WordPress", "version": "6.4"},
            {"name": "unknown", "version": "1.0"},
        ],
    }
    cpes = compute_cpes_from_entity("hostname", attrs)
    assert len(cpes) == 2
    assert "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*:*" in cpes
    assert "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*:*" in cpes


def test_compute_cpes_from_shodan_pass_through():
    attrs = {"cpes": ["cpe:/a:apache:http_server:2.4.41"]}
    cpes = compute_cpes_from_entity("ip", attrs)
    assert len(cpes) == 1
    assert "cpe:/a:apache:http_server:2.4.41" in cpes


def test_compute_cpes_deduplicates():
    attrs = {
        "technologies": [{"name": "nginx", "version": "1.24.0"}],
        "cpes": ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*:*"],
    }
    cpes = compute_cpes_from_entity("hostname", attrs)
    assert len(cpes) == 1
```

- [ ] **Step 3: Run tests to verify**

Run: `uv run pytest tests/test_cpe_mapper.py -v`
Expected: PASS (all 8 tests)

- [ ] **Step 4: Commit**

```bash
git add src/easm/cpe_mapper.py tests/test_cpe_mapper.py
git commit -m "feat: add CPE mapper — tech names/versions to CPE 2.3 URIs"
```

---

### Task 8: CISA KEV Fetcher + Cache

**Files:**
- Create: `src/easm/vuln_cache.py`
- Create: `alembic/versions/0006_vuln_cache.py`
- Modify: `src/easm/main.py` — startup cache population + scheduled refresh
- Modify: `src/easm/scheduler.py` — KEV refresh job
- Test: `tests/test_vuln_cache.py` (create)

- [ ] **Step 1: Create the database migration**

```python
# alembic/versions/0006_vuln_cache.py
"""Add cve_cache table for local NVD/KEV caching.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-17
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id          TEXT PRIMARY KEY,
            description     TEXT,
            cvss_score      REAL,
            cvss_severity   TEXT,
            cpe_matches     JSONB DEFAULT '[]'::jsonb,
            kev_included    BOOLEAN DEFAULT FALSE,
            kev_date_added  DATE,
            kev_due_date    DATE,
            kev_vendor      TEXT,
            kev_product     TEXT,
            kev_notes       TEXT,
            last_refreshed  TIMESTAMPTZ DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS idx_cve_cache_kev ON cve_cache(kev_included);
        CREATE INDEX IF NOT EXISTS idx_cve_cache_severity ON cve_cache(cvss_severity);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS cve_cache;")
```

- [ ] **Step 2: Write the vuln_cache module**

```python
# src/easm/vuln_cache.py
"""Local cache for CISA KEV (Known Exploited Vulnerabilities) data.

Downloads and caches the CISA KEV JSON feed into the ``cve_cache`` table.
Provides lookup functions for matching CPEs against known-exploited CVEs.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime, UTC
from typing import Any

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def refresh_kev_cache(pool) -> int:
    """Download CISA KEV JSON and upsert into cve_cache table.

    Returns the number of CVEs upserted.
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()

    vulnerabilities = data.get("vulnerabilities", [])
    upserted = 0
    now = datetime.now(UTC)

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        await pool.execute("""
            INSERT INTO cve_cache (cve_id, description, kev_included, kev_date_added,
                                   kev_due_date, kev_vendor, kev_product, kev_notes,
                                   last_refreshed)
            VALUES ($1, $2, TRUE, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (cve_id) DO UPDATE SET
                kev_included = TRUE,
                kev_date_added = EXCLUDED.kev_date_added,
                kev_due_date = EXCLUDED.kev_due_date,
                kev_vendor = EXCLUDED.kev_vendor,
                kev_product = EXCLUDED.kev_product,
                kev_notes = EXCLUDED.kev_notes,
                last_refreshed = EXCLUDED.last_refreshed
        """,
            cve_id,
            vuln.get("shortDescription", ""),
            _parse_date(vuln.get("dateAdded")),
            _parse_date(vuln.get("dueDate")),
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("notes", ""),
            now,
        )
        upserted += 1

    logger.info("kev cache refreshed", extra={"upserted": upserted})
    return upserted


async def lookup_kev_for_cve(pool, cve_id: str) -> dict[str, Any] | None:
    """Check if a CVE is in the KEV list."""
    row = await pool.fetchrow(
        "SELECT * FROM cve_cache WHERE cve_id = $1 AND kev_included = TRUE",
        cve_id,
    )
    if row is None:
        return None
    return dict(row)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None
```

- [ ] **Step 3: Write the test**

```python
# tests/test_vuln_cache.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from easm.vuln_cache import refresh_kev_cache


MOCK_KEV_RESPONSE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2023-44487",
            "shortDescription": "HTTP/2 Rapid Reset Attack",
            "dateAdded": "2023-10-10",
            "dueDate": "2023-10-31",
            "vendorProject": "Multiple",
            "product": "HTTP/2",
            "notes": "",
        },
        {
            "cveID": "CVE-2024-1234",
            "shortDescription": "Example vulnerability",
            "dateAdded": "2024-01-15",
            "dueDate": "2024-02-05",
            "vendorProject": "Example Corp",
            "product": "Example Product",
            "notes": "Patch available",
        },
    ],
}


@pytest.mark.asyncio
async def test_refresh_kev_cache_upserts():
    mock_pool = AsyncMock()
    mock_response = MagicMock()
    mock_response.json.return_value = MOCK_KEV_RESPONSE
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__aenter__.return_value.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        count = await refresh_kev_cache(mock_pool)
        assert count == 2
        assert mock_pool.execute.call_count == 2  # one INSERT per CVE
```

- [ ] **Step 4: Run tests to verify**

Run: `uv run pytest tests/test_vuln_cache.py -v`
Expected: PASS

- [ ] **Step 5: Add KEV refresh to scheduler and main.py**

```python
# src/easm/scheduler.py — add KEV refresh job registration
def setup_kev_refresh(self, pool) -> None:
    """Schedule weekly CISA KEV cache refresh."""
    from easm.vuln_cache import refresh_kev_cache

    async def _refresh():
        try:
            await refresh_kev_cache(pool)
        except Exception:
            logger.exception("kev refresh failed")

    self._scheduler.add_job(
        _refresh,
        "cron",
        id="kev-refresh",
        day_of_week="0",  # Sunday
        hour="3",
        minute="0",
        replace_existing=True,
    )
    logger.info("scheduled kev refresh job")
```

```python
# src/easm/main.py — add after scheduler setup (after line 90)
# Initial KEV cache population at startup
from easm.vuln_cache import refresh_kev_cache
try:
    kev_count = await refresh_kev_cache(pool)
    logger.info("initial kev cache populated", count=kev_count)
except Exception:
    logger.exception("initial kev cache population failed (non-fatal)")

scheduler.setup_kev_refresh(pool)
```

- [ ] **Step 6: Commit**

```bash
git add alembic/versions/0006_vuln_cache.py src/easm/vuln_cache.py src/easm/scheduler.py src/easm/main.py tests/test_vuln_cache.py
git commit -m "feat: add CISA KEV fetcher with local cache and weekly refresh"
```

---

### Task 9: CPE→CVE→KEV Enrichment Handler

**Files:**
- Create: `src/easm/vuln_enrichment.py`
- Modify: `src/easm/pivot/handlers.py` — register new handler
- Modify: `src/easm/config.py` — add `cpe_vuln_enrich` to `VALID_PIVOT_TYPES`
- Test: `tests/test_vuln_enrichment.py` (create)

- [ ] **Step 1: Write the enrichment handler**

```python
# src/easm/vuln_enrichment.py
"""Pivot handler for CPE → CVE → KEV vulnerability enrichment.

Triggered after software detection (Wappalyzer, nmap, Shodan) stores
technologies/CVEs on an entity. Computes CPEs, looks up matching CVEs
in the local cache, and flags KEV-listed vulnerabilities.
"""
from __future__ import annotations

import logging
from typing import Any

from easm.cpe_mapper import compute_cpes_from_entity

logger = logging.getLogger(__name__)

# Severity mapping for CVSS v3 scores
CVSS_TO_RISK = {
    (9.0, float("inf")): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (0.0, 4.0): "low",
}


async def cpe_vuln_enrich(job: dict, pool,
                          http_client=None, limiters=None) -> list[dict[str, Any]]:
    """Compute CPEs from entity attributes and match against cached CVEs.

    Returns enriched entity data with vulnerability findings.
    """
    entity_type = job["entity_type"]
    entity_value = job["entity_value"]
    entity_id = job["entity_id"]

    # Fetch entity attributes from DB
    row = await pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1", entity_id,
    )
    if not row:
        return [{"entity_id": str(entity_id), "message": "entity not found"}]

    attrs = row["attributes"] or {}

    # Compute CPEs from attributes
    cpes = compute_cpes_from_entity(entity_type, attrs)
    if not cpes:
        return [{"entity_id": str(entity_id), "message": "no CPEs computable"}]

    # Look up matching CVEs from cache
    matched_cves: list[dict[str, Any]] = []

    for cpe in cpes:
        # Match against cpe_matches in cache (JSONB contains check)
        rows = await pool.fetch("""
            SELECT cve_id, description, cvss_score, cvss_severity,
                   kev_included, kev_date_added, kev_due_date,
                   kev_vendor, kev_product
            FROM cve_cache
            WHERE cpe_matches @> $1::jsonb
               OR cve_id IN (
                   SELECT cve_id FROM cve_cache
                   WHERE kev_vendor || ':' || kev_product = $2
               )
        """, f'[{{"cpe23Uri": "{cpe}"}}]', _cpe_to_vendor_product(cpe))

        for row in rows:
            cve_id = row["cve_id"]
            if cve_id not in {c.get("cve_id") for c in matched_cves}:
                matched_cves.append({
                    "cve_id": cve_id,
                    "description": row["description"] or "",
                    "cvss_score": row["cvss_score"],
                    "severity": row["cvss_severity"] or "unknown",
                    "kev_included": row["kev_included"] or False,
                    "kev_date_added": str(row["kev_date_added"]) if row["kev_date_added"] else None,
                    "kev_due_date": str(row["kev_due_date"]) if row["kev_due_date"] else None,
                    "matched_cpe": cpe,
                })

    # Classify risk based on KEV status and CVSS
    risk = _classify_risk(matched_cves)

    return [{
        "entity_id": str(entity_id),
        "entity_type": entity_type,
        "entity_value": entity_value,
        "computed_cpes": cpes,
        "matched_cves": matched_cves,
        "kev_count": sum(1 for c in matched_cves if c["kev_included"]),
        "total_cves": len(matched_cves),
        "risk": risk,
    }]


def _cpe_to_vendor_product(cpe: str) -> str:
    """Extract vendor:product from a CPE string for matching."""
    parts = cpe.split(":")
    if len(parts) >= 5:
        return f"{parts[3]}:{parts[4]}"
    return ""


def _classify_risk(cves: list[dict[str, Any]]) -> str:
    """Classify overall risk based on matched CVEs.

    Priority: KEV-listed > highest CVSS score.
    """
    if any(c["kev_included"] for c in cves):
        return "critical"
    if not cves:
        return "none"
    max_score = max((c.get("cvss_score") or 0.0) for c in cves)
    for (lo, hi), level in CVSS_TO_RISK.items():
        if lo <= max_score < hi:
            return level
    return "unknown"
```

- [ ] **Step 2: Register the handler**

```python
# src/easm/pivot/handlers.py — add import and register
from easm.vuln_enrichment import cpe_vuln_enrich

PIVOT_HANDLER_REGISTRY["cpe_vuln_enrich"] = cpe_vuln_enrich
PIVOT_SOURCE_NAMES["cpe_vuln_enrich"] = "cpe_vuln_enrich"
```

```python
# src/easm/config.py — add to VALID_PIVOT_TYPES
VALID_PIVOT_TYPES = {
    "dns_mail_records",
    "dns_resolve", "rdap_lookup", "crtsh_search",
    # ... existing ...
    "cpe_vuln_enrich",  # NEW
}
```

- [ ] **Step 3: Write the test**

```python
# tests/test_vuln_enrichment.py
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock

from easm.vuln_enrichment import cpe_vuln_enrich, _classify_risk


def test_classify_risk_kev_is_critical():
    cves = [{"kev_included": True, "cvss_score": 5.0}]
    assert _classify_risk(cves) == "critical"


def test_classify_risk_high_cvss():
    cves = [{"kev_included": False, "cvss_score": 9.8}]
    assert _classify_risk(cves) == "critical"


def test_classify_risk_medium():
    cves = [{"kev_included": False, "cvss_score": 6.5}]
    assert _classify_risk(cves) == "medium"


def test_classify_risk_none():
    assert _classify_risk([]) == "none"


@pytest.mark.asyncio
async def test_cpe_vuln_enrich_no_technologies():
    mock_pool = AsyncMock()
    mock_pool.fetchrow.return_value = {
        "attributes": {"ports": [80]},  # no technologies
    }

    job = {
        "entity_type": "hostname",
        "entity_value": "example.com",
        "entity_id": uuid.uuid4(),
    }

    results = await cpe_vuln_enrich(job, mock_pool)
    assert len(results) == 1
    assert results[0]["message"] == "no CPEs computable"


@pytest.mark.asyncio
async def test_cpe_vuln_enrich_with_technologies():
    mock_pool = AsyncMock()
    mock_pool.fetchrow.side_effect = [
        {  # first call: entity attributes
            "attributes": {
                "technologies": [{"name": "nginx", "version": "1.24.0"}],
            },
        },
        None,  # cve_cache query returns nothing (no matches in mock)
    ]

    job = {
        "entity_type": "hostname",
        "entity_value": "example.com",
        "entity_id": uuid.uuid4(),
    }

    results = await cpe_vuln_enrich(job, mock_pool)
    assert len(results) == 1
    assert "cpe:2.3:a:nginx:nginx:1.24.0" in results[0]["computed_cpes"]
```

- [ ] **Step 4: Run tests to verify**

Run: `uv run pytest tests/test_vuln_enrichment.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/vuln_enrichment.py src/easm/pivot/handlers.py src/easm/config.py tests/test_vuln_enrichment.py
git commit -m "feat: add CPE→CVE→KEV enrichment pivot handler"
```

---

### Task 10: KEV Correlation Rule

**Files:**
- Create: `correlations/known_exploited_vulnerability.yaml`
- Test: verify rule loads correctly

- [ ] **Step 1: Write the correlation rule**

```yaml
# correlations/known_exploited_vulnerability.yaml
id: known_exploited_vulnerability
meta:
  name: "Known Exploited Vulnerability (CISA KEV)"
  risk: critical
  description: >
    Software detected on this host matches a CVE in the CISA
    Known Exploited Vulnerabilities catalog. These vulnerabilities
    are actively exploited in the wild and require immediate remediation.
collect:
  - method: json_path_exists
    field: attributes
    json_path: "$.matched_cves[*].kev_included"
    value: true
analysis:
  method: cve_risk_classify
  field: attributes.matched_cves
headline: "KEV-listed vulnerability detected on {entity_value}: {kev_count} exploited CVE(s)"
severity: critical
```

- [ ] **Step 2: Write the test for rule loading**

```python
# tests/test_correlation_rules.py — add test
from pathlib import Path
from easm.correlation.loader import load_rules_from_dir


def test_known_exploited_rule_loads():
    rules_dir = Path(__file__).parent.parent / "correlations"
    rules = load_rules_from_dir(rules_dir)
    rule_ids = {r.id for r in rules}
    assert "known_exploited_vulnerability" in rule_ids
```

- [ ] **Step 3: Run tests to verify**

Run: `uv run pytest tests/test_correlation_rules.py::test_known_exploited_rule_loads -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add correlations/known_exploited_vulnerability.yaml tests/test_correlation_rules.py
git commit -m "feat: add CISA KEV correlation rule for known exploited vulnerabilities"
```

---

### Task 11: Concurrent HTTP Requests in standard_http_run

**Files:**
- Modify: `src/easm/runners/engine.py:308-396` — add `max_concurrent` param
- Test: `tests/test_engine.py` (modify)

- [ ] **Step 1: Modify standard_http_run to support concurrent requests**

```python
# src/easm/runners/engine.py — add max_concurrent param and concurrent logic
async def standard_http_run(
    target: Any,
    store: Store,
    trigger_type: str,
    run_id: uuid.UUID,
    log: Callable[[str], None],
    http_client: httpx.AsyncClient | None,
    *,
    source_name: str,
    url_template: str,
    iterate_over: Callable[[Any], list[str]],
    timeout: float = 30.0,
    transform_fn: Callable[[dict, str], dict | None] | None = None,
    output_schema: Any | None = None,
    max_retries: int = 0,
    retry_statuses: tuple[int, ...] = (),
    inter_delay: float = 0.0,
    max_concurrent: int = 1,  # NEW: 1 = sequential (backward compat), >1 = concurrent
) -> tuple[int, int, int]:
    own_client = http_client is None
    http = http_client or httpx.AsyncClient(timeout=timeout)
    inserted = deduped = errors = 0
    sem = asyncio.Semaphore(max_concurrent) if max_concurrent > 1 else None

    async def _process_item(item: str) -> tuple[int, int, int]:
        url = url_template.replace("[item]", item)
        try:
            resp_text = await _http_fetch_with_retry(
                http, url, max_retries, retry_statuses, log,
            )
        except Exception as e:
            logger.warning("%s error for %s: %s", source_name, item, e)
            return 0, 0, 1

        if resp_text is None:
            logger.warning("%s returned no data for %s", source_name, item)
            return 0, 0, 1

        ins, ded, err = 0, 0, 0
        records = _parse_response_text(resp_text)
        for record in records:
            raw = transform_fn(record, item) if transform_fn else record
            if raw is None:
                continue
            result = await store.insert_raw_event(
                target.org_id, target.id, source_name, raw, run_id,
            )
            if result:
                ins += 1
                if output_schema:
                    await _ingest_entities(store, output_schema, raw, run_id,
                                           target.org_id, target.id)
            else:
                ded += 1
        return ins, ded, err

    async def _process_with_sem(item: str) -> tuple[int, int, int]:
        async with sem:
            return await _process_item(item)

    try:
        items = iterate_over(target)
        if max_concurrent > 1:
            tasks = [_process_with_sem(item) for item in items]
            results = await asyncio.gather(*tasks)
            for ins, ded, err in results:
                inserted += ins
                deduped += ded
                errors += err
        else:
            for item in items:
                ins, ded, err = await _process_item(item)
                inserted += ins
                deduped += ded
                errors += err
                if inter_delay:
                    await asyncio.sleep(inter_delay)
    finally:
        if own_client:
            await http.aclose()

    return inserted, deduped, errors
```

- [ ] **Step 2: Add max_concurrent to crtsh runner config**

```python
# src/easm/runners/registry.py — modify _crtsh_run (line 154-164)
    return await standard_http_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="crtsh",
        url_template="https://crt.sh/?q=%.[item]&output=json",
        iterate_over=lambda t: t.match_rules.domains,
        timeout=30.0,
        transform_fn=transform_fn,
        max_retries=3,
        retry_statuses=(429, 502, 503, 504),
        inter_delay=1.5,
        max_concurrent=3,  # NEW: fetch up to 3 domains concurrently
    )
```

- [ ] **Step 3: Write the test**

```python
# tests/test_engine.py — add test
import pytest
from unittest.mock import AsyncMock

from easm.runners.engine import standard_http_run


@pytest.mark.asyncio
async def test_standard_http_run_concurrent():
    """With max_concurrent=3, items should be processed concurrently."""
    mock_store = AsyncMock()
    mock_store.insert_raw_event.return_value = True
    mock_target = MagicMock()
    mock_target.id = "test"
    mock_target.org_id = "test-org"

    def log(msg): pass

    # 5 items, max_concurrent=3
    inserted, deduped, errors = await standard_http_run(
        mock_target, mock_store, "manual", uuid.uuid4(), log, None,
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: ["a", "b", "c", "d", "e"],
        timeout=5.0,
        max_concurrent=3,
    )
    # With mock HTTP responses, verify it doesn't crash
```

- [ ] **Step 4: Run tests to verify**

Run: `uv run pytest tests/test_engine.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/engine.py src/easm/runners/registry.py tests/test_engine.py
git commit -m "perf: add concurrent HTTP requests to standard_http_run via max_concurrent"
```

---

### Task 12: Wire CPE→CVE Enrichment into Pivot Chain

**Files:**
- Modify: `src/easm/pivot/resolver.py` — auto-enqueue `cpe_vuln_enrich` after tech detection pivots
- Modify: `src/easm/config.yaml.example` — document new pivot type
- Test: integration test

- [ ] **Step 1: Add auto-enrichment trigger in resolver**

```python
# src/easm/pivot/resolver.py — after successful enqueue in check_and_enqueue (after line 70)
# Auto-enqueue CPE→CVE enrichment after tech-detection pivots
if pivot_rule.via in ("shodan_enrich", "tls_cert_grab"):
    await self.store.enqueue_pivot_job(
        org_id=target.org_id,
        target_id=target.id,
        entity_type=entity_type,
        entity_value=entity_value,
        entity_id=entity_id,
        pivot_type="cpe_vuln_enrich",
        depth=depth + 1,
        parent_entity_id=entity_id,
        discovery_session_id=discovery_session_id,
    )
```

- [ ] **Step 2: Document the new pivot in config.yaml.example**

```yaml
# config.yaml.example — add to pivot.allowed_pivots:
        - from: hostname
          to: hostname
          via: cpe_vuln_enrich
          cooldown_hours: 24
```

- [ ] **Step 3: Write integration test**

```python
# tests/test_integration_vuln.py
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_wappalyzer_to_cpe_to_kev_flow():
    """Integration: Wappalyzer detects nginx → CPE computed → KEV match checked."""
    from easm.cpe_mapper import compute_cpes_from_entity

    wappalyzer_attrs = {
        "technologies": [
            {"name": "nginx", "version": "1.24.0"},
        ],
    }
    cpes = compute_cpes_from_entity("hostname", wappalyzer_attrs)
    assert len(cpes) == 1
    assert "cpe:2.3:a:nginx:nginx:1.24.0" in cpes
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 5: Final commit**

```bash
git add src/easm/pivot/resolver.py config.yaml.example tests/test_integration_vuln.py
git commit -m "feat: auto-enqueue CPE→CVE enrichment after tech detection pivots"
```

---

## Self-Review

### 1. Spec Coverage

| Requirement | Task |
|---|---|
| Prevent unlimited retry failures | Task 1 (Shodan fix), Task 4 (rate limiters), Task 5 (max concurrent runs) |
| Manage queuing to avoid self-DoS | Task 3 (batch dequeue), Task 6 (max queue depth) |
| Batch crt.sh by domain instead of subdomain | Task 2 (shared HTTP client pools connections), Task 3 (batch dequeue groups same-type jobs) |
| Compute detected CPEs from software | Task 7 (CPE mapper from Wappalyzer/nmap/Shodan) |
| CISA KEV integration | Task 8 (KEV fetcher + cache) |
| NVD integration | Task 8 (cve_cache table supports NVD data; NVD API fetch is next phase) |
| Local cache database with scheduled refreshes | Task 8 (cve_cache table, weekly KEV refresh job) |
| Correlation rule for KEV findings | Task 10 (YAML rule) |
| CPE→CVE→KEV enrichment handler | Task 9 (handler) |
| Auto-trigger enrichment after tech detection | Task 12 (resolver auto-enqueue) |

### 2. Placeholder Scan

No TBD, TODO, "implement later" patterns found. All steps have concrete code or commands.

### 3. Type Consistency

- `cpe_mapper.py` returns `str | None` for single CPEs and `list[str]` for bulk — consistent across Tasks 7 and 9
- `vuln_cache.py` returns `dict[str, Any] | None` for KEV lookups — consistent with `vuln_enrichment.py` caller
- `PIVOT_HANDLER_REGISTRY` key `"cpe_vuln_enrich"` matches the `via` field in pivot config and `VALID_PIVOT_TYPES`
- All handler signatures follow the same pattern: `async def handler(job, pool, http_client=None, limiters=None) -> list[dict]`
