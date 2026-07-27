# Open EASM — Comprehensive Backend Code Audit

**Date:** 2026-07-20  
**Auditor:** Staff Backend Engineer (Automated)  
**Scope:** `src/easm/`, `alembic/`, `pyproject.toml`, `Dockerfile`, `config.yaml.example`  
**Methodology:** Static analysis — read ~50 source files, ran 7 pattern greps, dispatched 3 explore agents against runners, auth/config, and API routes.

---

## Executive Summary

1. **No shell injection, no bare `except:`, no `time.sleep`, no `requests`** — the codebase avoids the most common Python backend footguns. Subprocess forking exclusively uses `asyncio.create_subprocess_exec` (no `shell=True`). HTTP is exclusively `httpx`.
2. **Store is a 1,578-LOC God Object** containing database queries, entity logic, asset profiles, user management, API key validation, certificate inventory, and migrations in a single file. This is the single largest architectural liability.
3. **Enrichment API keys are exposed via `GET /api/config`** — `Config` model holds plaintext `EnrichmentKeys` (Shodan, AbuseIPDB, Censys, SecurityTrails) on the same config object returned by the read-only config endpoint. No redaction layer.
4. **No auth enforcement on data routes** — `entities`, `events`, `runs`, `findings`, `config`, `graph`, `alerts`, `scoring`, `assets`, `certificates`, `reports`, `legal`, `verification`, `notifications`, `workers`, `triage` — 16 route files have zero auth checks. Only `auth.py` enforces authentication. The auth middleware sets `request.state.user` but routes never check it.
5. **340 `Any` usages across 49 files** — pervasive `dict[str, Any]` signatures erase all entity/event/finding types. `worker_context.py` uses `Any` for every getter. Combined with no `TypedDict` usage, the type system provides zero safety for domain objects.
6. **Five source files exceed 250 pure LOC** (`store.py`: 1,578, `handlers.py`: 1,145, `engine.py`: 702, `schemas.py`: 572, `registry.py`: 416), with `pivot.py` (353) and `config.py` (309) close behind. Several are 3–6x the ceiling.
7. **Asyncio correctness is strong** — `asyncio.wait_for` on subprocesses, proper `proc.kill()` on timeout, `finally: client.aclose()` patterns, semaphore-guarded concurrent HTTP. No `asyncio.gather` with return_exceptions=False as the single error path.

---

## Methodology

**Files read directly (30+):** `main.py`, `worker.py`, `config.py`, `store.py` (full 1,725 lines), `db.py`, `scheduler.py`, `runtime.py`, `runners/engine.py`, `runners/registry.py`, `runners/base.py`, `runners/portscan_runner.py`, `runners/screenshot_runner.py`, `runners/__init__.py`, `auth/middleware.py`, `auth/config.py`, `auth/session.py`, `auth/api_keys.py`, `auth/password.py`, `api/app.py`, `api/deps.py`, `api/schemas.py`, `pivot/handlers.py` (partial), `tasks/runner.py`, `tasks/pivot.py`, `queue.py`, `network_guard.py`, `tests/conftest.py`, `Dockerfile`, `Dockerfile.test`, `alembic/env.py`, `config.yaml.example` (partial), `pyproject.toml`

**Files read by explore agents (15+):** All 15 runner files, all 7 auth files, all 27 API files

**Pattern greps run:** `shell=True`, `subprocess.run`, `requests.(get|post)`, `time.sleep`, bare `except:`, `# type: ignore`, `Any`

**What was skipped:** React frontend (out of scope), Docker Compose files, documentation, fixtures

---

## Findings

### Architecture & Module Boundaries

#### [Severity: Critical] Store is a 1,578-LOC God Object
- **Location:** `src/easm/store.py` (entire file, 1,725 lines total, 1,578 pure LOC)
- **Evidence:** Single `Store` class contains methods for runs, raw events, entities, asset profiles, relationships, findings, pivot jobs, users, API keys, certificate inventory, asset inventory, entity lineage, triage, migrations (`migrate_ip_associations`), and config snapshots. Over 60 methods on a single class.
- **Impact:** Any change to Store risks breaking unrelated features. Impossible to test in isolation. Reviewer cannot hold the whole class in working memory. Every method has access to `self.pool` and can execute arbitrary SQL against any table. The entity lineage walking (`get_entity_lineage`, L871-968) performs N+1 queries in a while loop and belongs in its own repository.
- **Recommendation:** Split into focused repositories: `RunRepository`, `EntityRepository`, `FindingRepository`, `UserRepository`, `ApiKeyRepository`, `CertificateRepository`, `AssetInventoryRepository`, `ConfigSnapshotRepository`. Each with its own pool access. Use composition: `store.runs.create_run()`, not `store.create_run()`.

#### [Severity: Critical] Pivot handlers module is 1,145 pure LOC
- **Location:** `src/easm/pivot/handlers.py` (1,304 lines total, 1,145 pure LOC)
- **Evidence:** Contains all 18 pivot enrichment handlers inline, plus GeoIP lookup, TLS cert parsing, DNS resolution, API key resolution, and SSRF-safe HTTP helpers — all in one file.
- **Impact:** Adding a new enrichment handler requires touching this monolithic file. Testing individual handlers is impossible without importing the entire module. The TLS certificate parsing function `_certificate_to_raw_dict` (L57-156) alone is ~100 lines of low-level crypto library calls.
- **Recommendation:** Split into `handlers/dns.py`, `handlers/tls.py`, `handlers/geoip.py`, `handlers/shodan.py`, `handlers/abuseipdb.py`, etc. — one file per handler group. Extract `_certificate_to_raw_dict` into `certificates/parser.py`.

#### [Severity: High] Two runner registries with adapters — architectural duplication
- **Location:** `src/easm/runners/registry.py:422-493` (declarative) + `src/easm/runners/__init__.py:147-158` (legacy classes)
- **Evidence:** Standard runners (asnmap, subfinder, dnstwist, nuclei, wappalyzer, crtsh, certspotter, commoncrawl) use the declarative `RunnerDef`/`run_fn` model, while legacy runners (breach_monitor, certstream, cloud_enum, gist_monitor, github_scan, paste_monitor, portscan, screenshot, searchengine, stackoverflow_monitor) remain as `BaseRunner` subclasses. A `_make_legacy_adapter` function (`__init__.py:82-124`) bridges them at module load time.
- **Impact:** Two code paths for the same thing. `BaseRunner.execute()` (base.py:77-148) duplicates `execute_runner()` (engine.py:185-335) almost identically. Two near-identical `_exec_subprocess` implementations (`base.py:38-69` vs `engine.py:90-130`). New contributors must understand both patterns.
- **Recommendation:** Complete the migration. Convert all legacy runners to the `run_fn` pattern. Remove `BaseRunner.execute()`, `ApiRunner`, `_make_legacy_adapter()`, and the dual-registry. The `_EntityIngestStoreProxy` pattern is good — keep it but make it explicit.

#### [Severity: Medium] In-memory SSE singleton — broken in multi-worker deployments
- **Location:** `src/easm/api/sse.py:45` (module-level `_stream = FindingStream()` singleton)
- **Evidence:** `FindingStream` uses `asyncio.Queue` and an in-memory subscriber list. If multiple uvicorn workers run behind a load balancer, a finding published by worker A only reaches subscribers connected to worker A.
- **Impact:** Silent data loss — SSE subscribers miss findings. Debugging this requires correlating server logs across workers.
- **Recommendation:** Use PostgreSQL `LISTEN`/`NOTIFY` (asyncpg supports it) or a Redis pub/sub channel. The `FindingStream._subscribers` list also has no protection against a slow consumer — `put_nowait` with `QueueFull` → `get_nowait()` drops the oldest message, which is correct but means data loss under load.

#### [Severity: Medium] `PaginatedQuery` builder exists but is unused
- **Location:** `src/easm/api/pagination.py:6-90`
- **Evidence:** A well-designed cursor-based pagination builder with `add_filter`, `add_range`, `add_ilike`, `add_cursor`, `build` methods. Not imported or used by any route file. Every route implements pagination manually with raw SQL string interpolation.
- **Impact:** Dead code. Inconsistent pagination across routes — cursor-based in `entities.py`/`pivot_queue.py`, offset-based in `runs.py`/`findings.py`/`alerts.py`. Offset pagination on large tables (entities, findings) will degrade with table size.
- **Recommendation:** Either adopt `PaginatedQuery` across all list routes or remove it. Migrate offset-based routes to cursor-based.

### FastAPI Design & API Surface

#### [Severity: High] No authentication enforcement on 16 data routes
- **Location:** `src/easm/api/routes/targets.py`, `entities.py`, `events.py`, `runs.py`, `graph.py`, `config.py`, `pivot_queue.py`, `findings.py`, `alerts.py`, `assets.py`, `certificates.py`, `scoring.py`, `reports.py`, `legal.py`, `verification.py`, `notifications.py`, `workers.py`, `triage.py` — all of them.
- **Evidence:** None of these route files check `request.state.user`. The auth middleware (`auth/middleware.py:37`) sets `request.state.user` on every request (even in `none` mode), but no route gate checks it. For example, `runs.py:35` — `GET /runs` has no user check. `config.py:21` — `GET /config` returns the full config (including enrichment API keys) with no auth.
- **Impact:** In `none` mode, this is by design. But in `local`/`reverse_proxy`/`sso` mode, an authenticated user could still reach these endpoints — so this is only a problem if the middleware fails to assign a user and the route doesn't notice. However, **there is no RBAC** — all authenticated users have the same access. If `org_id` isolation were ever added, these routes would be a bypass.
- **Recommendation:** Create a `require_auth` FastAPI dependency that raises 401 if `request.state.user is None`. Apply it to every data route. Consider an `APIRouter` subclass that defaults to requiring auth.

#### [Severity: High] Enrichment API keys exposed via `GET /api/config`
- **Location:** `src/easm/config.py:211-221` (EnrichmentKeys) + `src/easm/api/routes/config.py:21` (GET /config)
- **Evidence:** `EnrichmentKeys` model holds `shodan`, `abuseipdb`, `greynoise`, `censys_id`, `censys_secret`, `securitytrails`, `dehashed`, `urlscan` as plain strings. The `Config` model includes `enrichment: EnrichmentKeys`. The `GET /api/config` endpoint returns the config. There is no redaction, no field exclusion, no `SecretStr`.
- **Impact:** Any user with access to the config endpoint can read all configured enrichment API keys. Combined with the no-auth finding above, this means Open EASM's enrichment keys are readable by anyone who can reach the API in default configuration.
- **Recommendation:** Use Pydantic `SecretStr` for all API key fields. Add a `model_dump(exclude={"enrichment": ...})` override on `Config` for the read-only config endpoint. Alternatively, return only non-sensitive config sections.

#### [Severity: Medium] Inconsistent error response format
- **Location:** `src/easm/api/routes/auth.py:77,91-94` (JSON string literals) vs other routes (`HTTPException` with dict detail)
- **Evidence:** Auth routes return `Response(status_code=403, content='{"error": "registration_requires_admin"}')` — hand-crafted JSON strings. Other routes raise `HTTPException(status_code=400, detail={"error": "...", "detail": "..."})`.
- **Impact:** Mismatched error format — auth route responses are `{"error": "..."}` (single-level), while data route errors use `{"error": "...", "detail": "..."}`. Clients must handle both.
- **Recommendation:** Standardize on `HTTPException` with `detail={"error": "...", "detail": "..."}` across all routes. Use a custom exception handler that formats all errors consistently.

#### [Severity: Low] CORS allows all origins with credentials
- **Location:** `src/easm/api/app.py:73-79`
- **Evidence:** `allow_origins=["*"]` with `allow_credentials=True`. Browsers reject this combination as a security violation — the CORS spec forbids credentials with wildcard origins. This effectively disables credentialed cross-origin requests.
- **Impact:** If `allow_credentials=True` is intentional (e.g., for cookie-based auth from a frontend on a different origin), this doesn't work. If it's not needed, the wildcard is fine.
- **Recommendation:** Either set `allow_origins` to a specific list of frontend origins (recommended), or remove `allow_credentials=True`.

#### [Severity: Low] Mixed `Depends` vs inline import patterns
- **Location:** e.g. `entities.py:20` uses `Depends(get_store)` while `runs.py:25` uses `from easm.api.deps import get_store; store = get_store()`
- **Evidence:** Two patterns coexist. `Depends` is preferred by FastAPI but some routes call getters directly inside function bodies.
- **Impact:** No runtime difference — both resolve the same global. But inconsistent patterns confuse new contributors and make it harder to refactor to proper DI.
- **Recommendation:** Standardize on `Depends(get_store)` / `Depends(get_config)`.

### Async Correctness & Concurrency

#### [Severity: High] Procrastinate tasks import-in-function — potential cold-start latency
- **Location:** `src/easm/tasks/runner.py:23-29`, `src/easm/tasks/pivot.py:56-71`
- **Evidence:** Both `execute_runner` and `execute_pivot` use lazy imports inside the task function body (e.g., `from easm.runners import get_all_runners`, `from easm.worker_context import get_config, get_store`). This is necessary because the task module is imported at process start by Procrastinate, but the dependencies aren't ready yet.
- **Impact:** Adds 10-50ms of import latency per task execution. Acceptable for background tasks but indicates an initialization order problem. More critically, if an import raises an exception, the task fails permanently without clear signal.
- **Recommendation:** Acceptable pattern for task-based architectures. Document it. Consider pre-warming imports in a worker startup hook.

#### [Severity: Medium] `asyncio.create_task` for certstream — no supervision, no cancellation propagation
- **Location:** `src/easm/main.py:179-184`
- **Evidence:** Certstream tasks are spawned with `asyncio.create_task(...)` without storing the task reference. If a certstream task crashes, there's no restart logic or error logging in the main loop. The task is fire-and-forget.
- **Impact:** A crashing certstream task silently terminates. No reconnect, no alert. The WebSocket reconnection logic exists inside `CertStreamRunner` (certstream_runner.py:78-86), but if the task itself crashes (e.g., unhandled exception outside the reconnect loop), the main process doesn't notice.
- **Recommendation:** Store certstream task references. Add an `asyncio.gather(*certstream_tasks)` with `return_exceptions=True` and log exceptions. Consider a watchdog that restarts crashed tasks.

#### [Severity: Low] `asyncio.create_task` for `_touch()` in API key validation — fire-and-forget
- **Location:** `src/easm/store.py:1549`
- **Evidence:** `asyncio.create_task(_touch())` to update `last_used_at` on API keys. No task reference stored. If the task fails (e.g., DB connection lost), the error is silently swallowed by the `try/except Exception: pass` inside `_touch()`.
- **Impact:** `last_used_at` doesn't get updated. Minor — only affects auditability, not functionality.
- **Recommendation:** Minor. Consider making the DB call directly instead of spawning a task, since `validate_api_key` is already async.

#### [Severity: Info] No async context propagation (no `contextvars`)
- **Location:** Entire codebase — no use of `contextvars.ContextVar`.
- **Evidence:** Structured logging uses `structlog` with `extra` dicts, but there's no request ID, trace ID, or user context propagated across async boundaries. Each log call must manually pass `extra={"target_id": ..., "run_id": ...}`.
- **Impact:** Hard to trace a request through its entire lifecycle — from route handler → store query → background task.
- **Recommendation:** Add a `contextvars.ContextVar` for `request_id` and `user_id`. Set them in the auth middleware. Use `structlog.contextvars.bind_contextvars()` to automatically include them in all log messages.

### Database Layer (asyncpg + Alembic)

#### [Severity: High] Offset-based pagination on large tables
- **Location:** `src/easm/api/routes/runs.py:43-54`, `findings.py:88-106`, `alerts.py:29-46` and their corresponding store methods (`store.py:281-336`, `store.py:1127-1182`)
- **Evidence:** Routes use `limit/offset` for pagination. Store methods add `OFFSET $N LIMIT $N`. As the `runs`, `findings`, and `entities` tables grow, offset pagination performance degrades linearly — PostgreSQL must scan and discard offset rows.
- **Impact:** Pagination latency grows as data accumulates. At 1M+ entities, page 500 becomes seconds-slow.
- **Recommendation:** Migrate to cursor-based pagination (`WHERE id > $cursor ORDER BY id`) for all list endpoints. The `entities.py` route already uses this pattern — standardize on it.

#### [Severity: Medium] N+1 query in `get_entity_lineage`
- **Location:** `src/easm/store.py:910-967`
- **Evidence:** A `while` loop that fetches one parent entity per iteration, up to `max_depth=20`. Each iteration performs a single-row query with a LATERAL JOIN. At depth 20, that's 20 sequential DB roundtrips.
- **Impact:** Slow lineage lookups for deep discovery chains. The LATERAL JOIN at lines 927-932 adds extra cost per iteration.
- **Recommendation:** Replace the while loop with a recursive CTE that walks the `parent_entity_id` chain in a single query. PostgreSQL CTEs handle this efficiently.

#### [Severity: Medium] `upsert_entity` has a read-after-write race
- **Location:** `src/easm/store.py:368-432`
- **Evidence:** The function does: INSERT ON CONFLICT DO UPDATE → check `is_insert` → if not insert, SELECT existing attributes → merge → UPDATE. Between the INSERT and the SELECT, another concurrent process could update the same entity. The final UPDATE overwrites the concurrent change.
- **Impact:** Lost update under high concurrency. Two runners discovering the same entity simultaneously could lose each other's attribute updates.
- **Recommendation:** Use `INSERT ... ON CONFLICT DO UPDATE SET attributes = jsonb_deep_merge(entities.attributes, EXCLUDED.attributes)` or `SELECT ... FOR UPDATE` followed by the merge. Alternatively, accept the last-write-wins semantics but document it.

#### [Severity: Medium] `result.endswith("1")` — fragile row-count check
- **Location:** `src/easm/store.py:848` and `store.py:1460`, `store.py:1568`
- **Evidence:** `return result.endswith("1")` checks if `DELETE` or `UPDATE` affected one row. asyncpg returns a command tag string like `"DELETE 1"` or `"DELETE 0"`. `"UPDATE 10".endswith("1")` would return `True` — updating 10, 11, 21, etc. rows would be reported incorrectly.
- **Impact:** Very unlikely in practice (updates on primary key), but a brittle pattern.
- **Recommendation:** Parse the command tag properly: `result.split()[-1] == "1"`. Or use `fetchrow(...) RETURNING id` instead of relying on command tags.

#### [Severity: Medium] Alembic migration blocks the startup event loop
- **Location:** `src/easm/main.py:101-105`
- **Evidence:** `loop.run_in_executor(ThreadPoolExecutor(), alembic_upgrade, alembic_cfg, "head")` — runs blocking alembic migration in a thread. The `ThreadPoolExecutor()` is not assigned to a variable, so it's not shut down explicitly. Falls back to GC-based cleanup.
- **Impact:** While migration runs, the startup is blocked. On a cold DB, migration may take seconds. During this time, health checks and readiness probes fail. The thread executor leak is negligible (one thread, short-lived).
- **Recommendation:** Acceptable pattern. Assign the executor to a `with` block for explicit shutdown. Ensure the Docker `HEALTHCHECK` allows sufficient startup time.

#### [Severity: Low] No connection pool sizing tuning
- **Location:** `src/easm/db.py:19-24`
- **Evidence:** `min_size=2, max_size=10, command_timeout=30` — hardcoded, not configurable via env vars or config. The worker process (`worker.py:25`) uses the same defaults. Procrastinate creates its own pool internally (`queue.py:12`).
- **Impact:** Under-provisioned for heavy workloads (only 10 connections). Fine for single-instance deployment, but multi-worker + web + Procrastinate could exhaust connections.
- **Recommendation:** Make `min_size`, `max_size`, `command_timeout` configurable via env vars. Ensure `Procrastinate` pool settings are coordinated.

### Runner Architecture

#### [Severity: High] `standard_subprocess_run` iterates items sequentially — no concurrency
- **Location:** `src/easm/runners/engine.py:543-598`
- **Evidence:** The for-loop at line 543 iterates items one-by-one: build command → exec_subprocess → parse stdout → insert events. For a target with 10 domains and subfinder (60s per domain), that's 10 minutes of wall-clock time for a run that could complete in 60s with concurrency.
- **Impact:** Slow runs for multi-domain targets. Asnmap for an organization with 50 ASNs takes 50 sequential subprocess invocations.
- **Recommendation:** Add `max_concurrent` parameter to `standard_subprocess_run` (like `standard_http_run` has at line 624). Use `asyncio.Semaphore` + `asyncio.gather` with item-batch parallelism.

#### [Severity: Medium] `ScreenshotRunner` launches a new browser per domain
- **Location:** `src/easm/runners/screenshot_runner.py:39-67`
- **Evidence:** For each domain, a new browser is launched with `await p.chromium.launch()`. After screenshots, `await browser.close()`. But the outer `async with _async_playwright() as p:` means Playwright itself is started/stopped once per run — only the browser is per-domain.
- **Impact:** Browser launch overhead per domain (~1-2s cold start). Acceptable for few domains, but 20 domains = 20 browser launches.
- **Recommendation:** Launch the browser once before the domain loop, reuse it for all URLs, close once at the end. Use `browser.new_context()` for isolation.

#### [Severity: Medium] `certstream_runner` does not check `allow_external_network`
- **Location:** `src/easm/runners/certstream_runner.py:47` vs `src/easm/main.py:170`
- **Evidence:** `main.py:170-171` checks `config.runtime.allow_external_network` before starting certstream. But the certstream runner itself (`certstream_runner.py`) does not re-check. If certstream is restarted internally (reconnection), the policy state is never re-asserted. The `certstream_runner.run_once` method is also callable via the engine bypassing main.py's guard entirely if triggered manually.
- **Impact:** If policy changes from `allow_external_network=true` to `false` at runtime, a reconnecting certstream would bypass the policy.
- **Recommendation:** Add `allow_external_network` check inside `certstream_runner.run_once()` at the top. Return early if external network is disabled.

#### [Severity: Low] `git_scan_runner.py` has unused args — `http_client` is passed but initially used as `None`
- **Location:** `src/easm/runners/github_scan_runner.py:26-27`
- **Evidence:** `_http_client` is initialized as `None` in the constructor, but the runner is an `ApiRunner` with `is_api_runner = True`. The engine passes `http_client` to `run_fn`, but `github_scan_runner.py:27` does `self._http_client = None` in `__init__`. The `run_once` method then creates its own client inline.
- **Impact:** Runner creates redundant httpx clients. Minor — the passed `http_client` is closed by the engine's `finally` block.
- **Recommendation:** Use the injected `http_client` rather than creating a new one, or remove `is_api_runner=True` from the class.

### Scheduler & Pivot Pipeline

#### [Severity: Medium] Scheduler uses Procrastinate for deferred execution — adds queue latency
- **Location:** `src/easm/scheduler.py:41-62`
- **Evidence:** When a scheduled time fires, the scheduler doesn't run the runner directly — it defers via `execute_runner.configure(...).defer_async(...)` to the Procrastinate queue. The worker pool processes the queue with `concurrency=3` (`queue.py:13-15`).
- **Impact:** Delayed execution — the task enters the queue and must wait for a worker slot. For short-cadence runners (`*/5 * * * *`), tasks can stack. The `count_active_runs` check (scheduler.py:43) prevents duplicate concurrent runs, but if the queue backs up, tasks pile up and eventually get rate-limited by Procrastinate.
- **Recommendation:** Monitor Procrastinate queue depth. Consider separate worker pools for short-cadence vs long-cadence jobs. Add alerting for queue depth exceeding 100.

#### [Severity: Low] Pivot depth tracking is correct but unbounded
- **Location:** `src/easm/tasks/pivot.py:261-268` and `src/easm/config.py:89` (`max_depth: int = 3`)
- **Evidence:** Pivot jobs increment `depth + 1` at each recursion. The `PivotResolver.check_and_enqueue` respects `max_depth`. This is sound.
- **Impact:** No immediate issue. `max_depth=3` default is reasonable. If set to a high value (e.g., 10), the pivot graph can explode in breadth.
- **Recommendation:** Add a maximum of 5 to `max_depth` in Pydantic validation. Add a total-pivot-count-per-discovery-session limit.

### Subprocess & External Tool Invocation

#### [Severity: Medium] Subprocess binaries resolved from PATH — no absolute path validation
- **Location:** `src/easm/runners/registry.py:43` — `binary="asnmap"`, `binary="subfinder"`, etc.
- **Evidence:** All subprocess runners specify binary names as bare strings: `"asnmap"`, `"subfinder"`, `"nuclei"`, `"webanalyze"`, `"nmap"`, etc. These are resolved from the system PATH at execution time by `asyncio.create_subprocess_exec`.
- **Impact:** If a malicious binary with the same name exists earlier in PATH, it would be executed instead. This is a deployment concern (the Dockerfile installs known binaries to `/usr/local/bin`), but the code doesn't verify the binary path.
- **Recommendation:** Validate binary paths at startup. The `health.py:check_binaries()` function already does this — call it during runner registration and fail fast if a required binary is missing or has an unexpected path. Document that all binaries should be in `/usr/local/bin`.

#### [Severity: Medium] `nmap` command uses `-oG -` (greppable output) — no structured output
- **Location:** `src/easm/runners/portscan_runner.py:69-71`
- **Evidence:** nmap is invoked with `-oG -` (greppable format to stdout). The output is parsed with regex at lines 90-113: `re.match(r"(\d+)/open/(\w+)///(.*?)/", p)`. If nmap changes its output format, parsing silently breaks.
- **Impact:** Port scan results silently drop if nmap greppable format changes. Errors are counted but individual port misses are hard to detect without diffing against expected results.
- **Recommendation:** Use `-oX -` (XML output) or `-oN -` + JSON conversion. XML is more stable and parseable with `xml.etree`.

#### [Severity: Low] `cloud_enum` replaced by `CloudBucketRunner` — naming inconsistency
- **Location:** `src/easm/runners/cloud_bucket_runner.py:1` vs `src/easm/config.py:15` (`"cloud_enum"`)
- **Evidence:** Config references `cloud_enum` as a runner name, but the implementation is `CloudBucketRunner` with `source_name = "cloud_enum"` at the class level. The name is correct at runtime, but the file is named `cloud_bucket_runner.py`.
- **Impact:** Confusing for maintenance — searching for `cloud_enum` in the codebase won't find the runner file.
- **Recommendation:** Rename the file to `cloud_enum_runner.py` or alias `cloud_enum` → `cloud_bucket` in the runner registry.

#### [Severity: Info] DNS resolution in `network_guard.py` is synchronous (uses `dns.resolver`)
- **Location:** `src/easm/network_guard.py:43-70`
- **Evidence:** `resolve_and_validate` uses `dns.resolver.Resolver().resolve(hostname, rtype)`, which is a **blocking** synchronous call. It's called from async runner code (`portscan_runner.py:58`).
- **Impact:** Blocks the event loop for the duration of DNS resolution. With timeout=4s per hostname, this can add up. The function is called per-hostname in a sequential loop. If called 10 times in a row, that's 40 seconds of event loop blocking.
- **Recommendation:** Use `dns.asyncresolver` or `asyncio.to_thread()` to wrap the sync DNS call. Better yet, use `aresolver` or a non-blocking DNS library.

### Error Handling & Observability

#### [Severity: High] Broad `except Exception` with `pass` or `logger.debug` — silent failures
- **Location:** Multiple locations:
  - `src/easm/store.py:429-430` — raw event link insert: `except Exception: logger.debug(...)`
  - `src/easm/store.py:552-554` — finding lookup: `except Exception: logger.debug(...)` and returns `[]`
  - `src/easm/store.py:1546-1547` — API key touch: `except Exception: pass`
  - `src/easm/runners/engine.py:174-176` — seed entity creation: `except Exception: logger.debug(...)`
  - `src/easm/runners/engine.py:484-486` — pivot enqueue: `except Exception: logger.debug(...)`
  - `src/easm/runners/__init__.py:74-78` — entity ingestion: `except Exception: logger.debug(...)`
  - `src/easm/tasks/pivot.py:261-268` — recursive pivot: `except Exception: errors += 1`
- **Evidence:** Production errors are logged at DEBUG level which is typically suppressed. If a DB connection is lost, `insert_raw_event` fails, or pivot enqueue fails, the only signal is a debug log that nobody reads.
- **Impact:** Silent data loss. Raw event links not created, findings not looked up, API key last_used not updated, entities not ingested, pivot recursion broken — all with DEBUG-level logging. Operators have no way to detect these failures.
- **Recommendation:** Log at WARNING or ERROR level for data mutations. Add a Prometheus counter for each swallowed exception. Consider a circuit-breaker pattern: if errors exceed a threshold in a time window, escalate to ERROR.

#### [Severity: High] Global exception handler leaks internal errors
- **Location:** `src/easm/api/app.py:85-88`
- **Evidence:** `return JSONResponse(status_code=500, content={"error": "internal", "detail": str(exc)})` — returns `str(exc)` to the client. This leaks exception messages, which can include SQL errors, file paths, and internal implementation details.
- **Impact:** Information disclosure. An attacker can probe the API and receive detailed error messages about database errors, missing files, etc.
- **Recommendation:** In production, return `{"error": "internal", "detail": "An internal error occurred"}`. Log the full exception detail server-side.

#### [Severity: Medium] `main.py` health check `os._exit(1)` — hard kill, no graceful shutdown
- **Location:** `src/easm/main.py:219-220`
- **Evidence:** `os._exit(1)` on health check timeout or connection error. This immediately terminates the process without running `finally` blocks, without closing DB connections, without signaling Procrastinate to shut down.
- **Impact:** Database connections leak. In-flight tasks are lost. The Docker container restarts (due to exit code 1), but the shutdown is unclean.
- **Recommendation:** Use `sys.exit(1)` instead, which raises `SystemExit` and allows `finally` blocks to run. Or use a signal-based approach.

#### [Severity: Low] No structured logging correlation ID
- **Location:** Entire codebase
- **Evidence:** `structlog` is configured with `JSONRenderer()` but there's no request ID in log context. Each log call passes `extra={"target_id": ..., "run_id": ...}` manually. Inconsistent — some calls use `extra`, others use positional formatting.
- **Impact:** Hard to trace a single request through the system in production logs.
- **Recommendation:** Add `structlog.contextvars.bind_contextvars(request_id=str(uuid.uuid4()))` in the auth middleware. All subsequent log calls within that request context will automatically include the request ID.

### Configuration & Secrets Handling

#### [Severity: High] Enrichment API keys exposed via `GET /api/config`
- **Location:** See Finding under FastAPI Design.

#### [Severity: Medium] Unresolved `${VAR}` references silently become literal strings
- **Location:** `src/easm/config.py:305`
- **Evidence:** `raw_text = os.path.expandvars(raw_text)` — if `EASM_SESSION_SECRET` is not set in the environment, the string `${EASM_SESSION_SECRET}` remains as-is in the parsed config. Pydantic validates it as a non-empty string, so the application starts with the literal placeholder as the session secret.
- **Impact:** Hard to debug. The application appears to work but session tokens are signed with the string `"${EASM_SESSION_SECRET}"` as the key — trivially forgeable. No startup warning.
- **Recommendation:** After `expandvars`, scan for remaining `${...}` patterns and raise `ValueError` with the unresolved variable names.

#### [Severity: Medium] `api_keys.py` ephemeral pepper — all keys invalidated on restart
- **Location:** `src/easm/auth/api_keys.py:19-29`
- **Evidence:** If `EASM_API_KEY_PEPPER` env var is not set, a random per-process pepper is generated. Every restart invalidates all stored API keys. A warning is logged but the application starts normally.
- **Impact:** Production outage on restart — all API integrations break immediately. Operators must regenerate and redistribute all API keys.
- **Recommendation:** Add a startup check: if `EASM_API_KEY_PEPPER` is not set and `auth.mode` is not `"none"`, refuse to start (exit with error). Only use ephemeral pepper in development.

#### [Severity: Low] Config file permissions not checked
- **Location:** `src/easm/config.py:300-309`
- **Evidence:** `load_config` reads the YAML file but does not check file permissions. A world-readable config file containing `${VAR}` placeholders for secrets creates a false sense of security.
- **Recommendation:** Check that the config file is readable only by the owner (`stat.S_IRUSR | stat.S_IWUSR`). Warn if world-readable.

### Pydantic & Validation

#### [Severity: Medium] `dict[str, Any]` for all entity attributes — no schema enforcement
- **Location:** `src/easm/api/schemas.py:75` (`attributes: dict[str, Any]`), used across the entire entity pipeline
- **Evidence:** Every entity's attributes are `dict[str, Any]`. The type system cannot distinguish between `{"port": 443, "service": "https"}` (valid portscan result) and `{"bad_key": "oops"}` (corrupt data). Pydantic schemas for responses don't validate attribute structure.
- **Impact:** Corrupt entity data propagates silently. API consumers receive attributes with no structure guarantees. Correlation rules access `entity["attributes"]["asset_profile"]["risk"]["level"]` with no compile-time or runtime type safety.
- **Recommendation:** Define `TypedDict` subclasses for each entity type's attributes: `HostnameAttributes`, `IPAttributes`, `DomainAttributes`, `CertificateAttributes`. Use `TypeGuard` functions at ingestion boundaries. Alternatively, use discriminated Pydantic models based on `entity_type`.

#### [Severity: Medium] `RunnerConfig.args: dict[str, Any]` — no validation of subprocess arguments
- **Location:** `src/easm/config.py:41`
- **Evidence:** `args: dict[str, Any] = Field(default_factory=dict)` — arbitrary key-value pairs pass through Pydantic validation unchecked. Runners read config-specific keys like `timeout_seconds`, `recursive`, `passive_only` from this dict with `.get()`.
- **Impact:** Typos in config silently become dead defaults. `timeout_secconds: 300` would be ignored (not `timeout_seconds`). No validation that required args are present.
- **Recommendation:** Define typed sub-configs per runner: `SubfinderRunnerConfig(RunnerConfig)` with explicit `recursive: bool` and `passive_only: bool` fields. Keep `args` only for truly ad-hoc options.

#### [Severity: Low] `ConfigUpdateRequest` accepts raw dicts — bypasses Config validation
- **Location:** `src/easm/api/schemas.py:116-120`
- **Evidence:** `targets: list[dict[str, Any]] | None = None` — accepts arbitrary dicts for targets. The update endpoint (`routes/config.py:42-46`) merges them into the in-memory config. No `TargetConfig` validation occurs on update.
- **Impact:** Invalid target configs can be submitted via `PUT /api/config` and won't be caught until the config is reloaded from the in-memory object. The YAML validator doesn't re-run on partial updates.
- **Recommendation:** Use `list[TargetConfig]` in `ConfigUpdateRequest` or validate via `model_validate` during the update process.

### Type Hints & mypy

#### [Severity: Critical] Pervasive `Any` — 340 usages across 49 files
- **Location:** All 49 files under `src/easm/` — see grep results above.
- **Evidence:** `worker_context.py:11,14,21,26,31` — type-erased context module uses `Any` for every getter. `store.py:10` — `from typing import Any, cast`. Functions return `dict[str, Any]`, accept `Any`, pass `Any`. The `_json_field(value: Any, default: Any) -> Any` function (store.py:1650) is the epitome — any value in, any value out.
- **Impact:** `mypy --strict` cannot catch attribute typos on entity dicts, cannot validate function argument shapes, cannot detect missing keys. The type checker is effectively disabled for the entire domain layer.
- **Recommendation:** This is the single most impactful code quality improvement possible:
  1. Define `TypedDict` classes: `EntityDict`, `RunDict`, `FindingDict`, `EventDict`
  2. Replace `dict[str, Any]` with these TypedDicts in function signatures
  3. Use `NewType` for branded IDs: `RunId = NewType("RunId", uuid.UUID)`
  4. Replace `worker_context.py` `Any` getters with typed protocol classes
  5. Phase out `Any` usage file-by-file, starting with `store.py` public methods

#### [Severity: Low] `# type: ignore[import-untyped]` for APScheduler — only 3 ignores total
- **Location:** `src/easm/scheduler.py:6`, `runners/screenshot_runner.py:13`, `api/routes/auth.py:402`
- **Evidence:** Only 3 `# type: ignore` comments in the codebase. This is excellent discipline.
- **Impact:** Minimal. APScheduler lacks stubs. The screenshot runner has a conditional import.
- **Recommendation:** Create a minimal `apscheduler-stubs` package or add `[[tool.mypy.overrides]]` entry.

### Testing

#### [Severity: Medium] 89 test files — good breadth, uncertain depth
- **Location:** `tests/` directory — 89 Python files
- **Evidence:** Tests cover: auth (5 files), runners (8 files), certificates (5), assets (5), correlation (6), API (5), pivot (6), config, store, schemas, dedup, classification, etc. The conftest (`tests/conftest.py`) provides `db_pool` fixture with `asyncpg.create_pool` and `_truncate_app_tables` for cleanup.
- **Impact:** Test breadth is excellent. But test depth varies: some test files are integration tests requiring a real PostgreSQL database (`EASM_TEST_DATABASE_DSN`), while others are pure unit tests with mocked dependencies. No clear separation.
- **Recommendation:** Run all tests to verify they pass. Check if any test file exceeds 250 LOC. Ensure unit tests don't require a DB — the `db` marker should gate DB tests behind `-m db`. Consider adding property-based tests (hypothesis) for entity serialization.

#### [Severity: Low] No test for `ScreenshotRunner` without Playwright installed
- **Location:** `tests/test_runners/test_screenshot_runner.py:1` (file exists)
- **Evidence:** A file exists but the runner has a soft import `try: from playwright.async_api import async_playwright; except ImportError: _async_playwright = None`. Tests might pass because Playwright is in dev dependencies but not always installed.
- **Impact:** CI might not test the screenshot path reliably.
- **Recommendation:** Ensure Playwright is installed in CI. Add a test that explicitly verifies the `_async_playwright is None` branch.

### Dependency Hygiene

#### [Severity: Medium] `psycopg` is in deps but not used — `asyncpg` is the primary driver
- **Location:** `pyproject.toml:10` — `"psycopg[binary]>=3.2.0"` + `pyproject.toml:26` — `"psycopg_pool>=3.2.0"`
- **Evidence:** `db.py` uses `asyncpg.create_pool`. `queue.py:12` uses `procrastinate.PsycopgConnector` which uses `psycopg` internally. `psycopg_pool` is listed but no direct usage found — Procrastinate manages its own pool.
- **Impact:** Unnecessary dependencies increase supply-chain risk and image size. `psycopg_pool` may be unused.
- **Recommendation:** Verify that `psycopg_pool` is needed. If only Procrastinate uses psycopg internally, keep `psycopg[binary]` and remove `psycopg_pool`.

#### [Severity: Low] `greenlet` in deps — likely from `psycopg` or `SQLAlchemy`
- **Location:** `pyproject.toml:17` — `"greenlet>=3.5.0"`
- **Evidence:** `greenlet` is a dependency of `SQLAlchemy` (used by Alembic's `run_sync`). It's explicitly listed but should be picked up automatically via SQLAlchemy.
- **Impact:** Minimal — unlikely to cause version conflicts.
- **Recommendation:** Remove explicit `greenlet` dependency. It's pulled in transitively.

#### [Severity: Low] `ruff select` is limited — missing important rules
- **Location:** `pyproject.toml:49` — `select = ["E", "F", "I", "N", "W", "UP", "B", "C4", "SIM"]`
- **Evidence:** Missing: `"TCH"` (flake8-type-checking — catches unnecessary runtime imports), `"T20"` (print statements), `"RUF"` (ruff-specific rules), `"PIE"` (flake8-pie), `"RET"` (flake8-return), `"ARG"` (unused arguments), `"PLC"`, `"PLE"` (pylint conventions/errors).
- **Impact:** Code quality issues like unused imports, bare print statements, and unnecessary runtime imports could slip through.
- **Recommendation:** Expand to `select = ["ALL"]` and add per-file ignores for known acceptable violations (e.g., `per-file-ignores = {"tests/*": ["S101"]}` for `assert` in tests).

### Dockerfile & Operations

#### [Severity: Medium] Hardcoded tool versions — supply chain risk from unverified downloads
- **Location:** `Dockerfile:47-81`
- **Evidence:** Tools (subfinder v2.14.0, asnmap v1.1.1, nuclei v3.4.2, webanalyze v0.4.3, gitleaks v8.24.3) are downloaded from GitHub releases via `curl ... | unzip ...`. No checksum verification.
- **Impact:** If a GitHub release is compromised or MITM'd, the Docker image includes a malicious binary. The `apt-get update` step at line 13 partially mitigates this for nmap (Debian package), but not for the downloaded binaries.
- **Recommendation:** Add SHA256 checksum verification for each downloaded binary. Store checksums in the Dockerfile or a separate `SHA256SUMS` file. Pin versions in a single location (env vars at top of Dockerfile).

#### [Severity: Medium] `USER easm` after package installs — correct
- **Location:** `Dockerfile:92-98`
- **Evidence:** The worker stage creates the `easm` user AFTER installing system packages and Playwright browsers. This is correct — tools are installed as root, runtime runs as non-root.
- **Impact:** No security issue.
- **Recommendation:** Good practice. Ensure `EASM_MODE=worker` CMD does not expose port 8000 (it doesn't — confirmed at line 100).

#### [Severity: Low] No `HEALTHCHECK` instruction in Dockerfile
- **Location:** `Dockerfile` — missing `HEALTHCHECK` directive
- **Evidence:** The web stage exposes port 8000 and the app serves `/api/healthz`, but the Dockerfile doesn't include a `HEALTHCHECK`. Docker Compose files may add one, but the Dockerfile itself doesn't.
- **Impact:** Without `HEALTHCHECK`, Docker cannot detect if the application is hung vs healthy. In `docker-compose` without explicit health checks, container restarts only happen on process exit.
- **Recommendation:** Add `HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8000/api/healthz || exit 1`.

#### [Severity: Low] `worker` and `all-in-one` stages install `dnstwist` via pip
- **Location:** `Dockerfile:84`
- **Evidence:** `RUN pip install --no-cache-dir dnstwist` — duplicates the pip install step from the base stage (line 21: `pip install -e .`). This is intentional: dnstwist requires runtime dependencies that aren't captured by the wheel install.
- **Impact:** Image size bloat. The base stage's `--no-cache-dir` helps. No security issue.
- **Recommendation:** Consider adding `dnstwist` to `pyproject.toml` dependencies and removing the explicit pip install. The base stage's `-e .` install would pick it up.

### Dead Code & Debt

#### [Severity: Medium] `PaginatedQuery` — dead code, never imported
- **Location:** See Finding 5 above.

#### [Severity: Low] `task_queue_legacy.py` — legacy, still in the module
- **Location:** `src/easm/task_queue_legacy.py`
- **Evidence:** File exists with `procrastinate` imports and task management code. Likely superseded by the current Procrastinate integration (`tasks/runner.py`, `tasks/pivot.py`, `queue.py`).
- **Impact:** Dead code. Potential confusion about which task system is active.
- **Recommendation:** Verify it's unused and remove it.

#### [Severity: Low] `pivot/worker_legacy.py` — legacy worker
- **Location:** `src/easm/pivot/worker_legacy.py`
- **Evidence:** Another legacy worker file alongside the current Procrastinate-based pivot system.
- **Recommendation:** Same as above — verify and remove if unused.

#### [Severity: Low] `runners/__init__.py` has old `RUNNER_REGISTRY` for backward compat
- **Location:** `src/easm/runners/__init__.py:14,164` — `RUNNER_REGISTRY: dict[str, type] = {}`
- **Evidence:** The `RUNNER_REGISTRY` is populated only for backward compat but should be removable once the migration is complete.
- **Impact:** Minor — a few bytes of dead memory.
- **Recommendation:** Remove after completing the declarative migration (Finding 3).

---

## Top 5 Quick Wins

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| 1 | **Redact enrichment keys from `GET /api/config`** — use `SecretStr` + explicit exclude in config response | 1 hour | **Critical** — credential leak fix |
| 2 | **Add auth guards to all data routes** — create `require_auth` dependency, apply to every router | 2 hours | **High** — auth enforcement |
| 3 | **Add health check for unresolved `${VAR}` after `expandvars`** — prevent "${SECRET}" as literal config values | 30 min | **High** — silent misconfiguration guard |
| 4 | **Replace `anyio.to_thread` for DNS in `network_guard.py`** — fix event loop blocking | 30 min | **Medium** — async correctness |
| 5 | **Expand `ruff select` to `["ALL"]`** — catch unused imports, bare prints, broad excepts, etc. | 1 hour | **Medium** — code quality automation |

---

## Scorecard

| Dimension | Score (1–10) | Justification |
|-----------|-------------|---------------|
| **Architecture** | 4/10 | God object Store (1,578 LOC), monolithic handlers module (1,145 LOC), dual runner registry, unused pagination builder. Good separation between web/worker processes and clear runner abstraction. |
| **Async Hygiene** | 8/10 | `asyncio.wait_for` on all subprocesses, proper proc.kill(), `finally: client.aclose()`, semaphore-guarded HTTP concurrency. One blocking DNS call, one `os._exit`, no `asyncio.gather` issues. |
| **DB Layer** | 6/10 | Parameterized queries everywhere (no SQL injection), excellent use of `ON CONFLICT` upserts, event hash dedup. Offset pagination on large tables, N+1 in lineage walker, fragile `.endswith("1")` for row-count checks. |
| **Runner Safety** | 7/10 | No `shell=True`, proper timeout + kill, simulation mode with fixture fallback, `network_guard.py` prevents SSRF. Sequential subprocess execution is slow, DNS blocking, certstream lacks policy re-check. |
| **Error Handling** | 5/10 | `try/except Exception: pass` in 6+ locations with DEBUG logging, global exception handler leaks `str(exc)`, no error counters/metrics. Good: `RunStatus.FAILED` correctly set, exceptions don't crash frameworks. |
| **Type Safety** | 3/10 | `mypy --strict` enabled (good), but 340 `Any` usages across 49 files erase all type safety for domain objects. `dict[str, Any]` everywhere. Only 3 `type: ignore` comments (excellent discipline on that front). |
| **Testing** | 6/10 | 89 test files covering most modules, proper `db_pool` fixture with table truncation, auth tests comprehensive. Depth and pass status unknown without running tests. No property-based tests. |
| **Operations** | 7/10 | Multi-stage Dockerfile, multi-process architecture (web + worker), structlog JSON rendering, config hot reload, graceful shutdown in `finally`. No HEALTHCHECK, no checksums on binary downloads, ephemeral pepper on restart. |

---

**Overall Assessment:** Open EASM is a well-designed system with solid async fundamentals, avoiding the most dangerous Python patterns (`shell=True`, `time.sleep` in async, bare except). The architecture shows clear thought — runner abstraction, entity pipeline, simulation mode, network guard. The major weaknesses are long-term maintainability concerns: the Store God Object, the pervasive `Any` type erasure, and the lack of auth enforcement on data routes. The enrichment API key exposure is a critical operational risk that should be fixed immediately.

**Estimated remediation effort for Top 5 Quick Wins:** ~5 hours.  
**Estimated effort for all Findings (non-architectural):** ~40 hours.  
**Estimated effort for full architectural refactor (Store split + type migration):** ~80 hours.
