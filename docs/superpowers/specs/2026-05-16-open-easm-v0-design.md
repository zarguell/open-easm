# open-easm v0 Design Specification

**Project:** open-easm
**Version:** 0.2 (API-first orchestration MVP)
**Status:** Approved
**Audience:** Agentic AI developer / autonomous coding agent
**Source PRD:** easm-passive-monitor-prd-v0.2.md

---

## Overview

open-easm is a self-hosted, passive External Attack Surface Management (EASM) monitoring platform. It continuously collects data from passive internet intelligence sources (Certificate Transparency logs, passive subdomain enumeration, ASN discovery), stores raw results in PostgreSQL, and exposes the collected data through an HTTP API.

**v0 scope is intentionally narrow:** build the orchestration layer, rich per-target configuration, raw data persistence, run tracking, and a required API. There is no normalization, no notification pipeline, and no dashboard in v0.

---

## Product Goals

- Continuously collect passive discovery data for configured targets
- Support target-specific runner configuration, schedules, matching rules, and metadata
- Store raw results exactly as received from each source
- Deduplicate repeated raw events via content hashing
- Provide an API for querying targets, runs, and raw events
- Support manual execution of schedulable runners via API
- Be fully self-hosted and containerized

### Non-Goals

- Notifications or alert routing
- Parsed or normalized entity models
- Correlation across sources
- Dashboard or web UI
- Multi-user auth / RBAC
- Active scanning or direct interaction with monitored assets

---

## Technical Baseline

| Component | Requirement | Notes |
|---|---|---|
| Language | Python 3.14 | Use current stable Python baseline |
| Database | PostgreSQL 18 | Primary store for raw events and run history |
| API | FastAPI | Async HTTP API |
| ASGI server | Uvicorn | Production entrypoint |
| DB driver | asyncpg | No ORM in v0 |
| Scheduling | APScheduler | AsyncIOScheduler |
| Migrations | Alembic | Schema control |
| Package management | uv | Pyproject.toml, generates requirements.txt for Docker |
| Testing | pytest + pytest-asyncio | Async test support |
| Linting/formatting | ruff | Single tool, fast |
| Type checking | mypy (strict mode) | Catch type errors early |
| Packaging | Docker + Docker Compose | App + Postgres, Docker-only dev workflow |

### Version Rationale

Python 3.14 includes improved asyncio introspection tools (`python -m asyncio ps`, `python -m asyncio pstree`) useful for debugging a long-running scheduler and API service. PostgreSQL 18 adds `uuidv7()`, skip scan support, parallel GIN index builds, and asynchronous I/O improvements — all helpful for a raw-event platform built around JSONB and time-ordered records.

---

## Core Principles

1. **Raw-first ingestion** — Save source output exactly as received. Do not normalize in v0.
2. **Target-centric configuration** — Every target defines its own monitoring behavior via a rich config model.
3. **API-first architecture** — Every meaningful action or query must be possible through the API.
4. **Composable runners** — Each passive source is an independent runner with a consistent execution contract.
5. **Traceable execution** — Every runner invocation creates a run record with status, timing, and counters.
6. **Config at startup only** — Configuration loaded once at startup, restart required for changes. Simpler v0.

---

## Architecture

### High-Level Component Diagram

```
┌─────────────────────────────────────────────────────┐
│                    FastAPI API                       │
│  /healthz /targets /events /runs /manual-execute    │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│                 Scheduler Layer                     │
│         APScheduler + per-target runner jobs        │
└───────────────┬───────────────────────┬─────────────┘
                │                       │
     ┌──────────▼─────────┐   ┌─────────▼──────────┐
     │   Runner Manager   │   │     Run Store      │
     │ certstream         │   │ run metadata       │
     │ subfinder          │   │ statuses/counters  │
     │ asnmap             │   └────────────────────┘
     └──────────┬─────────┘
                │ raw events
┌───────────────▼─────────────────────────────────────┐
│                 PostgreSQL 18 Store                 │
│   raw_events JSONB + runs + config_snapshots        │
└─────────────────────────────────────────────────────┘
```

### Component Responsibilities

**config.py** — Load and validate config.yaml at startup using Pydantic. Fail fast on invalid schema. Validate unique target IDs, supported runner names, valid cron expressions, required fields, sane integer values.

**db.py** — Create and manage asyncpg connection pool. Provide pool lifecycle (init, close). Expose pool to store layer.

**store.py** — Write boundary between runners and PostgreSQL. All DB access goes through this layer. Provides CRUD for runs, events, and config snapshots. Handles dedup via event_hash unique constraint.

**models.py** — Shared type aliases and enum definitions (TriggerType, RunStatus, etc.).

**services/** — Thin service layer between API routes and store. Encapsulates query logic and response assembly. Keeps route handlers clean.

**api/app.py** — FastAPI application with startup/shutdown lifecycle hooks, router registration, OpenAPI docs.

**api/deps.py** — Dependency injection: get_store, get_scheduler, get_config.

**api/schemas.py** — Explicit Pydantic response models for all endpoints.

**api/routes/** — Route handlers: health, targets, events, runs. All timestamps ISO 8601 UTC. Structured JSON errors. Cursor-based pagination where applicable.

**runners/base.py** — BaseRunner ABC with `run_once(target, trigger_type) -> UUID` contract.

**runners/certstream_runner.py** — Continuous websocket connection to certstream.calidog.io. Matches CN/SAN against target filters. Hourly run segmentation. Exponential backoff reconnect.

**runners/subfinder_runner.py** — Scheduled. Shells out to subfinder binary. Per-domain timeout enforcement. Parses line-delimited JSON output.

**runners/asnmap_runner.py** — Scheduled. Shells out to asnmap binary. Optional org-name expansion. Per-input timeout.

**scheduler.py** — APScheduler.AsyncIOScheduler. Registers one job per target per schedulable runner. Avoids double registration. Supports graceful shutdown. Status queryable by /healthz.

**main.py** — Entry point. Uses asyncio.TaskGroup for startup orchestration: load config, init DB pool, apply migrations, init scheduler + register jobs, start continuous runners, start FastAPI/Uvicorn.

### Data Flow

```
config.yaml → config.py (Pydantic validation at startup, fail-fast)
                    ↓
              main.py (asyncio.TaskGroup: start API + scheduler + continuous runners)
                    ↓
    ┌───────────────┼──────────────────┐
    ↓               ↓                  ↓
  APScheduler   certstream_runner   FastAPI (uvicorn)
  (subfinder,    (websocket          (routes → services → store)
   asnmap cron)   connect+filter)
    ↓               ↓
  runners call store.py ←→ PostgreSQL 18 (asyncpg pool)
                    ↓
              raw_events table
              (ON CONFLICT event_hash → dedup)
              runs table
              (status lifecycle tracking)
              config_snapshots table
```

---

## Repository Structure

```
open-easm/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── .env.example
├── config.yaml.example
├── README.md
├── alembic/
│   ├── env.py
│   └── versions/
│       └── 0001_initial.py
├── src/
│   └── easm/
│       ├── __init__.py
│       ├── main.py
│       ├── config.py
│       ├── db.py
│       ├── store.py
│       ├── scheduler.py
│       ├── models.py
│       ├── services/
│       │   ├── target_service.py
│       │   ├── event_service.py
│       │   └── run_service.py
│       ├── api/
│       │   ├── __init__.py
│       │   ├── app.py
│       │   ├── deps.py
│       │   ├── schemas.py
│       │   └── routes/
│       │       ├── health.py
│       │       ├── targets.py
│       │       ├── events.py
│       │       └── runs.py
│       └── runners/
│           ├── __init__.py
│           ├── base.py
│           ├── certstream_runner.py
│           ├── subfinder_runner.py
│           └── asnmap_runner.py
└── tests/
    ├── conftest.py
    ├── test_config.py
    ├── test_store.py
    ├── test_dedup.py
    ├── test_runners.py
    ├── test_scheduler.py
    └── test_api.py
```

---

## Configuration Model

### Config Format

Per-target YAML configuration with independent runner settings, schedules, and match rules per target.

### Validation Rules

- `id` must be unique and API-safe (alphanumeric + hyphens)
- `enabled: false` disables all execution for that target
- Each target may enable any subset of runners
- Each runner has target-local settings, schedules, and arguments
- certstream is continuous and does not use cron scheduling
- Schedulable runners must have valid cron expressions
- `labels` are arbitrary key/value metadata returned by the API
- `match_rules` are passed to runners for filtering logic
- Timeout values must be sane positive integers

Config loaded once at startup. Invalid config causes process exit with clear error message.

---

## Data Model

### Table: `raw_events`

```sql
CREATE TABLE raw_events (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    target_id     TEXT NOT NULL,
    source        TEXT NOT NULL,
    collected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw           JSONB NOT NULL,
    event_hash    TEXT NOT NULL,
    run_id        UUID NOT NULL,
    CONSTRAINT uq_raw_events_event_hash UNIQUE (event_hash)
);

CREATE INDEX idx_raw_events_target_id ON raw_events (target_id);
CREATE INDEX idx_raw_events_source ON raw_events (source);
CREATE INDEX idx_raw_events_collected_at ON raw_events (collected_at DESC);
CREATE INDEX idx_raw_events_run_id ON raw_events (run_id);
CREATE INDEX idx_raw_events_raw_gin ON raw_events USING GIN (raw);
```

### Table: `runs`

```sql
CREATE TABLE runs (
    id                UUID PRIMARY KEY DEFAULT uuidv7(),
    target_id         TEXT NOT NULL,
    source            TEXT NOT NULL,
    trigger_type      TEXT NOT NULL,
    status            TEXT NOT NULL,
    scheduled_for     TIMESTAMPTZ,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ,
    duration_ms       INTEGER,
    inserted_count    INTEGER NOT NULL DEFAULT 0,
    deduped_count     INTEGER NOT NULL DEFAULT 0,
    error_count       INTEGER NOT NULL DEFAULT 0,
    error_message     TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_runs_target_id ON runs (target_id);
CREATE INDEX idx_runs_source ON runs (source);
CREATE INDEX idx_runs_started_at ON runs (started_at DESC);
CREATE INDEX idx_runs_status ON runs (status);
```

### Table: `config_snapshots`

```sql
CREATE TABLE config_snapshots (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    loaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    config_hash   TEXT NOT NULL UNIQUE,
    raw_config    JSONB NOT NULL
);
```

### Key Data Rules

- `event_hash` computed as sha256 of `canonical_json({target_id, source, raw})` — key ordering canonicalized
- `run_id` links every event to the execution that collected it
- `trigger_type` values: `scheduled`, `manual`, `stream`
- Duplicate events dropped via unique constraint on `event_hash`, store returns `False` (not an exception)
- All IDs use PostgreSQL 18 `uuidv7()` for time-ordered identifiers

---

## API Specification

### `GET /healthz`
Returns: API status, DB connectivity, scheduler status, config load status.

### `GET /targets`
Returns all configured targets with metadata, enabled state, configured runners, last run summary per runner.

### `GET /targets/{target_id}`
Full target configuration view for one target.

### `GET /events`
Filtering: `target_id`, `source`, `start`, `end`, `limit`, `cursor`. Returns raw event metadata + truncated raw body preview. Cursor-based pagination.

### `GET /events/{event_id}`
Full raw event JSON.

### `GET /runs`
Filtering: `target_id`, `source`, `status`, `trigger_type`, time range. Ordered newest first.

### `GET /runs/{run_id}`
Single run record with counters and metadata.

### `POST /runs/{target_id}/{runner}`
Manual execution trigger. Rejects: disabled targets, unknown runners, non-manual-capable continuous runners. Returns accepted run record immediately.

### API Design Rules

- FastAPI response models must be explicit Pydantic schemas
- All timestamps ISO 8601 UTC strings
- Structured JSON error responses: `{"error": "type", "detail": "message"}`
- No auth required in v0, but route layout must not block adding auth later
- OpenAPI docs enabled in v0

---

## Runner Contract

### BaseRunner ABC

```python
class BaseRunner(ABC):
    source_name: str
    supports_schedule: bool
    supports_manual_trigger: bool
    is_continuous: bool

    @abstractmethod
    async def run_once(self, target: TargetConfig, trigger_type: str) -> UUID:
        ...
```

### Runner Behavior Requirements

- Create a `runs` record before execution starts (via store.create_run)
- Update the run record throughout execution (mark started, mark finished)
- Catch and persist errors instead of crashing the process
- Write each raw result through the store layer (store.insert_raw_event)
- Count inserted vs deduped events and report in run completion
- Keep source-specific parsing minimal, only enough to serialize source output consistently

### Concurrency Rules

- Runs for different targets may execute concurrently
- Same target/runner pair must not overlap (prevent via APScheduler job constraints)
- Continuous runners run as long-lived asyncio tasks

---

## Scheduler Design

### Technology
APScheduler.AsyncIOScheduler.

### Job Registration
- `subfinder`: one cron job per target from target config schedule
- `asnmap`: one cron job per target from target config schedule
- `certstream`: continuous asyncio task started at app boot (not cron-based)

### Lifecycle
- Register all jobs at startup after config load
- Avoid double registration (check existing jobs)
- Graceful shutdown: stop scheduler, wait for in-flight jobs
- Expose scheduler status to /healthz endpoint

---

## Store Layer Design

### Interface

```python
async def create_run(target_id, source, trigger_type, scheduled_for=None) -> UUID
async def mark_run_started(run_id, started_at) -> None
async def mark_run_finished(run_id, status, finished_at, duration_ms, inserted_count, deduped_count, error_count, error_message=None, metadata=None) -> None
async def insert_raw_event(target_id, source, raw, run_id) -> bool  # False on dup
async def list_events(target_id=None, source=None, start=None, end=None, limit=50, cursor=None) -> tuple[list[dict], str | None]
async def get_event(event_id) -> dict | None
async def list_runs(target_id=None, source=None, status=None, trigger_type=None, start=None, end=None, limit=50, offset=0) -> list[dict]
async def get_run(run_id) -> dict | None
async def save_config_snapshot(raw_config) -> None
```

### Dedup Behavior

- Canonicalize JSON (sort keys) before hashing with sha256
- event_hash = sha256(f"{target_id}:{source}:{canonical_json(raw)}")
- INSERT with ON CONFLICT (event_hash) DO NOTHING
- Return True if inserted, False if duplicate
- Never raise to the caller on duplicate

---

## Docker Design

### Dockerfile
- Base: python:3.14-slim (or alpine variant available at build time)
- Install subfinder and asnmap from pre-built GitHub release binaries
- Copy application code, install Python dependencies from requirements.txt (exported from uv)
- Run as non-root user
- Expose port 8000
- Entry: `uvicorn easm.main:app --host 0.0.0.0 --port 8000`

### docker-compose.yml
- postgres service: postgres:18-alpine with healthcheck (pg_isready)
- easm service: depends_on postgres healthy, mounts config.yaml read-only, env_file .env
- Named volume for postgres_data

---

## Observability

- Structured JSON logs (via python-json-logger or structlog)
- Log every run start and finish with target_id, source, run_id, counts
- Log event insertions at DEBUG level only
- Log certstream reconnect events with backoff duration
- Expose health via /healthz only (no separate metrics endpoint in v0)

---

## Error Handling Strategy

| Error Type | Handling |
|---|---|
| Invalid config.yaml | Exit with clear Pydantic validation error message |
| DB connection failure | Retry with backoff at startup, return 503 in healthz once running |
| Duplicate event insert | Return False from store, counted as deduped by runner |
| Runner execution error | Caught, logged, persisted to runs.error_message, run marked failed |
| Certstream disconnect | Reconnect with exponential backoff, logged |
| API request validation | FastAPI automatic 422, structured JSON errors |
| Unknown endpoint | FastAPI 404 |
| Internal server error | FastAPI exception handler returns structured JSON |

---

## Testing Strategy

### Test Categories
- **Config validation tests** (test_config.py): valid configs, invalid schemas, missing fields, duplicate IDs, bad cron expressions
- **Store tests** (test_store.py): CRUD operations, filtering, pagination
- **Dedup tests** (test_dedup.py): hash canonicalization, duplicate detection, edge cases
- **Runner tests** (test_runners.py): runner contract compliance, run lifecycle, error handling
- **Scheduler tests** (test_scheduler.py): job registration, duplicate prevention, status queries
- **API tests** (test_api.py): endpoint availability, response schemas, filtering, error responses

### Test Infrastructure
- pytest + pytest-asyncio
- Test database via Docker (separate postgres container or ephemeral)
- Fixtures in conftest.py: test config, test DB pool, test client (httpx.AsyncClient or FastAPI TestClient)
- All tests runnable with `pytest`

---

## Acceptance Criteria

- [ ] `docker compose up` starts PostgreSQL 18 and the API service successfully
- [ ] Configuration supports multiple targets with independent runner settings and schedules
- [ ] Invalid configuration fails startup with clear validation errors
- [ ] certstream starts continuously for enabled targets and stores matching events
- [ ] subfinder runs on each target's configured schedule and stores raw output
- [ ] asnmap runs on each target's configured schedule and stores raw output
- [ ] Duplicate raw events are dropped via event_hash dedup
- [ ] Every runner execution creates a persisted run record
- [ ] API exposes all 8 required endpoints
- [ ] API returns full raw JSON for a single event lookup
- [ ] Continuous service can be stopped cleanly without corrupting active runs
- [ ] OpenAPI docs load successfully in development mode

---

## Out of Scope

- Parser layer and normalized entities
- Correlation engine
- Alerting or notifications
- Dashboard frontend
- Auth and multi-user access controls
- Source-specific confidence scoring
- Historical delta classification beyond dedup
- Config hot-reload
- Multi-user RBAC
- Metrics endpoint
