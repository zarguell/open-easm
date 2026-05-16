# EASM Passive Monitor — v0.2 PRD

**Project:** `easm-monitor`  
**Version:** 0.2 (API-first orchestration MVP)  
**Status:** Draft  
**Audience:** Agentic AI developer / autonomous coding agent

---

## Overview

`easm-monitor` is a self-hosted, passive External Attack Surface Management (EASM) monitoring platform. It continuously collects data from passive internet intelligence sources such as Certificate Transparency logs, passive subdomain enumeration, and ASN discovery, stores raw results in PostgreSQL, and exposes the collected data through an HTTP API.

**v0 scope is intentionally narrow:** build the orchestration layer, rich per-target configuration, raw data persistence, run tracking, and a required API. There is no normalization, no notification pipeline, and no dashboard in v0. The purpose of v0 is to start collecting real data, preserve it faithfully, and provide a stable contract for future parsers and UI work.

---

## Product Goals

- Continuously collect passive discovery data for configured targets
- Support target-specific runner configuration, schedules, matching rules, and metadata
- Store raw results exactly as received from each source
- Deduplicate repeated raw events
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
| DB driver | asyncpg | Avoid ORM in v0 |
| Scheduling | APScheduler | AsyncIOScheduler |
| Migrations | Alembic | Schema control |
| Packaging | Docker + Docker Compose | App + Postgres |

### Baseline rationale

Python 3.14 is now a stable release and includes improved asyncio introspection tools such as `python -m asyncio ps` and `python -m asyncio pstree`, which are useful for debugging a long-running scheduler and API service [page:0]. PostgreSQL 18 is also released and adds features including `uuidv7()`, skip scan support, parallel GIN index builds, and asynchronous I/O improvements, all of which are helpful for a raw-event platform built around JSONB and time-ordered records [page:1].

---

## Core Principles

1. **Raw-first ingestion**  
   Save source output exactly as received. Do not normalize in v0.

2. **Target-centric configuration**  
   Every target defines its own monitoring behavior, instead of relying on terse global lists.

3. **API-first architecture**  
   Every meaningful action or query should be possible through the API.

4. **Composable runners**  
   Each passive source is implemented as an independent runner with a consistent execution contract.

5. **Traceable execution**  
   Every runner invocation creates a run record with status, timing, and counters.

---

## High-Level Architecture

```text
┌─────────────────────────────────────────────────────┐
│                    FastAPI API                      │
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
│   raw_events JSONB + targets snapshot + run logs    │
└─────────────────────────────────────────────────────┘
```

---

## Repository Structure

```text
easm-monitor/
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── config.yaml.example
├── requirements.txt
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
    ├── test_api.py
    ├── test_store.py
    ├── test_scheduler.py
    ├── test_dedup.py
    └── test_runners.py
```

---

## Target Configuration Model

v0 must use a **rich per-target configuration model**. The system should not assume a small set of global domains or ASNs. Each target is a monitoring unit with its own match inputs and runner behavior.

### Example `config.yaml`

```yaml
targets:
  - id: corp-primary
    name: Example Corp Primary
    type: organization
    enabled: true
    labels:
      env: prod
      owner: security
      criticality: high
    match_rules:
      domains:
        - example.com
        - example.org
      keywords:
        - Example Corp
        - Example
      asns:
        - AS12345
    runners:
      certstream:
        enabled: true
        mode: realtime
        filters:
          include_common_name: true
          include_san_dns_names: true
          match_mode: suffix
      subfinder:
        enabled: true
        schedule: "0 */6 * * *"
        args:
          passive_only: true
          recursive: true
          timeout_seconds: 300
      asnmap:
        enabled: true
        schedule: "0 2 * * *"
        args:
          expand_org_names: true
          timeout_seconds: 300

  - id: subsidiary-brand
    name: Subsidiary Brand
    type: brand
    enabled: true
    labels:
      env: external
      owner: appsec
      criticality: medium
    match_rules:
      domains:
        - subsidiary.io
      keywords:
        - Subsidiary
    runners:
      certstream:
        enabled: true
        mode: realtime
        filters:
          include_common_name: true
          include_san_dns_names: true
          match_mode: suffix
      subfinder:
        enabled: true
        schedule: "30 */12 * * *"
        args:
          passive_only: true
          recursive: false
          timeout_seconds: 180
```

### Configuration requirements

- `id` must be unique and API-safe
- `enabled: false` disables all execution for that target
- each target may enable any subset of runners
- each runner has target-local settings, schedules, and arguments
- certstream is continuous and does not use cron scheduling
- schedulable runners must support per-target cron expressions
- `labels` are arbitrary key/value metadata returned by the API
- `match_rules` are passed to runners for filtering logic

### Config validation

`config.py` must validate the YAML at startup and fail fast on invalid schema. Validation should ensure:
- unique target IDs
- only supported runner names are accepted
- cron expressions are valid for schedulable runners
- required fields exist for enabled runners
- values such as timeout settings are sane integers

Use Pydantic models for config validation.

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

### Data notes

- `raw_events.raw` stores the original event content with minimal wrapping
- `event_hash` is computed as a sha256 of stable serialized content: `target_id + source + canonical_json(raw)`
- `run_id` links every event to the execution that collected it
- `runs.trigger_type` should support values such as `scheduled`, `manual`, and `stream`
- IDs should use PostgreSQL 18 `uuidv7()` for time-ordered identifiers [page:1]

---

## API Requirements

The API is a mandatory part of v0. It is the supported interface for querying system state and triggering manual execution.

### Required endpoints

#### `GET /healthz`
Returns:
- API status
- DB connectivity status
- scheduler status
- config load status

#### `GET /targets`
Returns all configured targets, including:
- target metadata
- enabled/disabled state
- configured runners
- last run summary per runner if available

#### `GET /targets/{target_id}`
Returns full target configuration view for one target.

#### `GET /events`
Supports filtering and pagination by:
- `target_id`
- `source`
- `start`
- `end`
- `limit`
- `cursor` or page/offset (cursor preferred)

Returns raw event metadata and truncated raw body preview.

#### `GET /events/{event_id}`
Returns full raw event JSON.

#### `GET /runs`
Supports filtering by:
- `target_id`
- `source`
- `status`
- `trigger_type`
- time range

Returns execution history ordered by newest first.

#### `GET /runs/{run_id}`
Returns one run record with counters and metadata.

#### `POST /runs/{target_id}/{runner}`
Triggers a manual run for a schedulable runner.

Requirements:
- reject manual execution for disabled targets
- reject unknown runner names
- reject manual execution of non-manual-capable continuous runners unless explicitly supported
- return accepted run record immediately

### API design notes

- FastAPI response models must be explicit
- all timestamps returned as ISO 8601 UTC strings
- pagination should be deterministic
- API errors must use structured JSON error responses
- no auth required in v0, but route layout should not block adding auth later

---

## Runner Contract

All runners must implement a shared interface.

### `BaseRunner`

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

### Runner behavior requirements

- create a `runs` record before execution starts
- update the run record throughout execution
- catch and persist errors instead of crashing the process
- write each raw result through the store layer
- count inserted vs deduped events
- keep source-specific parsing minimal, only enough to serialize source output consistently

---

## Runner Specifications

### `certstream_runner.py`

Purpose:
- continuously watch Certificate Transparency events and match them against enabled targets

Behavior:
- connect to the certstream websocket feed
- process only `certificate_update` messages
- inspect CN and SAN DNS names based on target filter config
- when an event matches a target, write one `raw_event` for that target
- maintain a long-lived stream run model or synthetic run segmentation every fixed interval (implementation choice: recommended segmentation per hour)
- reconnect automatically with exponential backoff after disconnects

Notes:
- certstream is continuous and should start at application boot for all enabled targets that configure it
- because targets may overlap, one CT event may be stored once per matching target

### `subfinder_runner.py`

Purpose:
- perform scheduled passive subdomain discovery for domains defined in a target’s match rules

Behavior:
- for each domain in `target.match_rules.domains`, shell out to `subfinder`
- use passive-only arguments when configured
- parse line-delimited JSON output
- write each line as one raw event
- enforce per-domain timeout
- record inserted and deduped counts in the run

### `asnmap_runner.py`

Purpose:
- discover ASN and IP range relationships for a target’s configured ASNs and optionally org names

Behavior:
- run once per target schedule
- invoke `asnmap` for configured ASNs
- optionally invoke org-name expansion when enabled
- serialize each result as a raw event
- enforce timeout per input

---

## Scheduler Requirements

Use `APScheduler.AsyncIOScheduler`.

### Responsibilities

- register one job per target per schedulable runner
- start continuous runners at app startup
- avoid double registration on reload
- support graceful shutdown
- provide scheduler status to `/healthz`

### Scheduling model

- `certstream`: startup continuous task, not cron-based
- `subfinder`: cron schedule from each target’s config
- `asnmap`: cron schedule from each target’s config

### Concurrency rules

- runs for different targets may execute concurrently
- the same target/runner pair must not overlap unless explicitly allowed
- use a lock or APScheduler job constraints to prevent duplicate overlapping jobs

---

## Store Layer Requirements

`store.py` is the write boundary between runners and PostgreSQL.

### Required methods

- `create_run(...) -> UUID`
- `mark_run_started(run_id, started_at)`
- `mark_run_finished(run_id, status, finished_at, duration_ms, inserted_count, deduped_count, error_count, error_message=None, metadata=None)`
- `insert_raw_event(target_id, source, raw, run_id) -> bool`
- `list_events(filters...)`
- `get_event(event_id)`
- `list_runs(filters...)`
- `get_run(run_id)`
- `save_config_snapshot(raw_config)`

### Dedup requirements

- canonicalize JSON before hashing so key ordering does not create false uniqueness
- dedup must happen at the DB level via unique constraint on `event_hash`
- on duplicate insert, do not raise to the runner; return `False`

---

## FastAPI Application Requirements

### `main.py`
Responsibilities:
- load config
- initialize DB pool
- apply migrations or verify schema readiness
- initialize scheduler
- start FastAPI app
- start continuous runners during startup hook

### `api/app.py`
Responsibilities:
- create FastAPI application
- register routers
- define startup/shutdown lifecycle
- mount OpenAPI docs in v0

### Response schemas

Create explicit Pydantic response models for:
- health status
- target summary
- target detail
- event summary
- event detail
- run summary
- run detail
- API error shape

---

## Docker Requirements

### `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:18-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 5s
      timeout: 5s
      retries: 10

  easm:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    ports:
      - "8000:8000"
    restart: unless-stopped

volumes:
  postgres_data:
```

### Dockerfile requirements

- base image compatible with Python 3.14
- install `subfinder` and `asnmap` binaries in image
- run app as non-root user
- expose port 8000
- entrypoint starts Uvicorn app

---

## Observability and Logging

- use structured JSON logs
- log every run start and finish
- log event insertions at debug level only
- log certstream reconnect events with backoff duration
- include `target_id`, `source`, `run_id`, and counts in run completion logs
- expose only health information in API; no separate metrics endpoint in v0

Python 3.14’s asyncio task inspection tooling is a useful operational aid for diagnosing blocked tasks in this long-running async service [page:0].

---

## Acceptance Criteria

- [ ] `docker compose up` starts PostgreSQL 18 and the API service successfully [page:1]
- [ ] configuration supports multiple targets with independent runner settings and schedules
- [ ] invalid configuration fails startup with clear validation errors
- [ ] certstream starts continuously for enabled targets and stores matching events
- [ ] subfinder runs on each target’s configured schedule and stores raw output
- [ ] asnmap runs on each target’s configured schedule and stores raw output
- [ ] duplicate raw events are dropped via `event_hash` dedup
- [ ] every runner execution creates a persisted run record
- [ ] API exposes `/healthz`, `/targets`, `/targets/{target_id}`, `/events`, `/events/{event_id}`, `/runs`, `/runs/{run_id}`, and `POST /runs/{target_id}/{runner}`
- [ ] API returns full raw JSON for a single event lookup
- [ ] continuous service can be stopped cleanly without corrupting active runs
- [ ] OpenAPI docs load successfully in development mode

---

## Out of Scope for v1 Planning

These are explicitly deferred:

- parser layer and normalized entities
- correlation engine
- alerting or notifications
- dashboard frontend
- auth and multi-user access controls
- source-specific confidence scoring
- historical delta classification beyond dedup

---

## Future Extensions

After v0, likely next steps are:
- add parsed entity tables alongside raw event storage
- introduce replay/backfill parsers over historical raw events
- add a read-only dashboard backed by the existing API
- add source plugins for Shodan, Censys, WHOIS/RDAP, RIPE RIS, GitHub leak monitoring
- add auth and API tokens
- add event classification and delta semantics like “new subdomain” or “new ASN association”

---

## Implementation Notes for the Agent

- Use Python 3.14 syntax and standard library capabilities where appropriate [page:0]
- Prefer `asyncio.TaskGroup` for startup orchestration and managing long-lived tasks [page:0]
- Keep DB access in `asyncpg`; do not introduce SQLAlchemy in v0
- Use Alembic migrations for schema creation and upgrades
- Keep runner implementations thin and source-focused
- Preserve raw source fidelity; do not redesign third-party payloads in v0
- Design the API and service boundaries so a future UI can consume them without internal imports
- Add tests for config validation, dedup behavior, run lifecycle tracking, and API filtering
