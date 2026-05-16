# open-easm v1 Design Specification

**Project:** open-easm
**Version:** 1.0 (entity graph, parser layer, pivot engine, delta detection)
**Status:** Draft
**Audience:** Agentic AI developer / autonomous coding agent
**Predecessor:** v0 Design Spec (2026-05-16-open-easm-v0-design.md)

---

## Overview

open-easm v1 transforms the v0 raw-event store into an entity graph with typed nodes, relationships, and automated cascading discovery. Raw events are parsed into typed entities (domain, hostname, ip, ip_range, certificate, asn, org), relationships are derived between them, and a pivot engine follows configurable rules to spider outward from seed entities — always bounded by scope and depth limits.

Key additions: entity/relationship tables, per-source parsers, a backfill pipeline, a pivot queue with coverage-aware dedup, delta detection on entities, a crt.sh API runner, and operational hardening (config hot-reload, run retention, certstream gap detection, startup self-check).

Notifications are designed as a contract (API shape and config structure reserved) but not implemented.

---

## Product Goals

- Parse raw JSONB events from every runner into typed, deduplicated entity rows
- Derive relationships between entities (ASN→IP range, cert→domain, domain→IP, etc.)
- Enable cascading discovery via configurable pivot rules bounded by scope and depth
- Surface delta detection: what entities are new since a given run or timestamp
- Introduce a new API-based runner (crt.sh) for historical cert coverage
- Make the system trustworthy for unattended operation (config hot-reload, run GC, startup checks)
- Reserve API and config contracts for a future notification layer

### Non-Goals

- Global cross-target entity dedup (designed for, deferred to v2)
- Notifications or alert routing (contract reserved, implementation deferred)
- Dashboard or web UI (except possibly a graph visualizer as a later addition)
- Active scanning or direct interaction with monitored assets
- Multi-user auth / RBAC
- Apache AGE graph extension (recursive CTEs sufficient for current scale)

---

## Technical Baseline

Same as v0: Python 3.14, PostgreSQL 18, FastAPI, asyncpg, APScheduler, Alembic, uv, pytest, ruff, mypy.

New dependencies: `tldextract` (apex domain extraction for coverage checks), `dnstwist` (standalone scheduled runner, not pivot engine), `httpx` (HTTP client for API-based runners and pivot handlers), `dnspython` (PTR lookups in reverse_dns pivot handler).

---

## Core Principles

1. **Raw-first ingestion** — All source data captured as raw JSONB before any parsing. Parsers are always reprocessable.
2. **Normalize-once contract** — `normalize_entity_value(type, value) -> str` is the single normalization function every parser and future global registry depends on.
3. **Entity graph over pipeline** — Assets are nodes in a graph, not items in a linear pipeline. Relationships are first-class.
4. **Bounded spidering** — Every pivot is gated by scope evaluation, depth limits, cooldown windows, and coverage checks. No unbounded scanning.
5. **Provenance everywhere** — Every entity and relationship traces back to its raw event(s) and discovery context (run or pivot job).
6. **API-first architecture** — All entity, relationship, and delta queries are API-accessible.
7. **Config at startup with hot-reload** — Config loaded at boot, reloadable via `POST /config/reload` without restart.

---

## Architecture

### High-Level Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                        FastAPI API                            │
│  /healthz /targets /events /runs /entities /graph /config    │
└─────────────────────────┬────────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────────┐
│                    Scheduler Layer                            │
│     APScheduler + per-target runner jobs + pivot worker      │
└────────────────┬────────────────┬────────────────────────────┘
                 │                │
┌────────────────▼────┐  ┌───────▼─────────────────────────────┐
│    Runner Manager   │  │         Pivot Engine                 │
│  crt.sh (new)       │  │  pivot_queue + pivot worker pool     │
│  subfinder          │  │  scope evaluator                     │
│  asnmap             │  │  pivot handlers (dns_resolve,        │
│  certstream         │  │    rdap_lookup, crtsh_search,        │
│  dnstwist (new)     │  │    shodan_enrich, reverse_dns,       │
│                     │  │    domain_rdap, subdomain_enum)      │
└─────────┬───────────┘  └─────────────────┬───────────────────┘
          │  raw events                    │  entities
          ▼                                ▼
┌──────────────────────────────────────────────────────────────┐
│                    Backfill / Parser Layer                    │
│   polls raw_events WHERE parsed_at IS NULL                    │
│   per-source parser → typed entities + relationships          │
│   updates parsed_at, parsed_by, parse_error                   │
└──────────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────┐
│                  PostgreSQL 18 Store                          │
│   raw_events | entities | entity_relationships               │
│   runs | pivot_queue | config_snapshots                      │
└──────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

**entity_store.py** (new) — Entity and relationship CRUD. Owns `normalize_entity_value()`, entity upsert with `ON CONFLICT DO UPDATE` for `last_seen_at` and `attributes` merge, relationship insert, delta queries.

**parse/__init__.py** (new) — Parser registry mapping source names to parser classes.

**parse/base.py** (new) — `BaseParser` ABC with `source_name`, `current_version`, `parsed_by` property, `parse(raw_event) -> ParseResult`.

**parse/subfinder_parser.py** (new) — Parses subfinder line-delimited JSON into `domain` entities.

**parse/asnmap_parser.py** (new) — Parses asnmap JSON into `asn` and `ip_range` entities with `owns` relationships.

**parse/certstream_parser.py** (new) — Parses certstream cert data into `certificate` and `domain` entities with `issued_for` and `san_contains` relationships. Current version: 1.

**parse/crtsh_parser.py** (new) — Parses crt.sh API JSON into `certificate` and `domain` entities. Same entity types and relationship types as certstream. Current version: 1.

**backfill.py** (new) — Backfill worker: polls `raw_events WHERE parsed_at IS NULL OR parsed_by IS DISTINCT FROM source || ':' || parser.current_version ORDER BY collected_at LIMIT $batch_size`, feeds to parser, writes entities/relationships, sets `parsed_at`/`parsed_by`/`parse_error`. Configurable batch size, sleep interval. Triggers pivot resolver per batch.

**runners/base.py** (modify) — Add `is_api_runner: bool` class flag and optional `http_client` support alongside existing `is_continuous` and subprocess support.

**runners/crtsh_runner.py** (new) — Scheduled API runner: queries `crt.sh/?q=%.{domain}&output=json` for each target domain, respects rate limiting, inserts results as raw JSONB events. Uses httpx.

**runners/dnstwist_runner.py** (new) — Scheduled subprocess runner: shells out to dnstwist against `match_rules.domains` apex domains. Standalone — does not feed the pivot engine. Independent monitoring track.

**pivot/__init__.py** (new) — Pivot handler registry mapping `via` names to handler classes.

**pivot/resolver.py** (new) — Pivot resolver: invoked per backfill batch after entities are written. For each new entity, checks target pivot config (enabled, depth, scope, cooldown, coverage), enqueues eligible pivot jobs to `pivot_queue`.

**pivot/worker.py** (new) — Pivot worker pool: `asyncio.TaskGroup` of n workers, each polls `pivot_queue WHERE status = 'pending' LIMIT 1 FOR UPDATE SKIP LOCKED`, executes handler, feeds results to parser, marks completed/failed. Startup cleanup resets orphaned `running` jobs to `pending`.

**pivot/handlers/** (new) — Individual pivot handler implementations: `dns_resolve.py`, `rdap_lookup.py`, `crtsh_search.py`, `shodan_enrich.py`, `reverse_dns.py`, `domain_rdap.py`, `subdomain_enum.py`. Each is a `PivotHandler` subclass.

**pivot/scope.py** (new) — ScopeEvaluator: `evaluate(target, entity_type, entity_value) -> ScopeResult` with `IN_SCOPE | OUT_OF_SCOPE | UNKNOWN`. Uses target.match_rules.

**store.py** (modify) — Add entity CRUD methods, pivot queue CRUD, run retention/garbage collection methods.

**config.py** (modify) — Add `PivotConfig`, `CoverageConfig`, `NotificationConfig` (stub) to Pydantic models. Add hot-reload logic: `reload_config()` re-validates, diffs targets, adds/removes scheduler jobs, persists config_snapshot.

**scheduler.py** (modify) — Add `remove_jobs_for_target(target_id)`, `add_jobs_for_target(target)`, `reload_schedule(config)` for config hot-reload support.

**api/routes/** (modify/new) — Add entity, relationship, graph, and config endpoints.

**main.py** (modify) — Start backfill worker, pivot worker pool alongside existing scheduler and continuous runners. Config hot-reload endpoint.

---

## Data Model

### organizations (new)

Multitenancy foundation. No RLS or auth enforcement in v1 — just the column, FK, and a `'default'` org for existing data.

```sql
CREATE TABLE organizations (
    id   TEXT PRIMARY KEY,              -- slug: 'default', 'corp-a', etc.
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO organizations (id, name) VALUES ('default', 'Default Organization');
```

### raw_events (modified)

Add `org_id` and three parser columns:

```sql
ALTER TABLE raw_events ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES organizations(id);
ALTER TABLE raw_events ADD COLUMN parsed_at TIMESTAMPTZ;
ALTER TABLE raw_events ADD COLUMN parsed_by TEXT;       -- e.g. 'certstream:1'
ALTER TABLE raw_events ADD COLUMN parse_error TEXT;     -- NULL if parse succeeded
CREATE INDEX idx_raw_events_unparsed ON raw_events (source, parsed_at) WHERE parsed_at IS NULL;
CREATE INDEX idx_raw_events_org ON raw_events (org_id);
```

**Session ID convention:** Pivot-originated raw events embed the `discovery_session_id` in their `raw` JSONB under a `_meta` key: `{"_meta": {"session_id": "uuid..."}, ...actual data...}`. The backfill loop reads this from the raw JSONB to propagate to entity upserts. Runner-originated events get session_id from their parent run record (`runs.discovery_session_id`).

### entities (new)

```sql
CREATE TABLE entities (
    id               UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id           TEXT NOT NULL REFERENCES organizations(id),
    target_id        TEXT NOT NULL,
    entity_type      TEXT NOT NULL,
    entity_value     TEXT NOT NULL,
    attributes       JSONB DEFAULT '{}',
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_first_discovery BOOLEAN NOT NULL DEFAULT FALSE,
    discovery_session_id UUID,
    discovery_run_id UUID REFERENCES runs(id),
    discovery_pivot_id UUID REFERENCES pivot_queue(id),
    
    UNIQUE(org_id, target_id, entity_type, entity_value)
);
CREATE INDEX idx_entities_org ON entities (org_id);
CREATE INDEX idx_entities_target ON entities (target_id);
CREATE INDEX idx_entities_type ON entities (entity_type);
CREATE INDEX idx_entities_first_seen ON entities (first_seen_at);
CREATE INDEX idx_entities_last_seen ON entities (last_seen_at);
CREATE INDEX idx_entities_attrs ON entities USING GIN (attributes);
```

Exactly one of `discovery_run_id` or `discovery_pivot_id` is non-null. Both are nullable for manual entity creation.

Entity upsert uses `ON CONFLICT DO UPDATE`. The `attributes` merge is done in Python via a `deep_merge_attributes(existing: dict, incoming: dict) -> dict` function in `entity_store.py`, as Postgres has no built-in temporal JSONB merge that handles the array-append-per-source-key pattern. The upsert flow:

```python
async def upsert_entity(org_id, target_id, entity_type, entity_value, new_attributes,
                        raw_event_id, discovery_session_id=None, discovery_run_id=None,
                        discovery_pivot_id=None) -> tuple[UUID, bool]:
    """Returns (entity_id, is_first_discovery).
    
    Exactly one of discovery_run_id or discovery_pivot_id must be non-null.
    Pivot-discovered entities pass discovery_pivot_id, runner-discovered pass discovery_run_id.
    """
    existing = await fetch_existing_entity(org_id, target_id, entity_type, entity_value)
    if existing:
        merged_attrs = deep_merge_attributes(existing["attributes"], new_attributes)
        await db.execute("""
            UPDATE entities SET
                last_seen_at = NOW(),
                attributes = $1::jsonb
            WHERE id = $2
        """, json.dumps(merged_attrs), existing["id"])
        # Link the new raw event to this existing entity
        await db.execute("""
            INSERT INTO entity_raw_event_links (entity_id, raw_event_id)
            VALUES ($1, $2) ON CONFLICT DO NOTHING
        """, existing["id"], raw_event_id)
        return existing["id"], False  # is_first_discovery = False
    else:
        entity_id = await db.execute("""
            INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes,
                                  first_seen_at, last_seen_at,
                                  is_first_discovery, discovery_session_id,
                                  discovery_run_id, discovery_pivot_id)
            VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW(), TRUE, $6, $7, $8)
            RETURNING id
        """, org_id, target_id, entity_type, entity_value,
            json.dumps(new_attributes),
            discovery_session_id, discovery_run_id, discovery_pivot_id)
        # Link the raw event
        await db.execute("""
            INSERT INTO entity_raw_event_links (entity_id, raw_event_id)
            VALUES ($1, $2)
        """, entity_id, raw_event_id)
        return entity_id, True  # is_first_discovery = True
```

This ensures `last_seen_at` is always current, attributes accumulate over time without clobbering, and raw_event_ids track provenance.

### entity_relationships (new)

```sql
CREATE TABLE entity_relationships (
    id                     UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id                 TEXT NOT NULL REFERENCES organizations(id),
    source_entity_id       UUID NOT NULL REFERENCES entities(id),
    target_entity_id       UUID NOT NULL REFERENCES entities(id),
    relationship_type      TEXT NOT NULL,        -- owns, resolves_to, issued_for, san_contains, lookalike_of, etc.
    relationship_source    TEXT NOT NULL,        -- runner_direct, correlation, pivot
    evidence_raw_event_id  UUID REFERENCES raw_events(id),  -- nullable
    runner                 TEXT,                 -- nullable; which runner if runner_direct
    first_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(org_id, source_entity_id, target_entity_id, relationship_type)
);
CREATE INDEX idx_er_org ON entity_relationships (org_id);
CREATE INDEX idx_er_source ON entity_relationships (source_entity_id);
CREATE INDEX idx_er_target ON entity_relationships (target_entity_id);
CREATE INDEX idx_er_type ON entity_relationships (relationship_type);
```

Relationship upsert uses `ON CONFLICT DO UPDATE SET last_seen_at = NOW()`.

### entity_raw_event_links (new)

Join table linking entities to their originating raw events, with proper `ON DELETE CASCADE` for GC cleanup.

```sql
CREATE TABLE entity_raw_event_links (
    entity_id    UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    raw_event_id UUID NOT NULL REFERENCES raw_events(id) ON DELETE CASCADE,
    PRIMARY KEY (entity_id, raw_event_id)
);
```

When raw_events are deleted by GC, `ON DELETE CASCADE` removes the link row. A GC post-cleanup step removes entities with zero remaining links.

### pivot_queue (new)

```sql
CREATE TABLE pivot_queue (
    id               UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id           TEXT NOT NULL REFERENCES organizations(id),
    target_id        TEXT NOT NULL,
    entity_type      TEXT NOT NULL,
    entity_value     TEXT NOT NULL,
    entity_id        UUID NOT NULL REFERENCES entities(id),
    pivot_type       TEXT NOT NULL,              -- via name from allowed_pivots config
    depth            INTEGER NOT NULL,           -- incremented from parent entity
    parent_entity_id UUID REFERENCES entities(id),
    discovery_session_id UUID,                  -- propagated from parent run/entity
    status           TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed, skipped_covered
    enqueued_at      TIMESTAMPTZ DEFAULT NOW(),
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    run_id           UUID REFERENCES runs(id),
    error_message    TEXT,
    skip_reason      TEXT                        -- 'covered_by_apex:<apex_pivot_id>' etc.
);
CREATE INDEX idx_pq_org ON pivot_queue (org_id);
CREATE INDEX idx_pq_status ON pivot_queue (status) WHERE status = 'pending';
CREATE INDEX idx_pq_entity ON pivot_queue (org_id, entity_type, entity_value);
CREATE INDEX idx_pq_cooldown ON pivot_queue (org_id, entity_type, entity_value, pivot_type, completed_at);
```

### runs (modified)

```sql
ALTER TABLE runs ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default' REFERENCES organizations(id);
ALTER TABLE runs ADD COLUMN new_entity_count INTEGER DEFAULT 0;
ALTER TABLE runs ADD COLUMN total_entity_count INTEGER DEFAULT 0;
ALTER TABLE runs ADD COLUMN discovery_session_id UUID;
CREATE INDEX idx_runs_org ON runs (org_id);
```

### Attributes Enrichment Strategy

Entity attributes follow a temporal versioning pattern to preserve history:

```json
{
  "shodan": [
    {"observed_at": "2026-05-14T08:00:00Z", "ports": [80, 443, 8080], "hostnames": ["web.corp.com"]},
    {"observed_at": "2026-05-16T08:00:00Z", "ports": [443], "hostnames": ["web.corp.com"]}
  ]
}
```

`deep_merge_attributes` is a custom function that:
1. For top-level source keys (e.g., "shodan"), appends new observations as array entries
2. For non-source keys, performs standard dict merge (latest wins)

This preserves the full enrichment timeline for investigation without losing data.

---

## Entity Normalization Contract

`normalize_entity_value(entity_type: str, value: str) -> str` lives in `src/easm/entity_store.py` and is the single normalization function. Rules:

| entity_type | Normalization |
|---|---|
| `domain` | Lowercase, strip trailing dot, strip whitespace |
| `hostname` | Lowercase, strip trailing dot, strip whitespace |
| `ip` | Strip whitespace |
| `ip_range` | Strip whitespace |
| `certificate` | SHA-256 of canonicalized certificate data |
| `asn` | Uppercase, ensure `AS` prefix (add if missing), strip whitespace. Canonical form: `AS12345` |
| `org` | Strip whitespace only. Store raw RDAP registrant string as-is — no title case or other transformation. **Org entities are not suitable for automated pivot triggers in v1.** RDAP registrant name formatting is inconsistent across registrars. A fuzzy matching strategy for org dedup and pivot qualification is deferred to v2. The `org` entity type exists to store attribution data; no `allowed_pivots` entry should use `from: org` in v1. |

This function is the contract the future global entity registry depends on. Any parser or handler producing entity values MUST route through this function.

---

## Parser Layer

### BaseParser

```python
class BaseParser(ABC):
    source_name: str
    current_version: int = 1
    
    @property
    def parsed_by(self) -> str:
        return f"{self.source_name}:{self.current_version}"
    
    @abstractmethod
    async def parse(self, raw_event: RawEvent) -> ParseResult:
        """Parse a single raw event into entities and relationships."""
```

### ParseResult

```python
@dataclass
class EntityCandidate:
    entity_type: str
    value: str  # raw, will be normalized by entity_store on insert
    attributes: dict
    
@dataclass
class RelationshipCandidate:
    source_type: str
    source_value: str
    target_type: str
    target_value: str
    relationship_type: str
    relationship_source: str   # 'runner_direct' | 'correlation' | 'pivot'
    evidence_raw_event_id: UUID | None = None
    runner: str | None = None

@dataclass
class ParseResult:
    entities: list[EntityCandidate]
    relationships: list[RelationshipCandidate]
    unparseable: bool = False
    parse_error: str | None = None
```

### Parser Registry

```python
PARSER_REGISTRY = {
    "subfinder": SubfinderParser,
    "asnmap": AsnmapParser,
    "certstream": CertStreamParser,
    "crtsh": CrtShParser,
    "dnstwist": DnstwistParser,
}
```

### Backfill Loop

```
while running:
    batch = SELECT * FROM raw_events
            WHERE parsed_at IS NULL
            ORDER BY collected_at
            LIMIT $batch_size
    
    if empty batch:
        -- Also check for version-bump re-parses (smaller batch, lower priority)
        batch = SELECT * FROM raw_events re
                JOIN LATERAL (
                    SELECT $versions[source] AS current_ver
                ) v ON true
                WHERE re.parsed_at IS NOT NULL
                  AND re.parsed_by IS DISTINCT FROM re.source || ':' || v.current_ver
                ORDER BY re.collected_at
                LIMIT $batch_size
        if empty batch: sleep(interval), continue
    
    new_entities_by_target: dict[str, set[(str, str)]] = defaultdict(set)
    
    for event in batch:
        parser = PARSER_REGISTRY[event.source]
        result = await parser.parse(event)
        
        if result.unparseable:
            UPDATE raw_events SET parsed_at=NOW(), parsed_by=parser.parsed_by,
                parse_error=result.parse_error
            continue
        
        # Determine if this is a pivot-originated event (has _meta.session_id in raw)
        is_pivot_event = "_meta" in event.raw
        
        # Extract session_id: from raw._meta if pivot-originated, else from parent run
        session_id = event.raw.get("_meta", {}).get("session_id")
        if not session_id and event.run_id:
            run = await store.get_run(event.run_id)
            session_id = run["discovery_session_id"] if run else None
        
        # Pivot-discovered entities: discovery_pivot_id set, discovery_run_id NULL
        # Runner-discovered entities: discovery_run_id set, discovery_pivot_id NULL
        pivot_job_id = event.raw.get("_meta", {}).get("pivot_job_id")
        discovery_run_id = event.run_id if not is_pivot_event else None
        discovery_pivot_id = UUID(pivot_job_id) if is_pivot_event and pivot_job_id else None
        
        for entity_candidate in result.entities:
            entity_id = await entity_store.upsert_entity(
                target_id=event.target_id,
                entity_type=entity_candidate.entity_type,
                entity_value=entity_candidate.value,
                new_attributes=entity_candidate.attributes,
                raw_event_id=event.id,
                discovery_session_id=session_id,
                discovery_run_id=event.run_id,
            )
            new_entities_by_target[event.target_id].add(
                (entity_candidate.entity_type, entity_candidate.value, entity_id)
            )
        
        for rel_candidate in result.relationships:
            await entity_store.upsert_relationship(
                target_id=event.target_id,
                source_type=rel_candidate.source_type,
                source_value=rel_candidate.source_value,
                target_type=rel_candidate.target_type,
                target_value=rel_candidate.target_value,
                relationship_type=rel_candidate.relationship_type,
                relationship_source=rel_candidate.relationship_source,
                evidence_raw_event_id=rel_candidate.evidence_raw_event_id,
                runner=rel_candidate.runner,
            )
        
        UPDATE raw_events SET parsed_at=NOW(), parsed_by=parser.parsed_by
    
    # Trigger pivot resolver per batch, per target
    for target_id, entities in new_entities_by_target.items():
        target = get_target_config(target_id)
        for (entity_type, entity_value, entity_id) in entities:
            await pivot_resolver.check_and_enqueue(
                target=target,
                entity_type=entity_type,
                entity_value=entity_value,
                entity_id=entity_id,
                discovery_session_id=session_id,
            )
    
    await asyncio.sleep(batch_interval)
```

The version-bump re-parse pass uses a dict mapping each source name to its parser's `current_version`, constructed from `PARSER_REGISTRY` at loop start. This handles the case where only one parser's version changed — other sources' events are unaffected.

Batch size and interval are configurable:
```yaml
backfill:
  batch_size: 100
  batch_interval_ms: 500
```

---

## Pivot Engine

### Config Shape

```yaml
targets:
  - id: corp-primary
    org_id: default            # org this target belongs to
    pivot:
      enabled: true
      max_depth: 3
      max_concurrent: 3
      batch_interval_ms: 200
      scope_mode: strict           # strict | permissive | log_only
      allowed_pivots:
        - from: domain
          to: certificate
          via: crtsh_search
          cooldown_hours: 24
          coverage:
            apex_covers_subdomains: true
        - from: domain
          to: domain
          via: subdomain_enum
          cooldown_hours: 8
          coverage:
            apex_covers_subdomains: true
        - from: domain
          to: org
          via: domain_rdap
          cooldown_hours: 720
        - from: asn
          to: ip_range
          via: rdap_lookup
          cooldown_hours: 168
        - from: hostname
          to: ip
          via: dns_resolve
          cooldown_hours: 0        # no cooldown, resolve every time
        - from: ip
          to: enrichment
          via: shodan_enrich
          cooldown_hours: 168
        - from: ip_range
          to: ip
          via: reverse_dns
          cooldown_hours: 168
```

### Scope Evaluator

```python
class ScopeEvaluator:
    def evaluate(self, target: TargetConfig, entity_type: str, entity_value: str) -> ScopeResult:
        if entity_type == "domain":
            for suffix in target.match_rules.domains:
                if entity_value.endswith("." + suffix) or entity_value == suffix:
                    return ScopeResult.IN_SCOPE
            return ScopeResult.OUT_OF_SCOPE
        
        if entity_type == "asn":
            normalized = normalize_entity_value("asn", entity_value)
            configured = [normalize_entity_value("asn", a) for a in target.match_rules.asns]
            return ScopeResult.IN_SCOPE if normalized in configured else ScopeResult.OUT_OF_SCOPE
        
        if entity_type in ("ip", "ip_range"):
            import ipaddress
            parsed = ipaddress.ip_network(entity_value, strict=False)
            for cidr_str in target.match_rules.ip_ranges or []:
                cidr = ipaddress.ip_network(cidr_str, strict=False)
                if parsed.subnet_of(cidr):
                    return ScopeResult.IN_SCOPE
            return ScopeResult.OUT_OF_SCOPE
        
        if entity_type == "hostname":
            # A hostname is in scope if its domain suffix matches
            for suffix in target.match_rules.domains:
                if entity_value.endswith("." + suffix) or entity_value == suffix:
                    return ScopeResult.IN_SCOPE
            return ScopeResult.OUT_OF_SCOPE
        
        return ScopeResult.UNKNOWN
```

### Pivot Resolver (check_and_enqueue)

```python
async def check_and_enqueue(target: TargetConfig, entity_type: str, entity_value: str,
                            entity_id: UUID, parent_entity_id: UUID | None = None,
                            depth: int = 1, discovery_session_id: UUID | None = None):
    pivot_config = target.pivot
    if not pivot_config or not pivot_config.enabled:
        return
    if depth > pivot_config.max_depth:
        return
    
    scope = scope_evaluator.evaluate(target, entity_type, entity_value)
    if scope == ScopeResult.OUT_OF_SCOPE and pivot_config.scope_mode == "strict":
        return
    
    for pivot_rule in pivot_config.allowed_pivots:
        if pivot_rule.from_ != entity_type:
            continue
        
        # Coverage check: if apex_covers_subdomains and this is a subdomain,
        # check if apex already has a completed pivot of this type within cooldown.
        # Scoped by org_id so shared domains across targets don't re-trigger.
        if pivot_rule.coverage and pivot_rule.coverage.apex_covers_subdomains:
            if entity_type == "domain":
                apex = tldextract.extract(entity_value).registered_domain
                if apex != entity_value:
                    covered = await check_apex_coverage(target.org_id, apex, pivot_rule.via, pivot_rule.cooldown_hours)
                    if covered:
                        await insert_pivot_skipped(target.org_id, target.id, entity_type, entity_value, pivot_rule.via,
                                                   skip_reason=f"covered_by_apex:{apex}")
                        continue
        
        # Cooldown check (org-scoped)
        if pivot_rule.cooldown_hours > 0:
            recent = await check_cooldown(target.org_id, entity_type, entity_value, pivot_rule.via, pivot_rule.cooldown_hours)
            if recent: continue
        
        await enqueue_pivot_job(
            org_id=target.org_id,
            target_id=target.id,
            entity_type=entity_type,
            entity_value=entity_value,
            entity_id=entity_id,
            pivot_type=pivot_rule.via,
            depth=depth,
            parent_entity_id=parent_entity_id,
            discovery_session_id=discovery_session_id,
        )
```

### Coverage Check

Coverage is org-scoped: if any target within the same org already completed a pivot of the same type on the apex domain, all targets in that org skip it. This prevents duplicate API calls when multiple targets share domains.

```python
async def check_apex_coverage(org_id, apex, pivot_type, cooldown_hours):
    return await db.fetchval("""
        SELECT 1 FROM pivot_queue
        WHERE org_id = $1
          AND entity_value = $2
          AND pivot_type = $3
          AND status = 'completed'
          AND completed_at > NOW() - ($4 || ' hours')::INTERVAL
        LIMIT 1
    """, org_id, apex, pivot_type, cooldown_hours)
```

### Pivot Worker Pool

```python
async def pivot_worker_pool(n: int, store: Store):
    # Startup: reset any orphaned 'running' jobs
    await store.reset_orphaned_pivot_jobs()
    
    async with asyncio.TaskGroup() as tg:
        for _ in range(n):
            tg.create_task(pivot_worker_loop(store))

async def pivot_worker_loop(store: Store, entity_store: EntityStore):
    while True:
        job = await store.dequeue_pivot_job()  # FOR UPDATE SKIP LOCKED LIMIT 1
        if job:
            try:
                await store.mark_pivot_running(job.id)
                handler = PIVOT_HANDLER_REGISTRY[job.pivot_type]
                results = await handler.execute(job.target, job.entity_value)
                
                # Insert raw events with _meta for session propagation.
                # Parsing is deferred to the backfill loop — unified parse path.
                handler = PIVOT_HANDLER_REGISTRY[job.pivot_type]
                results = await handler.execute(job.target, job.entity_value)
                
                for raw_result in results:
                    raw_with_meta = {"_meta": {"session_id": str(job.discovery_session_id),
                                               "pivot_job_id": str(job.id)},
                                     **raw_result} if job.discovery_session_id else raw_result
                    
                    await store.insert_raw_event(
                        org_id=job.org_id,
                        target_id=job.target_id,
                        source=handler.source_name,
                        raw=raw_with_meta,
                        run_id=job.run_id,
                    )
                
                await store.mark_pivot_completed(job.id)
            except Exception as e:
                await store.mark_pivot_failed(job.id, str(e))
        else:
            await asyncio.sleep(batch_interval_ms / 1000)
```

### Pivot Handlers

| via | Handler | Implementation |
|---|---|---|
| `dns_resolve` | DnsResolveHandler | `socket.getaddrinfo()` — resolves hostname to IPs |
| `rdap_lookup` | RdapLookupHandler | HTTP to `rdap.arin.net` / `rdap.db.ripe.net` — ASN to IP ranges |
| `crtsh_search` | CrtShSearchHandler | HTTP to `crt.sh/?q=%.{domain}&output=json` |
| `shodan_enrich` | ShodanEnrichHandler | HTTP to `internetdb.shodan.io/{ip}` — ports, hostnames, CVEs |
| `reverse_dns` | ReverseDnsHandler | `dns.reversename` + `dns.resolver.resolve` (dnspython) for PTR lookups. No subprocess. |
| `domain_rdap` | DomainRdapHandler | HTTP to RDAP for domain → org mapping |
| `subdomain_enum` | SubdomainEnumHandler | Shells out to subfinder against discovered domain |

Pivot handlers that make HTTP calls share a rate-limited `httpx.AsyncClient`. Rate limits are configured per handler type.

---

## New Runners

### crt.sh API Runner

- `source_name = "crtsh"`, `supports_schedule = True`, `is_api_runner = True`
- Impements `BaseRunner` (not `PivotHandler` — scheduled, not event-triggered)
- For each `target.match_rules.domains`, calls `https://crt.sh/?q=%.{domain}&output=json`
- Respects rate limiting (configurable delay between requests)
- Inserts each cert record as a raw JSONB event
- Parsed by `CrtShParser` into `certificate` and `domain` entities

### DNSTwist Runner

- `source_name = "dnstwist"`, `supports_schedule = True`, `is_continuous = False`
- Shells out to `dnstwist` binary against `target.match_rules.domains` apex domains only
- Does NOT feed the pivot engine — standalone monitoring track
- Captures registered lookalike domain permutations
- Config supports: algorithm selection, `only_registered` flag, schedule

### DNSTwist Parser

Produces `domain` entities with `attributes.dnstwist` enrichment and `lookalike_of` relationships:

```python
class DnstwistParser(BaseParser):
    source_name = "dnstwist"
    current_version = 1
    
    async def parse(self, raw_event: RawEvent) -> ParseResult:
        data = raw_event.raw
        lookalike_domain = data.get("domain")        # e.g. exampl3.com
        original_domain = data.get("original_domain") # e.g. example.com
        permutation_type = data.get("type")           # e.g. homoglyph, addition, omission
        
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="domain",
                    value=lookalike_domain,
                    attributes={"dnstwist": {
                        "permutation_type": permutation_type,
                        "original_domain": original_domain,
                        "dns_records": data.get("dns", {}),
                        "is_registered": data.get("registered", False),
                    }},
                ),
            ],
            relationships=[
                RelationshipCandidate(
                    source_type="domain", source_value=lookalike_domain,
                    target_type="domain", target_value=original_domain,
                    relationship_type="lookalike_of",
                    relationship_source="runner_direct",
                    runner="dnstwist",
                ),
            ] if original_domain else [],
        )
```

A `lookalike_of` relationship points from the lookalike domain entity back to the original apex domain entity. Direction: `source_entity_id` = suspicious lookalike domain, `target_entity_id` = legitimate original domain. This reversed ownership semantics means "lookalike is impersonating original" rather than "source owns target." Graph traversal queries must account for this — filtering by `relationship_type = 'lookalike_of'` returns impersonation edges specifically. The original domain entity must already exist in `entities` (created by another runner's parser) for the FK to resolve — parsers should look up the original domain's entity_id before inserting the relationship.

---

## Delta Detection

### Approach

Delta detection is a query layer over `entities.first_seen_at` and `entities.last_seen_at`. No new tables needed beyond the columns already on `entities` and `runs`.

### Discovery Session

Each scheduled/manual run creates a `discovery_session_id`. All pivot jobs triggered downstream share the same session ID. This makes delta queries precise despite async pivot timing:

```sql
-- All entities first discovered in session X (including pivot cascade)
SELECT * FROM entities WHERE discovery_session_id = $session_id;
```

### Run Counters

At run finish, the store computes:
- `new_entity_count`: `COUNT(*) FROM entities WHERE discovery_session_id = $session_id AND is_first_discovery = TRUE` (entities discovered for the first time during this session, including pivot cascade)
- `total_entity_count`: `COUNT(*) FROM entities WHERE discovery_session_id = $session_id` (all entities from run + its pivots)

### API Endpoints

```
GET /entities?target_id={id}&first_seen_since={ts}&last_seen_before={ts}&entity_type={type}&new_since_run_id={id}&limit=50&cursor={cursor}
```

Filters:
- `first_seen_since` — entities newer than timestamp
- `last_seen_before` — entities NOT seen recently (stale/possibly decommissioned)
- `new_since_run_id` — entities first seen after that run's start time
- `entity_type` — filter by type

Response includes `is_first_discovery: boolean` (from the entity column), allowing consumers to distinguish new entities from updates.

---

## Operational Hardening

### Config Hot-Reload

**POST /config/reload**

1. Read and re-validate YAML with Pydantic
2. Diff old vs new targets: added targets get scheduler jobs, removed targets get jobs deleted, modified targets get jobs replaced
3. Persist new `config_snapshots` row
4. Update in-memory config singleton
5. Return diff summary (added, removed, modified targets)

### Run Garbage Collection

```yaml
retention:
  raw_events_days: 90       # default
  runs_days: 365            # default
  per_target: {}            # target-level overrides
```

A scheduled cleanup job (daily) deletes:
- `raw_events` where `collected_at < NOW() - INTERVAL '{raw_events_days} days'`
- `runs` where `finished_at < NOW() - INTERVAL '{runs_days} days'` and status in ('completed', 'failed')

Cascading deletes: `raw_events` deletion cascades to related `entity_relationships` references; entities are soft-checked (orphaned entities with all raw_event_ids deleted are also removed).

### Certstream Gap Detection

Store websocket connect/disconnect events in `run.metadata` JSONB. Expose gap windows in `GET /runs` response:
```json
{
  "gap_windows": [
    {"disconnected_at": "2026-05-15T03:00:00Z", "reconnected_at": "2026-05-15T03:01:30Z", "duration_ms": 90000}
  ]
}
```

### Startup Self-Check

On boot, verify `subfinder`, `asnmap`, and `dnstwist` binaries exist and are executable on `$PATH`. Log binary versions (via `--version` or `-h`). Surface in `/healthz`:
```json
{
  "binaries": {
    "subfinder": {"path": "/usr/local/bin/subfinder", "version": "2.6.6", "ok": true},
    "asnmap": {"path": "/usr/local/bin/asnmap", "version": "1.2.0", "ok": true},
    "dnstwist": {"path": "/usr/local/bin/dnstwist", "version": null, "ok": false, "error": "not found on PATH"}
  }
}
```

---

## API Additions

| Method | Path | Description |
|---|---|---|
| GET | `/entities` | Query entities with filters (type, target, first_seen, last_seen, new_since_run) |
| GET | `/entities/{entity_id}` | Single entity detail with attributes |
| GET | `/entities/{entity_id}/relationships` | All relationships for an entity |
| GET | `/graph/{target_id}?depth=3` | Entity graph nodes + edges for visualization |

Response shape:

```json
{
  "target_id": "corp-primary",
  "max_depth": 3,
  "nodes": [
    {
      "id": "uuid",
      "entity_type": "domain",
      "entity_value": "example.com",
      "attributes": {"shodan": [...]},
      "first_seen_at": "2026-05-15T...",
      "last_seen_at": "2026-05-16T...",
      "is_first_discovery": true,
      "depth": 0
    }
  ],
  "edges": [
    {
      "source_id": "uuid",
      "target_id": "uuid",
      "relationship_type": "resolves_to",
      "relationship_source": "pivot",
      "first_seen_at": "2026-05-15T...",
      "last_seen_at": "2026-05-16T..."
    }
  ]
}
```

Query implementation: recursive CTE from seed entities (those with `discovery_run_id` for a target's initial run or entities matching `target.match_rules`) outward to `depth` hops. Results filtered to `org_id` scope.
| POST | `/config/reload` | Hot-reload configuration without restart |
| GET | `/healthz` | Enhanced: adds binary checks |

---

## Notification Layer (Stub — Reserved Contract)

Not implemented in v1. API and config contracts reserved:

```yaml
targets:
  - id: corp-primary
    notifications:
      enabled: false
      interval_seconds: 300
      routing:
        - type: slack_webhook
          webhook_url: "${SLACK_WEBHOOK_URL}"
        - type: splunk_hec
          hec_url: "${SPLUNK_HEC_URL}"
          hec_token: "${SPLUNK_HEC_TOKEN}"
      filters:
        entity_types: [domain, certificate, ip]
        # Severity classification is part of the notification layer implementation (v2).
        # Not reserved in v1 — entity model has no severity field.
```

The notifier will poll `GET /entities?first_seen_since={last_poll_time}` on its interval and route new entities to configured destinations.

---

## Schema Migration Plan

### 0002 — Multitenancy + Entity Layer

- `CREATE TABLE organizations` with default 'default' row
- `ALTER TABLE raw_events ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`
- `ALTER TABLE raw_events ADD COLUMN parsed_at, parsed_by, parse_error`
- `ALTER TABLE runs ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`
- `CREATE TABLE entities` (with org_id, is_first_discovery, discovery_session_id, discovery_run_id, discovery_pivot_id)
- `CREATE TABLE entity_relationships` (with org_id)
- `CREATE TABLE entity_raw_event_links` (join table with ON DELETE CASCADE)
- Add FK constraints on org_id columns

### 0003 — Pivot Engine

- `CREATE TABLE pivot_queue` (with org_id, discovery_session_id)

### 0004 — Delta Counters

- `ALTER TABLE runs ADD COLUMN new_entity_count, total_entity_count, discovery_session_id`

### 0004 — GC Support

- Add cascading FK constraints for retention cleanup (already present on `entity_raw_event_links`; add to remaining tables as needed)

---

## Testing Strategy

- **Parser tests**: Each parser tested with real sample output from its runner. Verify entity values are normalized, relationship types are correct, unparseable events produce `parse_error`.
- **Entity store tests**: Verify upsert merges attributes correctly, `last_seen_at` updates on conflict, `raw_event_ids` accumulate without duplicates.
- **Pivot resolver tests**: Mock pivot queue, test coverage skip logic, cooldown logic, scope evaluation.
- **Pivot worker tests**: Mock handlers, test dequeue/skip-locked/concurrency, orphaned job recovery.
- **Integration test**: Full flow — schedule a run, backfill parses it, pivot resolver enqueues, pivot worker executes, delta query returns correct counts.
- **Config hot-reload test**: Modify config.yaml, POST /config/reload, verify scheduler picks up new target.
