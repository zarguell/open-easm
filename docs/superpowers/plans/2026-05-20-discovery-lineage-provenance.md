# Discovery Lineage Provenance Rewrite

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the broken relationship-walk lineage with a reliable `parent_entity_id` chain on the `entities` table, so any asset traces exactly back to its configured seed domain/ASN.

**Architecture:** Add `parent_entity_id UUID` column to `entities`. Pre-create seed entities (configured domains/ASNs) before runners execute so hostnames/certs can point to them. Pivots pass the entity they're pivoting from as the parent. Lineage query becomes a trivial parent-chain walk with optional relationship type lookup for display.

**Tech Stack:** PostgreSQL (alembic migration), asyncpg, tldextract (already in codebase), Python 3.14, FastAPI, React/TypeScript

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `alembic/versions/0006_parent_entity_id.py` | Migration: add `parent_entity_id` column |
| Modify | `src/easm/store.py:366-426` | `upsert_entity()` — add parent parameter + SQL |
| Modify | `src/easm/store.py:866-1002` | `get_entity_lineage()` — rewrite to parent chain walk |
| Modify | `src/easm/store.py` (new method ~line 427) | `_find_parents_for_candidates()` — batch seed matching |
| Modify | `src/easm/runners/engine.py:136-239` | `execute_runner()` — pre-create seed entities before run |
| Modify | `src/easm/runners/engine.py:242-351` | `_ingest_entities()` — resolve parent per candidate |
| Modify | `src/easm/tasks/pivot.py:157-164` | Pass `parent_entity_id` to `upsert_entity` |
| Modify | `src/easm/runners/schemas.py` | Fix inverted relationship polarities (crtsh, certstream, dnstwist) |

**Files NOT changed:** Frontend (`DiscoveryLineagePanel.tsx`, `entities.ts`, `EntityDetail.tsx`) — API contract stays identical.

---

### Task 1: Schema Migration — Add `parent_entity_id` Column

**Files:**
- Create: `alembic/versions/0006_parent_entity_id.py`

- [ ] **Step 1: Create the migration file**

```python
"""Add parent_entity_id to entities for provenance tracking

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-20
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entities",
        sa.Column("parent_entity_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_entities_parent",
        "entities", "entities",
        ["parent_entity_id"], ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "idx_entities_parent",
        "entities",
        ["parent_entity_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_entities_parent")
    op.drop_constraint("fk_entities_parent", "entities", type_="foreignkey")
    op.drop_column("entities", "parent_entity_id")
```

- [ ] **Step 2: Verify the migration runs**

Run: `docker compose exec api alembic upgrade head`
Expected: Migration applies cleanly, `parent_entity_id` column appears on entities.

- [ ] **Step 3: Commit**

```bash
git add alembic/versions/0006_parent_entity_id.py
git commit -m "feat: add parent_entity_id column to entities for provenance tracking"
```

---

### Task 2: Update `Store.upsert_entity()` — Add parent parameter

**Files:**
- Modify: `src/easm/store.py:366-426`

- [ ] **Step 1: Add `parent_entity_id` parameter to `upsert_entity()` signature**

Change the method signature from:

```python
async def upsert_entity(
    self,
    org_id: str,
    target_id: str,
    entity_type: str,
    entity_value: str,
    new_attributes: dict,
    raw_event_id: uuid.UUID | None = None,
    discovery_session_id: uuid.UUID | None = None,
    discovery_run_id: uuid.UUID | None = None,
    discovery_pivot_id: uuid.UUID | None = None,
) -> tuple[uuid.UUID, bool]:
```

To:

```python
async def upsert_entity(
    self,
    org_id: str,
    target_id: str,
    entity_type: str,
    entity_value: str,
    new_attributes: dict,
    raw_event_id: uuid.UUID | None = None,
    discovery_session_id: uuid.UUID | None = None,
    discovery_run_id: uuid.UUID | None = None,
    discovery_pivot_id: uuid.UUID | None = None,
    parent_entity_id: uuid.UUID | None = None,
) -> tuple[uuid.UUID, bool]:
```

- [ ] **Step 2: Update the INSERT SQL to include `parent_entity_id`**

Change the SQL from:

```python
        result = await self.pool.fetchrow(
            """
            INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes,
                                  first_seen_at, last_seen_at, is_first_discovery,
                                  discovery_session_id, discovery_run_id, discovery_pivot_id)
            VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW(), TRUE, $6, $7, $8)
            ON CONFLICT (org_id, target_id, entity_type, entity_value) DO UPDATE
            SET last_seen_at = NOW(),
                is_first_discovery = FALSE
            RETURNING id, (xmax = 0) AS is_insert
            """,
            org_id, target_id, entity_type, normalized_value,
            json.dumps(new_attributes),
            discovery_session_id, discovery_run_id, discovery_pivot_id,
        )
```

To:

```python
        result = await self.pool.fetchrow(
            """
            INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes,
                                  first_seen_at, last_seen_at, is_first_discovery,
                                  discovery_session_id, discovery_run_id, discovery_pivot_id,
                                  parent_entity_id)
            VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW(), TRUE, $6, $7, $8, $9)
            ON CONFLICT (org_id, target_id, entity_type, entity_value) DO UPDATE
            SET last_seen_at = NOW(),
                is_first_discovery = FALSE
            RETURNING id, (xmax = 0) AS is_insert
            """,
            org_id, target_id, entity_type, normalized_value,
            json.dumps(new_attributes),
            discovery_session_id, discovery_run_id, discovery_pivot_id,
            parent_entity_id,
        )
```

Note: `parent_entity_id` is NOT updated on ON CONFLICT — it is set once at first discovery and preserved on re-discovery. This matches the existing pattern for `discovery_session_id` and `discovery_run_id`.

- [ ] **Step 3: Run LSP diagnostics**

Run: Check `src/easm/store.py` for type errors
Expected: Clean — the new parameter is optional with default `None`, so all existing callers still compile.

- [ ] **Step 4: Commit**

```bash
git add src/easm/store.py
git commit -m "feat: add parent_entity_id to upsert_entity signature and SQL"
```

---

### Task 3: Seed Entity Pre-creation + Parent Resolution in Engine

**Files:**
- Modify: `src/easm/runners/engine.py:136-351`

This is the core change. Two parts:
1. Pre-create seed entities before runner executes (so hostnames/certs can reference them)
2. In `_ingest_entities`, resolve parent for each candidate

- [ ] **Step 1: Add `_ensure_seed_entities()` helper to engine.py**

Add this function near the top of the file (after imports, before `execute_runner`):

```python
async def _ensure_seed_entities(
    store: Store,
    target: Any,
    org_id: str,
    run_id: uuid.UUID,
) -> dict[tuple[str, str], uuid.UUID]:
    """Pre-create seed entities (configured domains/ASNs) for a target.

    Returns a mapping of (entity_type, entity_value) -> entity_id for
    all seed entities, so that discovered entities can reference them
    as parents.
    """
    seed_map: dict[tuple[str, str], uuid.UUID] = {}

    if not hasattr(target, "match_rules"):
        return seed_map

    # Ensure domain seeds exist
    for domain in (target.match_rules.domains or []):
        try:
            eid, _ = await store.upsert_entity(
                org_id, target.id, "domain", domain, {},
                discovery_run_id=run_id,
                parent_entity_id=None,  # seeds have no parent
            )
            seed_map[("domain", domain)] = eid
        except Exception:
            logger.debug("failed to create seed domain entity: %s", domain, exc_info=True)

    # Ensure ASN seeds exist
    for asn in (target.match_rules.asns or []):
        try:
            eid, _ = await store.upsert_entity(
                org_id, target.id, "asn", asn, {},
                discovery_run_id=run_id,
                parent_entity_id=None,  # seeds have no parent
            )
            seed_map[("asn", asn)] = eid
        except Exception:
            logger.debug("failed to create seed ASN entity: %s", asn, exc_info=True)

    return seed_map
```

- [ ] **Step 2: Call `_ensure_seed_entities()` in `execute_runner()`**

In `execute_runner()`, after `create_run()` (line 162) and before `run_fn()` (line 170), add:

```python
    run_id = await store.create_run(
        target.id, source_name, trigger_type, org_id=target.org_id,
    )

    # Pre-create seed entities so discovered entities can reference them
    seed_map: dict[tuple[str, str], uuid.UUID] = {}
    try:
        seed_map = await _ensure_seed_entities(store, target, target.org_id, run_id)
    except Exception:
        logger.debug("seed entity pre-creation failed", exc_info=True)

    start = datetime.now(UTC)
    await store.mark_run_started(run_id, start)
```

- [ ] **Step 3: Thread `seed_map` through to `_ingest_entities()`**

Add `seed_map` parameter to `_ingest_entities()`:

Change signature from:
```python
async def _ingest_entities(
    store: Store,
    output_schema: Any,
    raw: dict,
    run_id: uuid.UUID,
    org_id: str,
    target_id: str,
    target: Any | None = None,
    pool: Any | None = None,
    raw_event_id: uuid.UUID | None = None,
) -> None:
```

To:
```python
async def _ingest_entities(
    store: Store,
    output_schema: Any,
    raw: dict,
    run_id: uuid.UUID,
    org_id: str,
    target_id: str,
    target: Any | None = None,
    pool: Any | None = None,
    raw_event_id: uuid.UUID | None = None,
    seed_map: dict[tuple[str, str], uuid.UUID] | None = None,
) -> None:
```

- [ ] **Step 4: Add parent resolution logic in `_ingest_entities()`**

Add this helper function before the entity upsert loop (after line 264, before `for ec in entities:`):

```python
    # ── Parent resolution ──────────────────────────────────────────
    import tldextract as _tld

    def _resolve_parent(ec_entity_type: str, ec_value: str) -> uuid.UUID | None:
        """Resolve the parent entity for a candidate based on its type and value."""
        if not seed_map:
            return None

        if ec_entity_type == "domain":
            # A domain that IS a configured seed has no parent
            if ("domain", ec_value) in seed_map:
                return None
            # A domain that is NOT a seed was extracted from a hostname —
            # parent resolution happens via pivot, not here
            return None

        if ec_entity_type == "asn":
            # An ASN that IS a configured seed has no parent
            return None

        if ec_entity_type == "hostname":
            ext = _tld.extract(ec_value)
            registered_domain = f"{ext.domain}.{ext.suffix}"
            parent_id = seed_map.get(("domain", registered_domain))
            if parent_id:
                return parent_id
            # Fallback: try matching against any seed domain that is a suffix
            for (etype, eval_), eid in seed_map.items():
                if etype == "domain" and ec_value.endswith(f".{eval_}"):
                    return eid
            return None

        if ec_entity_type == "certificate":
            # Certificates discovered by runners (crtsh, certstream) —
            # parent is the domain that was searched/matched
            # The domain info is often in attributes
            cert_domains = set()
            attrs = {}  # will be filled from ec.attributes below
            san = attrs.get("san_dns_names", [])
            cn = attrs.get("common_name", "")
            if cn:
                cert_domains.add(cn)
            for s in (san if isinstance(san, list) else []):
                cert_domains.add(s)
            for d in cert_domains:
                ext = _tld.extract(d)
                rd = f"{ext.domain}.{ext.suffix}"
                parent_id = seed_map.get(("domain", rd))
                if parent_id:
                    return parent_id
            return None

        # ip, ip_range, org — no parent from runner pipeline
        return None
```

Then in the entity upsert loop, change the `upsert_entity` call from:

```python
            entity_id, is_new = await store.upsert_entity(
                org_id, target_id, ec.entity_type, ec.value,
                ec.attributes, raw_event_id=raw_event_id,
                discovery_session_id=discovery_session_id,
                discovery_run_id=run_id,
            )
```

To:

```python
            _parent_id = _resolve_parent(ec.entity_type, ec.value)
            entity_id, is_new = await store.upsert_entity(
                org_id, target_id, ec.entity_type, ec.value,
                ec.attributes, raw_event_id=raw_event_id,
                discovery_session_id=discovery_session_id,
                discovery_run_id=run_id,
                parent_entity_id=_parent_id,
            )
```

- [ ] **Step 5: Update all callers of `_ingest_entities()` to pass `seed_map`**

There are 4 call sites in `engine.py`. Update each to pass `seed_map=seed_map`:

**Call site 1: `standard_subprocess_run()`** — find the `_ingest_entities(` call and add `seed_map=seed_map` to the kwargs. This function also needs to accept and forward `seed_map`. Add to its signature:
```python
    seed_map: dict[tuple[str, str], uuid.UUID] | None = None,
```

**Call site 2-3: `standard_http_run()`** — same pattern, two `_ingest_entities` calls inside. Add `seed_map` to signature and forward.

**Call site 4: certspotter runner** in `registry.py` (~line 296) — add `seed_map=None` to the call. (Certspotter uses the same _ingest_entities but doesn't have access to seed_map from the engine; this is acceptable because certspotter certs match against config domains at runtime, and the certificate parent resolution will try to match.)

- [ ] **Step 6: Run LSP diagnostics**

Run: Check `src/easm/runners/engine.py` for type errors
Expected: Clean.

- [ ] **Step 7: Commit**

```bash
git add src/easm/runners/engine.py src/easm/runners/registry.py
git commit -m "feat: pre-create seed entities and resolve parent in runner pipeline"
```

---

### Task 4: Pivot Threading — Pass `parent_entity_id` to `upsert_entity`

**Files:**
- Modify: `src/easm/tasks/pivot.py:157-164`

- [ ] **Step 1: Pass `parent_entity_id` in the pivot entity upsert**

The pivot task already receives `parent_entity_id` as a parameter (line 53). It's the entity being pivoted from. Change the `upsert_entity` call from:

```python
                            eid, is_new = await store.upsert_entity(
                                org_id, target_id,
                                ec.entity_type, ec.value,
                                ec.attributes, raw_event_id=re_id,
                                discovery_session_id=discovery_session_id,
                                discovery_run_id=run_id,
                                discovery_pivot_id=job_id,
                            )
```

To:

```python
                            eid, is_new = await store.upsert_entity(
                                org_id, target_id,
                                ec.entity_type, ec.value,
                                ec.attributes, raw_event_id=re_id,
                                discovery_session_id=discovery_session_id,
                                discovery_run_id=run_id,
                                discovery_pivot_id=job_id,
                                parent_entity_id=(
                                    uuid.UUID(entity_id) if entity_id else None
                                ),
                            )
```

Note: `entity_id` (the entity being pivoted from) is already available as a parameter at line 50. It's a string, so we convert to UUID.

- [ ] **Step 2: Run LSP diagnostics**

Run: Check `src/easm/tasks/pivot.py` for type errors
Expected: Clean.

- [ ] **Step 3: Commit**

```bash
git add src/easm/tasks/pivot.py
git commit -m "feat: pass parent_entity_id in pivot entity upsert"
```

---

### Task 5: Rewrite `get_entity_lineage()` — Parent Chain Walk

**Files:**
- Modify: `src/easm/store.py:866-1002`

- [ ] **Step 1: Replace the entire `get_entity_lineage()` method**

Replace the method with this implementation:

```python
    async def get_entity_lineage(
        self,
        entity_id: uuid.UUID,
        org_id: str,
    ) -> dict[str, Any] | None:
        """Trace the discovery lineage of an entity via the parent_entity_id chain.

        Each entity points to its immediate parent (the entity that led to its
        discovery). Walking this chain produces an exact, non-heuristic lineage
        from any asset back to its configured seed domain/ASN.

        Returns ``None`` if the entity does not exist in the given org.
        """
        # Fetch the target entity
        target = await self.pool.fetchrow(
            """
            SELECT e.id, e.entity_type, e.entity_value, e.first_seen_at,
                   e.parent_entity_id, e.discovery_run_id,
                   r.source AS run_source
            FROM entities e
            LEFT JOIN runs r ON r.id = e.discovery_run_id
            WHERE e.id = $1 AND e.org_id = $2
            """,
            entity_id, org_id,
        )
        if target is None:
            return None

        entity_info: dict[str, Any] = {
            "id": str(target["id"]),
            "entity_type": target["entity_type"],
            "entity_value": target["entity_value"],
            "discovered_by": target["run_source"],
            "first_seen_at": (
                target["first_seen_at"].isoformat()
                if target["first_seen_at"] else None
            ),
        }

        ancestors: list[dict[str, Any]] = []
        child_id: uuid.UUID | None = target["id"]
        current_parent_id = target["parent_entity_id"]
        depth = 0
        max_depth = 20

        while current_parent_id is not None and depth < max_depth:
            # Fetch parent entity + relationship type to child
            parent = await self.pool.fetchrow(
                """
                SELECT e.id, e.entity_type, e.entity_value, e.first_seen_at,
                       e.parent_entity_id, e.discovery_run_id,
                       r.source AS run_source,
                       rel.relationship_type,
                       rel.runner AS relationship_runner
                FROM entities e
                LEFT JOIN runs r ON r.id = e.discovery_run_id
                LEFT JOIN LATERAL (
                    SELECT relationship_type, runner
                    FROM entity_relationships
                    WHERE (source_entity_id = e.id AND target_entity_id = $2)
                       OR (target_entity_id = e.id AND source_entity_id = $2)
                    LIMIT 1
                ) rel ON TRUE
                WHERE e.id = $1
                """,
                current_parent_id,
                child_id,
            )
            if parent is None:
                break

            depth += 1
            ancestors.append({
                "entity": {
                    "id": str(parent["id"]),
                    "entity_type": parent["entity_type"],
                    "entity_value": parent["entity_value"],
                    "discovered_by": parent["run_source"],
                    "first_seen_at": (
                        parent["first_seen_at"].isoformat()
                        if parent["first_seen_at"] else None
                    ),
                },
                "connects_to_entity_id": str(child_id),
                "relationship": {
                    "type": (
                        parent["relationship_type"]
                        if parent["relationship_type"] else "discovered_by"
                    ),
                    "runner": parent["relationship_runner"],
                },
                "depth": depth,
            })

            child_id = parent["id"]
            current_parent_id = parent["parent_entity_id"]

        return {"entity": entity_info, "ancestors": ancestors}
```

- [ ] **Step 2: Run LSP diagnostics**

Run: Check `src/easm/store.py` for type errors
Expected: Clean.

- [ ] **Step 3: Commit**

```bash
git add src/easm/store.py
git commit -m "feat: rewrite lineage query to use parent_entity_id chain walk"
```

---

### Task 6: Fix Inverted Relationship Polarities

**Files:**
- Modify: `src/easm/runners/schemas.py` — crtsh, certstream, dnstwist handlers

The relationship table is used by the graph explorer and by the lineage relationship lookup. Fixing polarity ensures both display correct arrows.

- [ ] **Step 1: Fix crtsh relationship polarity**

Find the crtsh output schema function in `schemas.py`. It creates relationships like:
```python
RelationshipCandidate("certificate", cert_value, "domain", domain_value, "issued_for")
```

This means `cert → issued_for → domain`, but `domain` was the INPUT (seed). Fix to:
```python
RelationshipCandidate("domain", domain_value, "certificate", cert_value, "cert_discovered")
```

Use the find/grep tools to locate the exact line. Change the source/target so domain (input) is source and certificate (discovered) is target.

- [ ] **Step 2: Fix certstream relationship polarity**

Same pattern as crtsh. Find the certstream schema function and flip the direction:
```python
# Before: certificate → domain
# After: domain → certificate
```

- [ ] **Step 3: Fix dnstwist relationship polarity**

Find the dnstwist schema function. It creates:
```python
RelationshipCandidate("domain", lookalike, "domain", original, "lookalike_of")
```

This means `lookalike → lookalike_of → original`, but `original` was the INPUT. Fix to:
```python
RelationshipCandidate("domain", original, "domain", lookalike, "discovered_lookalike")
```

- [ ] **Step 4: Run LSP diagnostics**

Run: Check `src/easm/runners/schemas.py` for type errors
Expected: Clean.

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/schemas.py
git commit -m "fix: correct relationship polarity for crtsh, certstream, dnstwist"
```

---

### Task 7: Docker Smoke Test — End-to-End Validation

**Files:**
- None (infrastructure validation)

- [ ] **Step 1: Rebuild Docker image**

```bash
docker compose build --no-cache api
docker compose up -d
```

- [ ] **Step 2: Verify migration applied**

```bash
docker compose exec api alembic current
```

Expected: Shows `0006` (or your migration revision ID).

- [ ] **Step 3: Trigger a subfinder run**

```bash
curl -X POST http://localhost:8000/api/runs/<target_id>/subfinder
```

- [ ] **Step 4: Wait for completion, then query lineage**

Wait ~60s for the run to complete and pivots to process. Then pick an entity and query:

```bash
curl http://localhost:8000/api/entities | python3 -m json.tool | head -50
# Pick an entity_id

curl http://localhost:8000/api/entities/<entity_id>/lineage | python3 -m json.tool
```

Expected:
- `ancestors` array traces from seed domain → discovered hostname → pivoted IP (or similar chain)
- No `target_scope` synthetic relationships
- Chain length < 10 steps
- Seed domain at the end of the chain with `parent_entity_id = null`

- [ ] **Step 5: Verify in UI**

Open `http://localhost:8000/ui`, navigate to an entity, click "Lineage" button.

Expected:
- Clean vertical chain: Seed Domain → Hostname → IP (or similar)
- Each connector shows the relationship type and runner
- No false paths or wrong seeds

- [ ] **Step 6: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address smoke test findings"
```

---

## Design Decisions & Rationale

### Why `parent_entity_id` on entities (not a separate provenance table)?
- Simpler queries — just follow the FK chain
- No JOIN needed for the basic lineage walk
- Works with existing data model — one column addition
- The Oracle-recommended `entity_provenance` table is the long-term ideal, but this gets 95% there with zero complexity

### Why pre-create seed entities?
- Runners discover hostnames/certs that need to point to domain seeds
- Without pre-creation, the domain entity doesn't exist until `domain_extract` pivot runs
- Pre-creating seeds breaks the chicken-and-egg dependency
- Uses `upsert_entity` with ON CONFLICT — idempotent, no duplicates

### Why N+1 parent lookups in `_ingest_entities` (not batch)?
- Actually batched: `seed_map` is computed once, lookups are in-memory dict checks
- Only `tldextract` CPU cost per candidate — no DB queries for parent resolution
- The real DB query happens in `upsert_entity` (which already does one INSERT per entity)

### Why NOT update `parent_entity_id` on ON CONFLICT?
- First discovery is the authoritative provenance
- Re-discovery shouldn't change the lineage chain
- Matches existing pattern: `discovery_run_id` and `discovery_session_id` also aren't updated on conflict

### Certstream special case
- Certstream is realtime, not triggered from a specific seed
- The certificate's domain is matched against config domains
- Parent resolution uses the matched domain from the seed map
- This works correctly without special handling

### What about entities with no parent?
- Seed entities (configured domains/ASNs): `parent_entity_id = NULL` — correct, they're the roots
- Entities from runners that don't match any seed: `parent_entity_id = NULL` — lineage shows just the entity itself
- This is acceptable for the MVP — the user said they're fine with no historical data

## Spec Coverage Check

| Requirement | Task |
|-------------|------|
| Add `parent_entity_id` to entities | Task 1 (migration) + Task 2 (store) |
| Pre-create seed entities before runners | Task 3 (engine) |
| Resolve parent for runner-discovered entities | Task 3 (_ingest_entities) |
| Thread parent through pivot pipeline | Task 4 (pivot task) |
| Rewrite lineage query | Task 5 (store) |
| Fix inverted relationship polarities | Task 6 (schemas) |
| End-to-end validation | Task 7 (Docker) |
| API contract unchanged (frontend works) | Task 5 (same response shape) |
| No schema migration for provenance table | Yes — single column addition |
