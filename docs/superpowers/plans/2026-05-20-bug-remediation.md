# Bug Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 7 verified bugs from BACKLOG.md — claimed features that silently produce wrong or empty results.

**Architecture:** Each bug is independent and can be fixed in parallel. Bugs are grouped by difficulty: **Tier 1 (easy, ~15 min each)** can be dispatched to `quick` agents simultaneously. **Tier 2 (medium, ~45 min each)** need `unspecified-high` agents. **Tier 3 (hard, ~2hr each)** need `deep` agents with architecture decisions.

**Tech Stack:** Python 3.14, FastAPI, asyncpg, PostgreSQL, React 18, TypeScript, Pydantic, Docker

**Parallelism Strategy:**

```
Tier 1 (parallel, quick agents):  BUG-04, BUG-05, BUG-07
Tier 2 (parallel, deep agents):   BUG-01, BUG-06
Tier 3 (sequential, deep agents): BUG-02, BUG-03
```

Tier 1 and Tier 2 can all run simultaneously. Tier 3 items should run after Tier 1/2 because BUG-03 may affect the certstream architecture that BUG-02 search will interact with.

---

## Tier 1 — Easy Fixes (Parallel `quick` agents)

---

### Task 1: BUG-04 — Fix Silent-Failing Scanner Runners

**Files:**
- Modify: `Dockerfile:39-98` (worker stage — add gitleaks + dnstwist binaries)
- Modify: `src/easm/runners/commoncrawl_runner.py` (fix hardcoded index)
- Modify: `src/easm/runners/searchengine_runner.py:28-29` (wire API keys from config)
- Read: `src/easm/runners/github_scan_runner.py:55-59` (reference for gitleaks path)

**What's broken:**
- `gitleaks` binary not in Docker image → `github_scan_runner.py:55` calls `gitleaks detect` → `FileNotFoundError` silently caught at line 59
- `dnstwist` binary not in Docker image → same silent failure pattern
- `commoncrawl` hardcodes crawl index `"CC-MAIN-2026-17"` → time-bomb
- `searchengine_runner.py:28-29` has `google_api_key: str = "", bing_api_key: str = ""` as constructor defaults, never wired from config
- `discord_monitor` is a paper feature (`add_message()` never called) — REMOVE it

- [ ] **Step 1: Add gitleaks and dnstwist to Dockerfile worker stage**

Add after the `webanalyze` installation block (around line 75) in the `worker` stage:

```dockerfile
# Install gitleaks
RUN GITLEAKS_VER="v8.24.3" && \
    curl -L "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz" \
    | tar xz -C /usr/local/bin/ gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Install dnstwist
RUN pip install --no-cache-dir dnstwist
```

Note: dnstwist is a Python package, so `pip install dnstwist` is correct. Verify the latest gitleaks version at https://github.com/gitleaks/gitleaks/releases — use whichever is latest.

- [ ] **Step 2: Fix commoncrawl hardcoded index**

Find the hardcoded `"CC-MAIN-2026-17"` or `"2026-17"` string in `src/easm/runners/commoncrawl_runner.py`. Replace with dynamic index resolution:

```python
import datetime

def _get_latest_cc_index() -> str:
    """Return the most recent CommonCrawl index ID (e.g., 'CC-MAIN-2026-17')."""
    now = datetime.datetime.utcnow()
    # CommonCrawl indexes are named CC-MAIN-YYYY-NN where NN is a weekly index
    # Default to current year. The API will return available indexes.
    return f"CC-MAIN-{now.year}-{now.month:02d}"
```

If the runner fetches from `index.commoncrawl.org/collinfo.json`, parse the first entry instead. Read the file to see the actual implementation pattern before deciding.

- [ ] **Step 3: Wire search engine API keys from config**

In `src/easm/runners/searchengine_runner.py`, the constructor takes `google_api_key` and `bing_api_key` as defaults. The caller (in `src/easm/runners/registry.py` or wherever the runner is instantiated) should pass these from the target's runner config.

Check `src/easm/config.py:42` — `RunnerConfig` doesn't have google/bing key fields yet. Add them:

```python
# In RunnerConfig (config.py)
google_api_key: str | None = None
google_cx: str | None = None
bing_api_key: str | None = None
```

Then in the registry where `SearchEngineRunner` is instantiated, pass the config values.

- [ ] **Step 4: Remove discord_monitor paper feature**

Remove `discord_monitor` from:
- `src/easm/config.py:11,19` — remove from `VALID_RUNNER_NAMES` and `SCHEDULABLE_RUNNERS`
- `src/easm/runners/discord_monitor_runner.py` — delete the file
- Any registration in `src/easm/runners/registry.py`
- Any reference in `src/easm/runners/__init__.py`

- [ ] **Step 5: Verify with diagnostics**

Run: `cd /Users/zach/localcode/open-easm && python -c "from easm.config import VALID_RUNNER_NAMES; print(VALID_RUNNER_NAMES)"`
Expected: discord_monitor NOT in the set.

Run: `grep -r "discord_monitor" src/`
Expected: zero matches.

---

### Task 2: BUG-05 — Fix 5 Broken Correlation Rules

**Files:**
- Modify: `correlations/high_risk_port_exposed.yaml`
- Modify: `correlations/stale_certificate.yaml`
- Modify: `correlations/outlier_country.yaml`
- Modify: `correlations/subdomain_takeover_risk.yaml`
- Modify: `correlations/email_in_breach.yaml`
- Read: `src/easm/correlation/engine.py:128-136` (understand `_field_to_sql` for `attributes.*` fields)

**How the engine works:**
- `collect` conditions filter entities from the `entities` table
- `_field_to_sql` maps: `entity_type` → `entity_type`, `entity_value` → `entity_value`, `attributes.X` → `attributes->>'X'`
- Regex patterns use PostgreSQL `~` operator (POSIX regex)
- All conditions are ANDed together

- [ ] **Step 1: Fix `high_risk_port_exposed.yaml`**

The bug: Regex matches on `entity_value` (e.g., `"1.2.3.4"`) which is just an IP address. Ports are stored as separate entities with `entity_type: port` or as attributes on IP entities.

Read the database to understand the data model: entities with port data have `entity_type: port` or `entity_type: service`. The `entity_value` for port entities looks like `"1.2.3.4:3389"` or just `"3389"`.

Fix approach — change to match on port entity type:

```yaml
id: high_risk_port_exposed
meta:
  name: "High-risk port exposed to the internet"
  risk: high
  description: >
    A host was found with a high-risk port open (RDP 3389, SSH 22,
    Telnet 23, MySQL 3306, PostgreSQL 5432, or Redis 6379).
collect:
  - method: exact
    field: entity_type
    value: port
  - method: regex
    field: entity_value
    patterns:
      - "^(3389|22|23|3306|5432|6379)$"
aggregation:
  field: entity_value
  headline: "High-risk port exposed: {entity_value}"
```

IMPORTANT: First verify what entity_type and entity_value port scan results actually use. Read `src/easm/runners/portscan_runner.py` or the portscan output schema to confirm. If port entities use format `"ip:port"` then adjust regex to `":(3389|22|23|3306|5432|6379)$"`.

- [ ] **Step 2: Fix `stale_certificate.yaml`**

The bug: Regex matches `entity_value` (which is a SHA-256 hex fingerprint like `"abc123def456..."`) against `.*expired.*`. Certificate expiry info is in `attributes.not_after` or similar.

Fix approach — match on certificate attributes:

```yaml
id: stale_certificate
meta:
  name: "Stale or expiring TLS certificate"
  risk: medium
  description: >
    A TLS certificate was found that is expired or expiring within
    30 days, increasing the risk of service disruption.
collect:
  - method: exact
    field: entity_type
    value: certificate
aggregation:
  field: entity_value
  headline: "Stale certificate found: {entity_value}"
```

IMPORTANT: The YAML rule format currently only supports `exact` and `regex` on `entity_type`, `entity_value`, and `attributes.*`. Certificate expiry is a date comparison, which the engine doesn't support natively. Two options:
- **Option A (simple):** Remove the broken regex filter entirely. Accept that ALL certificate entities will be collected. Then add a Python-level analysis step or a custom analysis method.
- **Option B (proper):** Add a `date_before` collect method to the correlation engine (`src/easm/correlation/engine.py` and `src/easm/correlation/rule.py`) that compares `attributes.not_after` against `now + 30 days`. This is more work but correct.

Start with Option A — remove the broken regex so at least certificates ARE collected. Then the existing `certificate_inventory_to_findings()` (BUG-06) can do the actual expiry analysis.

- [ ] **Step 3: Fix `outlier_country.yaml`**

The bug: Collects ALL IP entities with no country filter. Fires for every IP.

Fix approach — add expected countries to config and filter:

The YAML rule format doesn't support "expected countries" natively. The fix needs to happen at the correlation engine level or the rule needs to use `attributes.geo.country_code` with a NOT-match.

Best approach: Add an `exclude` method to the rule format, or add a negative regex on `attributes.country_code`:

```yaml
id: outlier_country
meta:
  name: "Asset hosted in unexpected country"
  risk: medium
  description: >
    An asset was found hosted in a country not typically associated with
    the organization's infrastructure.
collect:
  - method: exact
    field: entity_type
    value: ip
  - method: regex
    field: attributes.country_code
    patterns:
      # Exclude common expected countries - adjust per organization
      # This is a negative approach: match anything NOT in expected set
      # Unfortunately the engine doesn't support negation natively
aggregation:
  field: entity_value
  headline: "IP in potentially unexpected location: {entity_value}"
```

The real fix requires adding a `not_regex` or `not_in` collect method to the engine. For now, **disable this rule** by setting a condition that can never match (e.g., require `entity_type: ip` AND `entity_type: none`), OR add a `not_regex` method to the engine:

In `src/easm/correlation/rule.py`, add to `CollectMethod` enum:
```python
NOT_REGEX = "not_regex"
```

In `src/easm/correlation/engine.py`, add to `_collect`:
```python
elif cond.method == CollectMethod.NOT_REGEX:
    field_sql = self._field_to_sql(cond.field)
    sub_conditions = []
    for pattern in cond.patterns or []:
        idx += 1
        sub_conditions.append(f"{field_sql} !~ ${idx}::text")
        params.append(pattern)
    conditions.append(f"({' AND '.join(sub_conditions)})")
```

Then the rule becomes:
```yaml
collect:
  - method: exact
    field: entity_type
    value: ip
  - method: regex
    field: attributes.country_code
    patterns:
      - ".+"
  - method: not_regex
    field: attributes.country_code
    patterns:
      - "^US$"
      - "^CA$"
      - "^GB$"
```

This collects IPs that HAVE a country_code but it's NOT in the expected set.

- [ ] **Step 4: Fix `subdomain_takeover_risk.yaml`**

The bug: Collects ALL hostname entities. No pre-filter for takeover-vulnerable patterns.

Fix approach — filter on takeover attributes set by the `subdomain_takeover` handler:

The `subdomain_takeover` handler in `src/easm/pivot/handlers.py:395-438` sets `takeover_risk: true` in the entity attributes when a vulnerability is detected. Filter on that:

```yaml
id: subdomain_takeover_risk
meta:
  name: "Potential subdomain takeover"
  risk: high
  description: >
    A domain or hostname was found with a DNS record pointing to a
    service that may be unclaimed or expired.
collect:
  - method: exact
    field: entity_type
    value: hostname
  - method: regex
    field: attributes.takeover_risk
    patterns:
      - "True"
      - "true"
aggregation:
  field: entity_value
  headline: "Subdomain with takeover indicators: {entity_value}"
```

This only matches hostnames where the takeover handler already flagged them.

- [ ] **Step 5: Fix `email_in_breach.yaml`**

The bug: Depends on breach monitor creating entities with `@` in `entity_value`. Breach monitor only creates raw events, not entities. And even if it did, `entity_type: hostname` values don't contain `@`.

This rule is blocked by BUG-03 pattern (breach monitor entity creation broken). For now, **disable the rule** so it stops producing false negatives / wasting cycles. Add a comment explaining why:

```yaml
id: email_in_breach
meta:
  name: "Organization email found in breach data"
  risk: high
  description: >
    An email address matching the organization was found in breach
    monitoring data. NOTE: This rule is disabled until breach_monitor
    creates email entities (see BUG-03).
  enabled: false
collect:
  - method: exact
    field: entity_type
    value: email
aggregation:
  field: entity_value
  headline: "Email found in breach data: {entity_value}"
```

Check if the correlation engine supports an `enabled` field. If not, change `entity_type` to match a non-existent type so the rule can never fire:

```yaml
collect:
  - method: exact
    field: entity_type
    value: __disabled_breach_monitor_no_entities__
```

- [ ] **Step 6: Verify correlation engine changes**

If you added `not_regex` to the engine, run:
```
python -c "from easm.correlation.rule import CollectMethod; print(list(CollectMethod))"
```
Expected: `NOT_REGEX` should appear.

Run: `grep -r "discord_monitor\|email_in_breach" correlations/`
Expected: email_in_breach is disabled.

---

### Task 3: BUG-07 — Wire Enrichment API Keys from Config

**Files:**
- Modify: `src/easm/config.py:204-208` (add `EnrichmentConfig` section)
- Modify: `src/easm/pivot/handlers.py:444,644,708,748,817` (read keys from config/env)
- Read: `config.yaml.example` (reference for config surface)

**What's broken:**
Six enrichment handlers hardcode `api_key = ""`:
- `passive_dns` (SecurityTrails): line 444
- `shodan_enrich`: line 644
- `abuseipdb_enrich`: line 708
- `greynoise_enrich`: line 748
- `censys_enrich`: lines 817-818 (`api_id` and `api_secret`)

None read from config or environment variables.

- [ ] **Step 1: Add enrichment config to config model**

In `src/easm/config.py`, add a new model:

```python
class EnrichmentKeys(BaseModel):
    """API keys for external enrichment services. Can also be set via environment variables."""
    shodan: str | None = None
    abuseipdb: str | None = None
    greynoise: str | None = None
    censys_id: str | None = None
    censys_secret: str | None = None
    securitytrails: str | None = None
    dehashed: str | None = None
    urlscan: str | None = None
```

Add to `Config` class:
```python
class Config(BaseModel):
    targets: list[TargetConfig]
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    saas_providers: SaasProviderConfig = Field(default_factory=SaasProviderConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    enrichment: EnrichmentKeys = Field(default_factory=EnrichmentKeys)  # NEW
```

- [ ] **Step 2: Create a key resolver utility**

The handlers need a way to get keys. The cleanest approach: a module-level function that resolves key → config → env var.

In `src/easm/pivot/handlers.py`, add at the top:

```python
import os

# Module-level config reference, set during app startup
_enrichment_keys: dict[str, str] = {}

def configure_enrichment_keys(config) -> None:
    """Called once at startup to load enrichment API keys from config."""
    keys = config.enrichment if hasattr(config, 'enrichment') else None
    _enrichment_keys["shodan"] = _resolve_key(keys, "shodan", "SHODAN_API_KEY")
    _enrichment_keys["abuseipdb"] = _resolve_key(keys, "abuseipdb", "ABUSEIPDB_API_KEY")
    _enrichment_keys["greynoise"] = _resolve_key(keys, "greynoise", "GREYNOISE_API_KEY")
    _enrichment_keys["censys_id"] = _resolve_key(keys, "censys_id", "CENSYS_API_ID")
    _enrichment_keys["censys_secret"] = _resolve_key(keys, "censys_secret", "CENSYS_API_SECRET")
    _enrichment_keys["securitytrails"] = _resolve_key(keys, "securitytrails", "SECURITYTRAILS_API_KEY")

def _resolve_key(keys_obj, attr: str, env_var: str) -> str:
    """Resolve API key: config value > environment variable > empty string."""
    config_val = getattr(keys_obj, attr, None) if keys_obj else None
    return config_val or os.environ.get(env_var, "")
```

Then find where handlers are initialized (in `main.py` or `worker.py`) and call `configure_enrichment_keys(config)` at startup.

- [ ] **Step 3: Replace hardcoded empty keys in each handler**

Replace each `api_key = ""` with:

```python
# passive_dns handler
api_key = _enrichment_keys.get("securitytrails", "")

# shodan_enrich handler
api_key = _enrichment_keys.get("shodan", "")

# abuseipdb_enrich handler
api_key = _enrichment_keys.get("abuseipdb", "")

# greynoise_enrich handler
api_key = _enrichment_keys.get("greynoise", "")

# censys_enrich handler
api_id = _enrichment_keys.get("censys_id", "")
api_secret = _enrichment_keys.get("censys_secret", "")
```

- [ ] **Step 4: Update config.yaml.example**

Add enrichment section:
```yaml
enrichment:
  # API keys for external enrichment services.
  # These can also be set via environment variables (shown in comments).
  shodan: "${SHODAN_API_KEY}"          # env: SHODAN_API_KEY
  abuseipdb: "${ABUSEIPDB_API_KEY}"    # env: ABUSEIPDB_API_KEY
  greynoise: "${GREYNOISE_API_KEY}"    # env: GREYNOISE_API_KEY
  censys_id: "${CENSYS_API_ID}"        # env: CENSYS_API_ID
  censys_secret: "${CENSYS_API_SECRET}" # env: CENSYS_API_SECRET
  securitytrails: "${SECURITYTRAILS_API_KEY}" # env: SECURITYTRAILS_API_KEY
```

- [ ] **Step 5: Verify**

Run: `python -c "from easm.config import Config, EnrichmentKeys; print(EnrichmentKeys.model_fields.keys())"`
Expected: `dict_keys(['shodan', 'abuseipdb', 'greynoise', 'censys_id', 'censys_secret', 'securitytrails', 'dehashed', 'urlscan'])`

Run: `grep -n 'api_key = ""' src/easm/pivot/handlers.py`
Expected: zero matches (all replaced with `_enrichment_keys.get(...)`).

---

## Tier 2 — Medium Fixes (Parallel `deep` agents)

---

### Task 4: BUG-01 — Fix Incorrect UI Count Displays

**Files:**
- Modify: `src/easm/store.py:720-730` (remove or raise the 500 cap)
- Modify: `src/easm/store.py:536-556` (fix `_findings_for_entity` 200 cap)
- Modify: `src/easm/store.py` (add `total_count` to list responses)
- Modify: `src/easm/api/routes/assets.py:55-70` (fix export to stream all results)
- Modify: `ui/src/components/dashboard/AssetRiskOverview.tsx` (use count endpoint)
- Modify: `ui/src/components/dashboard/CascadeVisualization.tsx` (use count endpoint)
- Modify: `ui/src/components/GeoMap.tsx` (remove or raise limit)
- Read: `ui/src/hooks/useEntityCounts.ts` (reference for correct pattern)
- Read: `ui/src/components/dashboard/MetricCards.tsx` (reference for correct pattern)

**What's broken:**
- `store.py:730`: `limit = max(1, min(limit, 500))` caps all asset inventory queries at 500
- `store.py:542`: `await self.list_findings(target_id=target_id, limit=200)` caps findings per entity
- `api/routes/assets.py:63`: `limit=500` hardcoded in export
- Frontend components count `results.length` instead of using a proper count

- [ ] **Step 1: Add `total_count` to `list_asset_inventory` response**

In `store.py`, modify `list_asset_inventory` to also return total count. Use the window function pattern already proven in the triage inbox:

```python
async def list_asset_inventory(
    self,
    target_id: str | None = None,
    confidence_level: str | None = None,
    risk_level: str | None = None,
    feed_eligible: bool | None = None,
    limit: int = 100,
    offset: int = 0,
    org_id: str = "default",
) -> dict[str, Any]:  # Changed return type
    effective_limit = max(1, min(limit, 5000))  # Raised from 500 to 5000
    offset = max(0, offset)
    conditions = ["org_id = $1", "attributes ? 'asset_profile'"]
    params: list[Any] = [org_id]
    idx = 2
    # ... existing condition building ...

    query = f"""
        SELECT *, count(*) OVER() as total_count
        FROM entities
        WHERE {' AND '.join(conditions)}
        ORDER BY first_seen_at DESC NULLS LAST
        LIMIT ${idx} OFFSET ${idx + 1}
    """
    params.extend([effective_limit, offset])

    async with self.pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    total = rows[0]["total_count"] if rows else 0
    entities = [self._entity_row_to_dict(r) for r in rows]
    return {"entities": entities, "total_count": total}
```

This is a breaking change for callers — they currently get `list[dict]` and will now get `dict`. Update all callers (API routes, etc.) to use `result["entities"]` and `result["total_count"]`.

- [ ] **Step 2: Fix `_findings_for_entity` to query by entity_id directly**

Instead of fetching ALL findings for a target and filtering in Python (which is both slow and capped), query by entity_id:

```python
async def _findings_for_entity(
    self,
    target_id: str,
    entity_id: uuid.UUID,
) -> list[dict[str, Any]]:
    try:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT * FROM findings
                   WHERE target_id = $1 AND $2 = ANY(entity_ids)
                   ORDER BY created_at DESC""",
                target_id, str(entity_id),
            )
        return [dict(r) for r in rows]
    except Exception:
        logger.debug("finding lookup skipped for asset profile", exc_info=True)
        return []
```

This removes the 200 cap entirely and queries efficiently.

- [ ] **Step 3: Fix asset export to stream all results**

In `src/easm/api/routes/assets.py`, change `export_assets_ndjson` to paginate through all results:

```python
@router.get("/assets/export.ndjson")
async def export_assets_ndjson(
    target_id: str | None = Query(None),
    store: Store = Depends(get_store),
):
    async def generate():
        offset = 0
        batch_size = 1000
        while True:
            result = await store.list_asset_inventory(
                target_id=target_id,
                feed_eligible=True,
                limit=batch_size,
                offset=offset,
                org_id="default",
            )
            entities = result["entities"]
            if not entities:
                break
            for asset in entities:
                yield json.dumps(asset) + "\n"
            if len(entities) < batch_size:
                break
            offset += batch_size

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
    )
```

Add the necessary imports (`json`, `StreamingResponse` from `starlette.responses`).

- [ ] **Step 4: Fix frontend components to use count endpoints**

For `AssetRiskOverview.tsx` and `CascadeVisualization.tsx`:
- Instead of fetching entities and counting array length, use the `useEntityCounts()` hook that `MetricCards.tsx` already uses
- Or add a `total_count` field to the API response (done in Step 1) and use it directly

For `GeoMap.tsx`:
- Remove or significantly raise the `limit: 500`. Consider using a dedicated endpoint that returns only `entity_value` (IP) and geo coordinates, not full entity data.

- [ ] **Step 5: Update all callers of `list_asset_inventory`**

Search for all callers: `grep -rn "list_asset_inventory" src/ ui/src/`

Update each to handle the new return type `{"entities": [...], "total_count": N}` instead of a plain list.

- [ ] **Step 6: Verify**

Run: `grep -n "limit, 500" src/easm/store.py`
Expected: changed to `5000` or removed.

Run: `grep -n "limit=200\|limit: 200" src/easm/store.py`
Expected: zero matches (replaced with direct entity_id query).

---

### Task 5: BUG-06 — Wire Certificate Findings Dead Code

**Files:**
- Read: `src/easm/certificates/findings.py` (the dead-code function)
- Read: `tests/test_assets/test_export.py` (existing tests for reference)
- Modify: `src/easm/correlation/engine.py` or `src/easm/worker.py` or `src/easm/main.py` (wire the function)
- Create: `tests/test_certificates/test_findings_integration.py`

**What's broken:**
`certificate_inventory_to_findings()` in `src/easm/certificates/findings.py` is a well-written, tested function that produces 5 types of certificate findings (expired deployed, expiring soon, weak crypto, expired CT-only, unobserved candidates). It is never called in production.

- [ ] **Step 1: Read the function signature and understand its interface**

Read `src/easm/certificates/findings.py` to understand:
- What parameters it takes (store? pool? target_id?)
- What it returns (list of findings? inserts into DB?)
- What it depends on (certificate entities with what attributes?)

- [ ] **Step 2: Wire it into the correlation engine run cycle**

The best place is in the correlation engine's `evaluate_rules` method, or as a post-correlation step. After all YAML rules run, call `certificate_inventory_to_findings()` for the target.

Alternative: wire it as a scheduled job in the scheduler, running daily or after any certificate-related runner completes.

Look at how the existing correlation rules are invoked (in `src/easm/pivot/worker_legacy.py:410` or wherever `evaluate_rules` is called) and add the certificate findings call right after.

- [ ] **Step 3: Add integration test**

Create a test that:
1. Inserts certificate entities with various states (expired, expiring, valid)
2. Calls the function
3. Verifies it produces the expected findings

- [ ] **Step 4: Verify**

Run: `grep -rn "certificate_inventory_to_findings" src/easm/`
Expected: at least one call site in non-test code.

---

## Tier 3 — Hard Fixes (Sequential `deep` agents)

---

### Task 6: BUG-03 — Fix Certstream Pipeline

**Files:**
- Modify: `src/easm/runners/__init__.py:25` (legacy adapter)
- Modify: `src/easm/runners/engine.py:185-297` (`execute_runner`)
- Read: `src/easm/runners/schemas.py:184-245` (certstream output schema)
- Read: `src/easm/runners/certstream_runner.py` (current implementation)
- Read: `src/easm/main.py:162` (certstream startup)

**What's broken:**
Certstream only inserts raw events. The OUTPUT_SCHEMA at `schemas.py:184` transforms events into entities, but the legacy adapter (`_make_legacy_adapter`) never invokes it. `execute_runner` only invokes output schemas for standard runners, not legacy adapters.

**Architecture decision needed:** Three options (listed in BACKLOG.md BUG-03). The cleanest is Option B — make `execute_runner` invoke `output_schema` when present, even for legacy adapters.

- [ ] **Step 1: Read the standard pipeline to understand how output schemas work**

Read `standard_subprocess_run` and `standard_http_run` in `src/easm/runners/engine.py` to see how they:
1. Run the runner
2. Pass raw output through `output_schema`
3. Insert resulting entities

- [ ] **Step 2: Implement Option B — invoke output_schema in execute_runner**

Modify `execute_runner` to check if the runner has an `output_schema` and if so, process raw events through it after the legacy adapter runs.

The flow should be:
1. Legacy adapter calls `runner.run_once()` → inserts raw events, returns counts
2. After `run_once`, query the newly inserted raw events from this run_id
3. Pass them through `output_schema` to produce entities
4. Insert the entities

Read `src/easm/runners/schemas.py` to understand the output schema function signature.

- [ ] **Step 3: Add diagnostic logging**

Log when certstream entities are created: `"certstream: created N entities from M raw events"`. This makes the fix verifiable in production.

- [ ] **Step 4: Write integration test**

Test that certstream raw events produce entities when the pipeline is fixed.

- [ ] **Step 5: Verify**

Run the certstream runner with test data and confirm entities appear in the graph.

---

### Task 7: BUG-02 — Implement Working Search

**Files:**
- Modify: `src/easm/store.py` (add `q` parameter to list methods)
- Modify: `src/easm/api/routes/entities.py` (add `q` query parameter)
- Modify: `src/easm/api/routes/findings.py` (add `q` query parameter)
- Modify: `ui/src/components/layout/TopBar.tsx` (wire search input)
- Create: `ui/src/components/findings/FindingsView.tsx` (new view for findings)
- Modify: `ui/src/App.tsx` (add FindingsView route)
- Modify: `ui/src/components/alerts/AlertsView.tsx` (add filter controls)

**What's broken:**
- TopBar search is decorative (no handlers)
- No backend text search (`ILIKE` or `tsvector`)
- Findings API exists with filtering but no UI
- AlertsView passes zero filter params to the findings API

This is the largest task. Consider splitting into subtasks:
1. Backend: Add `q` param to entity/finding list queries
2. Frontend: Wire TopBar to search API
3. Frontend: Create FindingsView
4. Frontend: Add filters to AlertsView

- [ ] **Step 1: Add text search to backend list queries**

In `store.py`, add a `q: str | None = None` parameter to `list_entities` and `list_findings`. When provided, add:

```sql
AND (entity_value ILIKE '%' || $N || '%' OR entity_type ILIKE '%' || $N || '%')
```

For `list_findings`, search on `headline` and `rule_id`.

- [ ] **Step 2: Wire `q` parameter through API routes**

Add `q: str | None = Query(None)` to the entity and finding list endpoints. Pass to store methods.

- [ ] **Step 3: Wire TopBar search to entity API**

Add state to TopBar, debounce input, call `/api/entities?q={query}`, show results in a dropdown.

- [ ] **Step 4: Create FindingsView component**

Create `ui/src/components/findings/FindingsView.tsx` that:
- Fetches from `/api/findings` with filters
- Shows filter controls (risk, status, rule_id, q)
- Displays findings in a table with pagination
- Allows status updates (acknowledge/resolve/false_positive)

- [ ] **Step 5: Add filter controls to AlertsView**

Wire the existing `/api/findings` filter params into `AlertsView`:
- Risk filter dropdown (critical/high/medium/low)
- Status filter (open/acknowledged/resolved)
- Pagination

- [ ] **Step 6: Verify**

Open the UI and test:
- Type in TopBar search → results appear
- Navigate to findings view → filters work
- Alerts view → filter dropdowns functional

---

## Execution Order

```
Phase 1 (all parallel):
  Task 1 (BUG-04) → quick agent
  Task 2 (BUG-05) → quick agent
  Task 3 (BUG-07) → quick agent
  Task 4 (BUG-01) → deep agent
  Task 5 (BUG-06) → deep agent

Phase 2 (after Phase 1):
  Task 6 (BUG-03) → deep agent (certstream pipeline)
  Task 7 (BUG-02) → deep agent (search)

Phase 3: Integration test of all fixes together
```
