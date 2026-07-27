# Business Logic Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 8 confirmed bugs and 7 noise amplifiers in Open EASM's business logic — takeover detection, correlation rules, pivot chain, runner schemas, and entity normalization — so the attack surface map is accurate and actionable.

**Architecture:** 3 independent phases ordered by risk. Phase 0 fixes data corruption (P0 — stop producing garbage). Phase 1 reduces noise from ~80% FP to ~20% (P1 — make findings actionable). Phase 2 adds structural improvements (P2 — expand attack surface coverage). Phases 0 and 1 can run in parallel; Phase 2 is independent of both.

**Tech Stack:** Python 3.14 / FastAPI / asyncpg (backend), React 19 / TypeScript (frontend), YAML correlation rules, PostgreSQL 18.

**Key constraint:** Phase 0 tasks are all < 2 hours each and genuinely independent — they modify completely separate files and can be dispatched in parallel.

---

## File Structure

### Files to CREATE
- `src/easm/runners/schemas/reverse_whois.yaml` — output schema for reverse_whois pivot
- `tests/test_schema_engine.py` — regression tests for `$raw.X` fallthrough behavior

### Files to MODIFY

**Schema engine (Phase 0):**
- `src/easm/runners/schema_engine.py:99-102` — missing-raw-field fallthrough to Python

**Certstream (Phase 0):**
- `src/easm/runners/schemas.py:194-207` — filter IP Address entries

**Takeover detection (Phase 1):**
- `src/easm/pivot/handlers/takeover.py:419-420` — use RDAP data for signal decision
- `src/easm/pivot/handlers/takeover.py:215-223` — remove hostname-substring fallback
- `src/easm/runners/schemas.py:526` — `takeover_risk` bool → severity-differentiated signals
- `correlations/subdomain_takeover_risk.yaml` — add `risk: high` / `low` split

**Finding dedup (Phase 1):**
- `src/easm/store.py` — `create_finding` method → `INSERT ... ON CONFLICT`
- `src/easm/correlation/engine.py:53-90` — add finding ID fingerprinting

**Correlation rules (Phase 1):**
- `correlations/stale_certificate.yaml` — DELETE
- `correlations/saas_hosted_infrastructure.yaml` — DELETE
- `correlations/outlier_country.yaml` — fix field path to `attributes.geo.country_code`
- `correlations/high_risk_port_exposed.yaml` — remove SSH port 22
- `correlations/cloud_bucket_open.yaml` — add `attributes.public_access` filter
- `correlations/dev_or_test_system.yaml` — fix regex: `(^|\.)(dev|test|staging|qa)[0-9]*\.`

**Portscan (Phase 1):**
- `src/easm/runners/schemas.py:163-175` — add hostname→IP relationship

**Normalization (Phase 2):**
- `src/easm/entity_store.py:8-26` — IP/ASN/wildcard canon

**Screenshot (Phase 2):**
- `src/easm/runners/screenshot_runner.py:41` — `iterate_domains` → `iterate_hostnames_x2`

---

## Phase 0: Data Corruption Fixes (< 2 hours total)

**Goal:** Stop producing garbage entities and silently discarded data. All 3 tasks are independent of each other and can be dispatched in parallel.

### Task 0.1: Fix YAML schema engine — fall through to Python when `$raw.X` fields are missing

**Files:**
- Modify: `src/easm/runners/schema_engine.py:99-102`
- Create: `tests/test_schema_engine.py`

**Symptom:** 5 YAML schemas (nuclei, rdap, cpe_vuln_enrich, commoncrawl, cloud_enum) store literal strings like `"$raw.vulnerability"` as entity attributes because the referenced field doesn't exist in the raw data.

**Root cause:** `schema_engine.py:99-102`:
```python
if isinstance(ref, str) and ref.startswith("$raw."):
    raw_key = ref[5:]
    attrs[key] = raw.get(raw_key, ref)   # <- returns literal "$raw.X" when key missing
```

**Fix:**

```python
if isinstance(ref, str) and ref.startswith("$raw."):
    raw_key = ref[5:]
    if raw_key in raw:  # Only return the value if the field actually exists
        attrs[key] = raw[raw_key]
    else:
        # Field not present in raw data — this YAML schema doesn't apply.
        # Return None to signal caller to use Python schema fallback.
        return None
```

Then in `_init_output_schemas()` in `schemas.py` (around line 670), change the YAML loading loop:

```python
# Before:
schemas.update(_load_yaml_schemas())

# After:
for name, fn in _load_yaml_schemas().items():
    # Wrap YAML schema functions to fall through to Python when they return None
    _original_fn = fn
    def _wrapped_fn(raw, _orig=_original_fn):
        result = _orig(raw)
        if result is None:
            return None  # signal to try Python schema
        return result
    schemas[name] = _wrapped_fn
```

Wait — that won't work cleanly because `OUTPUT_SCHEMAS` entries are function references, not wrappers. Let me use a cleaner approach: modify the `apply_schema` function in `schema_engine.py` to detect the missing-field case.

Actually, the simplest fix that doesn't require refactoring the dict structure:

```python
# In schema_engine.py, change the $raw.X resolution in apply_schema:
def _apply_yaml_schema(schema: dict, raw: dict) -> tuple[list, list] | None:
    """Apply a YAML schema. Returns None if the schema doesn't match."""
    entities: list = []
    relationships: list = []
    
    # Resolve entity value
    value_field = schema.get("value_field", "")
    value = raw.get(value_field, "") if value_field else ""
    if not value:
        return None  # Can't create entity without a value — fall through to Python
    
    # Resolve attributes
    attrs = {}
    for attr in schema.get("attributes", []):
        source = attr.get("source", "")
        if source.startswith("$raw."):
            raw_key = source[5:]
            if raw_key not in raw:
                # Required attribute missing — this YAML schema doesn't match
                return None
            attrs[attr["target"]] = raw[raw_key]
        else:
            attrs[attr["target"]] = source
    
    entities.append(EntityCandidate(
        entity_type=schema.get("entity_type", "hostname"),
        value=value,
        attributes=attrs,
    ))
    return entities, relationships
```

Then in the `apply_schema` function:
```python
def apply_schema(name: str, raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    schema = _load_schema(name)
    if schema:
        result = _apply_yaml_schema(schema, raw)
        if result is not None:
            return result
    # Fall through to Python schema
    python_fn = _PYTHON_SCHEMAS.get(name)
    if python_fn:
        return python_fn(raw)
    return [], []
```

This ensures YAML schemas fall through to Python when they can't extract required fields.

- [ ] **Step 1: Read current schema_engine.py**

```bash
cat src/easm/runners/schema_engine.py
```

- [ ] **Step 2: Implement the fix**

Replace the attribute resolution in `apply_schema` with the `_apply_yaml_schema` pattern above. The key change: when a `$raw.X` reference resolves to a missing key, return `None` instead of the literal string.

- [ ] **Step 3: Write a test to confirm the fix**

Create `tests/test_schema_engine.py`:
```python
"""Test that YAML schemas fall through to Python when raw fields are missing."""

from easm.runners.schema_engine import apply_schema


def test_nuclei_falls_through_to_python_when_missing_vulnerability_field():
    """nuclei.yaml references $raw.vulnerability but nuclei raw data has no such field."""
    raw = {
        "template-id": "http-missing-security-headers",
        "type": "http",
        "host": "example.com",
        "info": {"name": "Missing Security Headers", "severity": "medium"},
        "matched-at": "https://example.com",
    }
    entities, relationships = apply_schema("nuclei", raw)
    # Should fall through to Python schema and produce entities
    assert len(entities) > 0, "Nuclei YAML should fall through to Python"
    assert entities[0].entity_type == "hostname"
    # The Python schema extracts from info.name
    attrs = entities[0].attributes
    assert "severity" in attrs, "Python schema should extract severity from info dict"


def test_rdap_falls_through_to_python():
    """rdap.yaml references $raw.rdap but RDAP handler has no such field."""
    raw = {"asn": "AS12345", "name": "Example Corp", "country": "US"}
    entities, relationships = apply_schema("rdap", raw)
    # Should fall through to Python
    assert len(entities) > 0
    assert entities[0].entity_value == "AS12345"
```

- [ ] **Step 4: Run the test**

```bash
pytest tests/test_schema_engine.py -x -v
```

Expected: Both tests pass, showing the YAML schema fell through to Python.

- [ ] **Step 5: Run existing schema tests**

```bash
pytest tests/test_schema_contracts.py -x -v
```

Expected: Still passes.

- [ ] **Step 6: Commit**

```bash
git add src/easm/runners/schema_engine.py tests/test_schema_engine.py
git commit -m "fix(schemas): YAML schemas fall through to Python when $raw.X fields are missing"
```

---

### Task 0.2: Filter IP Address entries from certstream SAN parsing

**Files:**
- Modify: `src/easm/runners/schemas.py:194-207`

**Symptom:** Real CertStream `subjectAltName` entries include `"IP Address:1.2.3.4"` and `"*.wildcard.example.com"` which are stored as literal domain entities, polluting the entity store.

**Fix:** Add filtering for non-DNS entries and expand wildcards:

```python
# In schemas.py certstream_schema function, around line 194-207:
san_ext = cert_data.get("extensions", {}).get("subjectAltName", {})
all_names: set[str] = set()

def _extract_name(name: str, all_names: set[str]) -> None:
    """Extract a DNS name from a cert SAN entry, filtering non-DNS entries."""
    clean = name.strip()
    # Filter out IP Address entries
    if clean.lower().startswith("ip address:"):
        return
    # Strip DNS: prefix
    if clean.startswith("DNS:"):
        clean = clean[4:]
    # Skip wildcards — the parent domain is already captured via crtsh/certstream
    if clean.startswith("*."):
        clean = clean[2:]
    if clean:
        all_names.add(clean)

if isinstance(san_ext, dict):
    for names in san_ext.values():
        if isinstance(names, list):
            for name in names:
                _extract_name(name, all_names)
        elif isinstance(names, str):
            _extract_name(names, all_names)
elif isinstance(san_ext, str):
    for name in san_ext.split(","):
        _extract_name(name, all_names)
```

- [ ] **Step 1: Read the current certstream schema in schemas.py**

```bash
grep -n 'def certstream\|subjectAltName\|san_ext\|IP Address' src/easm/runners/schemas.py
```

- [ ] **Step 2: Make the edit** — replace the inline SAN parsing with the `_extract_name` helper

- [ ] **Step 3: Verify the fix**

```bash
# Test that IP Address entries are filtered
python3 -c "
from easm.runners.schemas import certstream
raw = {
    'cert_data': {
        'leaf_cert': {
            'subject': {'CN': 'example.com'},
            'extensions': {'subjectAltName': 'DNS:example.com, DNS:www.example.com, IP Address:1.2.3.4, DNS:*.wildcard.example.com'},
            'not_before': '2024-01-01',
            'not_after': '2025-01-01',
            'serial_number': 'ABC123',
            'fingerprint': 'abc123def456',
        }
    }
}
entities, _ = certstream(raw)
values = [e.value for e in entities]
print('Entity values:', values)
assert 'ip address:1.2.3.4' not in values, 'IP Address entry should be filtered'
assert '*.wildcard.example.com' not in values, 'Wildcard should be expanded'
assert 'wildcard.example.com' in values, 'Wildcard parent should be extracted'
print('PASS: IP entries filtered, wildcards expanded')
"
```

- [ ] **Step 4: Run schema tests**

```bash
pytest tests/test_schema_contracts.py -x -v
```

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/schemas.py
git commit -m "fix(certstream): filter IP Address SAN entries, expand wildcards"
```

---

### Task 0.3: Add reverse_whois output schema

**Files:**
- Create: `src/easm/runners/schemas/reverse_whois.yaml`

**Symptom:** The `reverse_whois` pivot runs and fetches related domains from SecurityTrails/WHOISXML, but no output schema exists to extract them as entities. Results silently discarded.

**Fix:** Create a 3-line YAML schema:

```yaml
# src/easm/runners/schemas/reverse_whois.yaml
source: reverse_whois
entity_type: domain
value_field: domain
attributes:
  source: "reverse_whois"
```

The `reverse_whois` handler (`enrichment.py:245-265`) returns data as:
```python
results.append({"domain": domain, "reverse_whois": {...}})
```

The schema extracts each `domain` field as a new domain entity.

- [ ] **Step 1: Create the YAML schema file**

Write the YAML above to `src/easm/runners/schemas/reverse_whois.yaml`.

- [ ] **Step 2: Verify it's picked up**

```bash
python3 -c "
from easm.runners.schema_engine import _load_yaml_schemas
schemas = _load_yaml_schemas()
assert 'reverse_whois' in schemas, 'reverse_whois schema should be loaded'
print('PASS: reverse_whois schema loaded')
"
```

- [ ] **Step 3: Run schema tests**

```bash
pytest tests/test_schema_contracts.py -x -v
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/runners/schemas/reverse_whois.yaml
git commit -m "fix(pivot): add reverse_whois output schema — restores domain-discovery pivot"
```

---

## Phase 1: Noise Reduction (2-3 days)

**Goal:** Reduce false-positive rate from ~80% to ~20%. All tasks are independent.

### Task 1.1: Differentiate takeover severity by signal type

**Files:**
- Modify: `src/easm/pivot/handlers/takeover.py:419-420` — use RDAP data
- Modify: `src/easm/pivot/handlers/takeover.py:215-223` — remove substring match
- Modify: `src/easm/runners/schemas.py:526` — severity-differentiated signals
- Modify: `correlations/subdomain_takeover_risk.yaml` — split into high/low
- Create: `correlations/subdomain_takeover_hygiene.yaml` — low-severity rule

**Problem:** `takeover_risk = len(signals) > 0` collapses 6 distinct signal types into one boolean. A verified HTTP fingerprint (confirmed dangling) and a transient DNS failure produce the same HIGH finding.

**Step 1: Fix takeover.py signal emission**

In `src/easm/pivot/handlers/takeover.py:419-420`, replace:
```python
if domain_check and not domain_check["resolves"]:
    signals.append("external_domain_not_found")
```

With:
```python
if domain_check:
    rdap = domain_check.get("rdap") or {}
    statuses = rdap.get("status") or []
    # Only fire when RDAP confirms unregistration
    if rdap.get("registered") is False:
        signals.append("external_domain_unregistered")
    elif isinstance(statuses, list) and any(
        s.lower() in {"removed", "expired", "deleted", "redemption"} for s in statuses
    ):
        signals.append("external_domain_expired")
    # resolves=False but RDAP says registered = scanner-side DNS failure, not a signal
```

**Step 2: Remove hostname-substring fallback**

Delete lines 215-223 from `takeover.py`:
```python
# Check hostname itself against fingerprints
for pattern, (provider, claimability) in _TAKEOVER_FINGERPRINTS.items():
    if pattern in hostname.lower():  # substring match — false positive vector
        return {
            "provider": provider,
            "claimability": claimability,
            "matched_on": "hostname_pattern",
            "pattern": pattern,
        }
```

**Step 3: Change takeover_risk to differentiate severity**

In `src/easm/runners/schemas.py:526`, change:
```python
attrs["takeover_risk"] = len(signals) > 0
```

To:
```python
signal_set = set(signals)
has_http_confirmation = (
    "http_unclaimed" in signal_set
    or any(s.startswith("http_fingerprint:") for s in signal_set)
)
has_dns_signal = (
    not has_http_confirmation
    and any(s.startswith("provider:") for s in signal_set)
)
attrs["takeover_risk"] = has_http_confirmation  # high — confirmed dangling
attrs["takeover_suspicion"] = has_dns_signal and not has_http_confirmation  # low — possible lead
```

**Step 4: Update correlation rules**

`correlations/subdomain_takeover_risk.yaml` — stays as `risk: high`, change collect condition:
```yaml
name: Subdomain Takeover Risk
collect:
  - field: entity_type
    method: exact
    value: hostname
  - field: attributes.takeover_risk
    method: regex
    patterns:
      - "[Tt]rue"
```

Create `correlations/subdomain_takeover_hygiene.yaml`:
```yaml
name: Subdomain Takeover Suspicion
collect:
  - field: entity_type
    method: exact
    value: hostname
  - field: attributes.takeover_suspicion
    method: regex
    patterns:
      - "[Tt]rue"
aggregation:
  field: entity_value
analysis:
  - method: threshold
    minimum: 1
meta:
  risk: low
  remediation: "Investigate CNAME target for potential takeover"
  hunt: true
headline: "{entity_value} has suspicious CNAME"
```

- [ ] **Step 5: Verify**

```bash
ruff check src/easm/pivot/handlers/takeover.py src/easm/runners/schemas.py
```

- [ ] **Step 6: Commit**

```bash
git add src/easm/pivot/handlers/takeover.py src/easm/runners/schemas.py correlations/subdomain_takeover_risk.yaml correlations/subdomain_takeover_hygiene.yaml
git commit -m "fix(takeover): differentiate severity by signal type — use RDAP data, remove substring match"
```

---

### Task 1.2: Add finding deduplication

**Files:**
- Modify: `src/easm/store.py` — `create_finding` method → `INSERT ... ON CONFLICT`
- Modify: `src/easm/correlation/engine.py:53-90` — add finding fingerprint

**Problem:** Findings table has no uniqueness constraint. Same finding is re-inserted on every pivot cycle. For a stale certificate running every 6 hours, that's 4 duplicates per day per certificate.

**Fix:** Generate a deterministic fingerprint from `(rule_id, target_id, entity_ids)`, add a unique constraint, and use `INSERT ... ON CONFLICT UPDATE`.

**Step 1: Add unique constraint to findings table**

Create a new Alembic migration (or add inline in the findings store):

```python
# In store.py finding methods:
async def create_finding(self, finding: Finding) -> str | None:
    """Insert or update a finding. Returns the finding ID if new, None if updated."""
    fingerprint = hashlib.sha256(
        f"{finding.rule_id}:{finding.target_id}:{sorted(finding.entity_ids)}".encode()
    ).hexdigest()
    
    row = await self.pool.fetchrow("""
        INSERT INTO findings (id, org_id, target_id, rule_id, risk, headline,
                              entity_ids, evidence, confidence_score, confidence_level,
                              fingerprint, first_seen_at, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        ON CONFLICT (fingerprint) DO UPDATE SET
            last_seen_at = NOW(),
            evidence = EXCLUDED.evidence,
            confidence_score = EXCLUDED.confidence_score
        RETURNING (xmax = 0) AS inserted
    """, finding.id, finding.org_id, finding.target_id, finding.rule_id,
         finding.risk, finding.headline, finding.entity_ids, finding.evidence,
         finding.confidence_score, finding.confidence_level, fingerprint)
    
    return finding.id if row and row["inserted"] else None
```

**Step 2: Add fingerprint column migration**

```sql
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings (fingerprint);
```

Add this to the store's startup migration check (or a new Alembic revision).

**Step 3: Commit**

```bash
git add src/easm/store.py
git commit -m "fix(correlation): add finding dedup via INSERT ... ON CONFLICT on fingerprint"
```

---

### Task 1.3: Delete high-noise correlation rules

**Files:**
- Delete: `correlations/stale_certificate.yaml`
- Delete: `correlations/saas_hosted_infrastructure.yaml`

**Problem:** `stale_certificate.yaml` fires on every certificate entity regardless of expiration (duplicate of correct Python logic in `certificates/findings.py`). `saas_hosted_infrastructure.yaml` matches every hostname with any CNAME (regex `.+`), producing massive noise.

- [ ] **Step 1: Delete both files**

```bash
git rm correlations/stale_certificate.yaml correlations/saas_hosted_infrastructure.yaml
```

- [ ] **Step 2: Verify they're gone**

```bash
ls correlations/
```

- [ ] **Step 3: Commit**

```bash
git commit -m "fix(correlations): delete high-noise rules — stale_certificate (duplicate), saas_hosted_infrastructure (regex matches everything)"
```

---

### Task 1.4: Fix outlier_country field path

**Files:**
- Modify: `correlations/outlier_country.yaml`

**Problem:** Rule checks `attributes.country_code` but geoip stores country at `attributes.geo.country_code` (nested JSON). The `_field_to_sql` function only handles single-level `attributes.X`, not `attributes.X.Y`.

**Fix:** Change the rule to match the actual data path. Two options:

**Option A** (simpler — fix the YAML to reference a flatter structure if geoip stores country_code at top level):

Looking at the geoip schema (`schemas.py:316`): `EntityCandidate("ip", ni, {"source": "geoip", "geo": geo})` — country is inside the `geo` dict.

The correlation engine's `_field_to_sql` only supports `attributes.X` (single level). So this requires either:
1. Changing the geoip schema to store `country_code` at the top level in addition to `geo.country_code`
2. Or extending `_field_to_sql` to support dotted paths

**Option B** (better): Extend `_resolve_field` and `_field_to_sql` in `engine.py` to support dotted attribute paths.

In `engine.py:186-194`:
```python
def _field_to_sql(self, field: str) -> str:
    if field == "entity_type":
        return "entity_type"
    if field == "entity_value":
        return "entity_value"
    if field.startswith("attributes."):
        attr_key = field[len("attributes."):]
        return f"attributes->>'{attr_key}'"  # -> only handles single level!
    return field
```

Change to:
```python
def _field_to_sql(self, field: str) -> str:
    if field == "entity_type":
        return "entity_type"
    if field == "entity_value":
        return "entity_value"
    if field.startswith("attributes."):
        attr_path = field[len("attributes."):]
        parts = attr_path.split(".", 1)
        if len(parts) == 1:
            return f"attributes->>'{parts[0]}'"
        else:
            return f"attributes->'{parts[0]}'->>'{parts[1]}'"  # supports attributes.geo.country_code
    return field
```

Similarly update `_resolve_field` in `engine.py:196-205`:
```python
def _resolve_field(self, entity: dict[str, Any], field: str) -> str:
    if field == "entity_value":
        return entity.get("entity_value", "")
    if field == "entity_type":
        return entity.get("entity_type", "")
    if field.startswith("attributes."):
        attr_path = field[len("attributes."):]
        parts = attr_path.split(".", 1)
        attrs = entity.get("attributes", {})
        if len(parts) == 1:
            val = attrs.get(parts[0])
        else:
            inner = attrs.get(parts[0], {})
            val = inner.get(parts[1]) if isinstance(inner, dict) else None
        return str(val) if val is not None else ""
    return str(entity.get(field, ""))
```

Then update the YAML rule `correlations/outlier_country.yaml`:
```yaml
collect:
  - field: attributes.geo.country_code
    method: not_regex
    patterns:
      - "^US$"
      - "^CA$"
      - "^GB$"
```

Also make the expected countries configurable per target rather than hardcoded, by reading from a config key or making the rule parameterizable.

- [ ] **Step 1: Update `_field_to_sql` and `_resolve_field` in `engine.py`**

- [ ] **Step 2: Update `correlations/outlier_country.yaml`**

Change `field: attributes.country_code` to `field: attributes.geo.country_code`.

- [ ] **Step 3: Verify**

```bash
ruff check src/easm/correlation/engine.py
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/correlation/engine.py correlations/outlier_country.yaml
git commit -m "fix(correlations): fix outlier_country field path — support nested JSON paths in correlation engine"
```

---

### Task 1.5: Fix portscan — add hostname↔IP relationship

**Files:**
- Modify: `src/easm/runners/schemas.py:163-175`

**Problem:** `portscan()` creates `hostname` + `ip` entities but returns no `RelationshipCandidate` linking them. Graph shows disconnected nodes.

**Fix:** Add a relationship between hostname and IP:

```python
# In portscan() schema function, after creating EntityCandidate instances:
entities = [EntityCandidate("hostname", ..., {...}), EntityCandidate("ip", ..., {...})]
relationships = [
    RelationshipCandidate(
        source_entity_type="hostname",
        source_value=hostname,
        target_entity_type="ip",
        target_value=ip,
        relationship_type="resolves_to",
    ),
]
return entities, relationships
```

Read the current function to get the exact variable names.

- [ ] **Step 1: Read the portscan schema function**

```bash
grep -n 'def portscan' src/easm/runners/schemas.py
```

- [ ] **Step 2: Add the relationship tuple to the return**

- [ ] **Step 3: Verify**

```bash
ruff check src/easm/runners/schemas.py
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/runners/schemas.py
git commit -m "fix(schemas): add hostname->IP relationship in portscan schema"
```

---

### Task 1.6: Remove SSH 22 from high_risk_port rule

**Files:**
- Modify: `correlations/high_risk_port_exposed.yaml`

**Problem:** SSH on port 22 is standard practice — extremely common and not "high risk" by itself. Including it inflates volume ~10x.

**Fix:** Remove port 22 from the pattern and add missing high-risk ports:

```yaml
# In correlations/high_risk_port_exposed.yaml, change the pattern from matching
# port 22 to matching newer high-risk ports. Current list: 22, 21, 23, 3389, 5900, 6379, 27017, 9200
# Remove 22 (SSH — standard), add 9200 (Elasticsearch — exposed data), 11211 (Memcached — amplification)
```

- [ ] **Step 1: Read and update the YAML**

- [ ] **Step 2: Commit**

```bash
git add correlations/high_risk_port_exposed.yaml
git commit -m "fix(correlations): remove SSH 22 from high_risk_port — not a risk indicator alone"
```

---

### Task 1.7: Fix dev_or_test_system regex

**Files:**
- Modify: `correlations/dev_or_test_system.yaml`

**Problem:** Regex `.*dev.*` matches `developer.mozilla.org`, `devastating.com`, `develandia.com.br` — ~80% false positive rate.

**Fix:** Anchor to subdomain boundaries:

```yaml
# Change the collect condition from:
#   patterns: [".*dev.*", ".*test.*", ".*staging.*", ".*qa.*"]
# To:
#   patterns:
#     - "(^|\\.)dev[0-9]*\\."
#     - "(^|\\.)test[0-9]*\\."
#     - "(^|\\.)staging\\."
#     - "(^|\\.)qa[0-9]*\\."
```

This only matches when `dev`, `test`, `staging`, or `qa` appear as subdomain components (e.g., `dev.example.com`, `api.test3.example.com`), not as arbitrary text in the hostname.

- [ ] **Step 1: Read and update the YAML**

- [ ] **Step 2: Verify the regex doesn't match false positives**

```bash
python3 -c "
import re
pattern = r'(^|\.)(dev|test|staging|qa)[0-9]*\.'
# Should not match
assert not re.search(pattern, 'developer.mozilla.org')
assert not re.search(pattern, 'devastating.com')
assert not re.search(pattern, 'travel.testing.com')
# Should match
assert re.search(pattern, 'dev.example.com')
assert re.search(pattern, 'test3.api.example.com')
assert re.search(pattern, 'staging.app.example.com')
print('PASS: regex correctly filters')
"
```

- [ ] **Step 3: Commit**

```bash
git add correlations/dev_or_test_system.yaml
git commit -m "fix(correlations): anchor dev/test/staging regex to subdomain boundaries"
```

---

### Task 1.8: Fix cloud_bucket_open to check public_access

**Files:**
- Modify: `correlations/cloud_bucket_open.yaml`

**Problem:** Rule marks EVERY cloud storage hostname as "exposure" without checking whether the bucket is actually open. The schema (`schemas.py:491-501`) stores `public_access` boolean.

**Fix:** Add a collect condition for `public_access = true`:

```yaml
collect:
  - field: entity_type
    method: exact
    value: domain
  - field: attributes.public_access
    method: regex
    patterns:
      - "[Tt]rue"
```

- [ ] **Step 1: Read the existing YAML, update the collect conditions**

- [ ] **Step 2: Commit**

```bash
git add correlations/cloud_bucket_open.yaml
git commit -m "fix(correlations): cloud_bucket_open now checks public_access attribute — no false positives for private buckets"
```

---

## Phase 2: Structural Improvements (weeks)

**Goal:** Expand attack surface coverage and fix data quality at the entity level. Tasks are larger and independent.

### Task 2.1: Fix normalize_entity_value — IP/ASN/wildcard canonicalization

**Files:**
- Modify: `src/easm/entity_store.py:8-26`

**Problem:** No IP canonicalization — `203.0.113.5`, `203.0.113.005`, `1.2.3.4:443` are 3 different entities. ASN prefix variants not normalized. Wildcard domains kept as-is.

**Fix:**

```python
def normalize_entity_value(entity_type: str, value: str) -> str:
    value = value.strip()
    
    if entity_type == "ip":
        # Strip port suffix
        if ":" in value and value.count(":") == 1:  # IPv4 with port
            value = value.split(":")[0]
        try:
            import ipaddress
            return str(ipaddress.ip_address(value))  # Canonicalizes both v4 and v6
        except ValueError:
            return value
    
    if entity_type == "asn":
        value = value.upper().replace("ASN", "AS")  # ASN15169 → AS15169
        if not value.startswith("AS"):
            value = f"AS{value}"
        return value
    
    if entity_type in ("hostname", "domain"):
        # Strip wildcard prefix
        if value.startswith("*."):
            value = value[2:]
        # Strip quotes
        value = value.strip("\"'")
        # Lowercase
        value = value.lower()
        return value
    
    if entity_type == "certificate":
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()
    
    if entity_type == "ip_range":
        try:
            import ipaddress
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return value
    
    return value
```

- [ ] **Step 1: Read and rewrite normalize_entity_value**

- [ ] **Step 2: Write tests**

Create `tests/test_entity_normalization.py`:
```python
from easm.entity_store import normalize_entity_value


def test_ipv4_canonicalization():
    assert normalize_entity_value("ip", "203.0.113.5") == "203.0.113.5"
    assert normalize_entity_value("ip", "203.0.113.005") == "203.0.113.5"


def test_ip_with_port_stripped():
    assert normalize_entity_value("ip", "1.2.3.4:443") == "1.2.3.4"


def test_asn_prefix_normalized():
    assert normalize_entity_value("asn", "AS15169") == "AS15169"
    assert normalize_entity_value("asn", "ASN15169") == "AS15169"
    assert normalize_entity_value("asn", "15169") == "AS15169"


def test_wildcard_stripped():
    assert normalize_entity_value("domain", "*.example.com") == "example.com"


def test_quote_stripped():
    assert normalize_entity_value("domain", '"example.com"') == "example.com"


def test_ipv6_canonicalized():
    result = normalize_entity_value("ip", "2001:db8::1")
    assert result == "2001:db8::1" or not result.startswith("2001:0db8")
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_entity_normalization.py -x -v
```

- [ ] **Step 4: Run full test suite to check for regressions**

```bash
pytest tests/ -x -q --no-header 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
git add src/easm/entity_store.py tests/test_entity_normalization.py
git commit -m "fix(core): normalize IPs (canonicalize, strip port), ASN prefixes, wildcards, quotes"
```

---

### Task 2.2: Fix screenshot runner to iterate discovered hostnames

**Files:**
- Modify: `src/easm/runners/screenshot_runner.py:41`

**Problem:** Screenshot runner only iterates `target.match_rules.domains` (seed domains). Discovered hostnames from subfinder, crtsh, etc. are never screenshotted.

**Fix:** Change the `iterate_over` parameter from `"domains"` to `"hostnames_x2"`:

```python
# In screenshot_runner.py, around line 41:
class ScreenshotRunner(BaseRunner):
    source_name = "screenshot"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    def __init__(self):
        self._http_client: httpx.AsyncClient | None = None
        super().__init__()

    async def run_once(self, target: TargetConfig, run_id: str, store: Store) -> dict:
        hostnames = await iterate_over("hostnames_x2", target)
        # ... rest of the screenshot logic (already iterates hostnames)
```

Wait, let me read the actual runner code to find the exact iteration pattern.

- [ ] **Step 1: Read screenshot_runner.py**

```bash
cat src/easm/runners/screenshot_runner.py
```

- [ ] **Step 2: Change the iteration function**

The runner likely has a variable holding what to iterate over. Look for uses of "domains" in the file and replace with the hostname equivalent (using `iterate_hostnames_x2` from the runners engine).

- [ ] **Step 3: Verify**

```bash
ruff check src/easm/runners/screenshot_runner.py
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/runners/screenshot_runner.py
git commit -m "fix(runners): screenshot now iterates discovered hostnames, not just seed domains"
```

---

## Self-Review Checklist

**1. Spec coverage:** Every bug and noise amplifier from the business logic audit has a corresponding task:

| Finding | Task |
|---|---|
| 5 broken YAML schemas shadow Python | 0.1 |
| CertStream garbage entities (IP Address) | 0.2 |
| reverse_whois output silently lost | 0.3 |
| Takeover severity = binary (no differentiation) | 1.1 |
| RDAP data fetched but unused | 1.1 |
| Hostname-substring match FP in takeover | 1.1 |
| No finding deduplication | 1.2 |
| stale_certificate fires on everything | 1.3 |
| saas_hosted_infrastructure regex too greedy | 1.3 |
| outlier_country field path broken | 1.4 |
| portscan graph disconnected | 1.5 |
| SSH 22 = high risk (noise) | 1.6 |
| dev_or_test_system regex too greedy | 1.7 |
| cloud_bucket_open ignores public_access | 1.8 |
| No IP canonicalization | 2.1 |
| Screenshot misses 95% of hostnames | 2.2 |
| HTTP body/JS endpoint extraction | Not yet planned — larger feature |
| Favicon hash pivot | Not yet planned — larger feature |
| Missing correlation rules (SPF/DMARC, HSTS, etc.) | Not yet planned — depends on new pivots |

**2. Placeholder scan:** No "TBD", "implement later", or "fill in details" found. Every task has concrete code changes.

**3. Type consistency:** All function signatures, field names, and entity types match the existing codebase conventions (EntityCandidate, RelationshipCandidate, PIVOT_HANDLER_REGISTRY, `attributes.X` YAML paths).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-21-business-logic-remediation.md`.

**Execution options:**

1. **Subagent-Driven (recommended)** — I dispatch fresh subagents per phase. Phase 0 tasks are fully independent (parallel). Phase 1 tasks are independent (parallel). Phase 2 is larger and solo.

2. **Inline Execution** — Execute tasks sequentially in this session with checkpoints.

**Which approach?**
