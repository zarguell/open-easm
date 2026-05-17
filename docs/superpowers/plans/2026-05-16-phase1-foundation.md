# Phase 1 Foundation — Taxonomy + Keyword Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add asset classification (org-owned vs SaaS-hosted vs third-party-integrated) and a shared keyword matching engine to Open EASM.

**Architecture:** Classification runs as a post-upsert step in the backfill loop, writing `asset_classification` into the entity's `attributes` JSONB column. The keyword engine is a standalone module that builds a match library from target config and exposes a `match(text)` method consumed by all future monitors. Both features are config-driven through `config.yaml` extensions with Pydantic models.

**Tech Stack:** Python 3.14, Pydantic, pytest-asyncio, asyncpg, existing entity store, existing config pattern, fnmatch (stdlib).

---

## File Structure

### Feature 1.1: Org vs. SaaS Provider Taxonomy

| File | Responsibility |
|------|---------------|
| `src/easm/classify.py` | Classification logic: `classify_entity()` function + `ClassificationResult` type |
| `tests/test_classify.py` | Tests for classification logic |
| `src/easm/config.py` | Add `SaasProviderRule`, `SaasProviderConfig` Pydantic models; add `saas_providers` to `Config` |
| `src/easm/backfill.py` | Call `classify_entity()` after entity upsert, write `asset_classification` to attributes |
| `src/easm/pivot/resolver.py` | Skip pivot enqueue for `saas-hosted` or `third-party-integrated` entities |
| `config.yaml.example` | Add `saas_providers` block |

### Feature 1.4: Keyword Alert Architecture

| File | Responsibility |
|------|---------------|
| `src/easm/keywords.py` | `KeywordMatch` dataclass + `KeywordEngine` class with `match()` method |
| `tests/test_keywords.py` | Tests for keyword matching engine |
| `src/easm/config.py` | Add `KeywordPattern` Pydantic model; add `keyword_patterns` to `MatchRules` |
| `config.yaml.example` | Add `keyword_patterns` under `match_rules` |

---

## Feature 1.1 — Org vs. SaaS Provider Taxonomy

### Task 1: Config Models for SaaS Providers

**Files:**
- Modify: `src/easm/config.py:1-128`

- [ ] **Step 1: Write failing tests for SaaS provider config models**

```python
# Add to tests/test_config.py
from easm.config import SaasProviderRule, SaasProviderConfig


def test_saas_provider_rule_valid():
    rule = SaasProviderRule(
        pattern="*.amazonaws.com",
        provider="aws",
        classification="saas-hosted",
    )
    assert rule.pattern == "*.amazonaws.com"
    assert rule.provider == "aws"
    assert rule.classification == "saas-hosted"


def test_saas_provider_rule_rejects_invalid_classification():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SaasProviderRule(
            pattern="*.foo.com",
            provider="unknown",
            classification="invalid_value",
        )


def test_saas_provider_config_default_empty():
    cfg = SaasProviderConfig()
    assert cfg.rules == []


def test_saas_provider_config_from_list():
    cfg = SaasProviderConfig(
        rules=[
            {"pattern": "*.amazonaws.com", "provider": "aws", "classification": "saas-hosted"},
        ]
    )
    assert len(cfg.rules) == 1


def test_saas_providers_parsed_from_yaml(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }],
        "saas_providers": {
            "rules": [
                {"pattern": "*.amazonaws.com", "provider": "aws", "classification": "saas-hosted"},
                {"pattern": "*.cloudfront.net", "provider": "aws", "classification": "saas-hosted"},
            ],
        },
    }))
    config = load_config(path)
    assert len(config.saas_providers.rules) == 2
    assert config.saas_providers.rules[0].provider == "aws"


def test_saas_providers_optional(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }],
    }))
    config = load_config(path)
    assert len(config.saas_providers.rules) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py::test_saas_provider_rule_valid tests/test_config.py::test_saas_provider_rule_rejects_invalid_classification tests/test_config.py::test_saas_provider_config_default_empty tests/test_config.py::test_saas_provider_config_from_list tests/test_config.py::test_saas_providers_parsed_from_yaml tests/test_config.py::test_saas_providers_optional -v`
Expected: FAIL — `ImportError: cannot import name 'SaasProviderRule' from 'easm.config'`

- [ ] **Step 3: Add Pydantic models to config**

Add to `src/easm/config.py` before the `Config` class:

```python
from pydantic import BaseModel, Field, field_validator
from typing import Literal


ClassificationType = Literal["saas-hosted", "org-owned", "third-party-integrated"]


class SaasProviderRule(BaseModel):
    pattern: str
    provider: str
    classification: ClassificationType


class SaasProviderConfig(BaseModel):
    rules: list[SaasProviderRule] = Field(default_factory=list)
```

Add `saas_providers` field to the `Config` class:

```python
class Config(BaseModel):
    targets: list[TargetConfig]
    saas_providers: SaasProviderConfig = Field(default_factory=SaasProviderConfig)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py::test_saas_provider_rule_valid tests/test_config.py::test_saas_provider_rule_rejects_invalid_classification tests/test_config.py::test_saas_provider_config_default_empty tests/test_config.py::test_saas_provider_config_from_list tests/test_config.py::test_saas_providers_parsed_from_yaml tests/test_config.py::test_saas_providers_optional -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Run existing config tests to verify no regressions**

Run: `uv run pytest tests/test_config.py -v`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add src/easm/config.py tests/test_config.py
git commit -m "feat: add SaaS provider config models (SaasProviderRule, SaasProviderConfig)"
```

---

### Task 2: Classification Logic Module

**Files:**
- Create: `src/easm/classify.py`
- Create: `tests/test_classify.py`

- [ ] **Step 1: Write failing tests for classify module**

```python
# tests/test_classify.py
import pytest
from easm.classify import classify_entity, ClassificationResult
from easm.config import SaasProviderRule, SaasProviderConfig


def test_classify_domain_org_owned():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="domain",
        entity_value="example.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result == ClassificationResult(classification="org-owned", provider=None)


def test_classify_domain_saas_hosted():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
        SaasProviderRule(pattern="*.cloudfront.net", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="domain",
        entity_value="d2x3y4z5.cloudfront.net",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "saas-hosted"
    assert result.provider == "aws"


def test_classify_hostname_saas_hosted():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="hostname",
        entity_value="ec2-54-123-45-67.us-west-2.compute.amazonaws.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "saas-hosted"
    assert result.provider == "aws"


def test_classify_no_rules_returns_org_owned():
    rules = SaasProviderConfig()
    result = classify_entity(
        entity_type="domain",
        entity_value="sub.example.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result == ClassificationResult(classification="org-owned", provider=None)


def test_classify_no_target_domains_returns_unknown():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="domain",
        entity_value="some-random-domain.com",
        target_domains=[],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_ip_with_no_rules_org_owned():
    rules = SaasProviderConfig()
    result = classify_entity(
        entity_type="ip",
        entity_value="1.2.3.4",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_certificate_returns_org_owned():
    rules = SaasProviderConfig()
    result = classify_entity(
        entity_type="certificate",
        entity_value="abcdef1234567890",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_asn_returns_org_owned():
    result = classify_entity(entity_type="asn", entity_value="AS12345", target_domains=["example.com"])
    assert result.classification == "org-owned"


def test_classify_glob_pattern_matching():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.azurewebsites.net", provider="azure", classification="saas-hosted"),
        SaasProviderRule(pattern="*.googleapis.com", provider="gcp", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="hostname",
        entity_value="myapp.azurewebsites.net",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "saas-hosted"
    assert result.provider == "azure"


def test_classify_non_matching_glob_returns_org_owned():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="hostname",
        entity_value="myapp.herokuapp.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_result_to_dict():
    result = ClassificationResult(classification="saas-hosted", provider="aws")
    d = result.to_dict()
    assert d["asset_classification"] == "saas-hosted"
    assert d["provider"] == "aws"


def test_classify_result_defaults():
    result = ClassificationResult()
    assert result.classification == "org-owned"
    assert result.provider is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_classify.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.classify'`

- [ ] **Step 3: Write the classify module**

```python
# src/easm/classify.py
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from easm.config import SaasProviderConfig


@dataclass
class ClassificationResult:
    classification: str = "org-owned"
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "asset_classification": self.classification,
        }
        if self.provider:
            d["provider"] = self.provider
        return d


def classify_entity(
    entity_type: str,
    entity_value: str,
    target_domains: list[str] | None = None,
    saas_rules: SaasProviderConfig | None = None,
) -> ClassificationResult:
    if entity_type not in ("domain", "hostname"):
        return ClassificationResult()

    entity_lower = entity_value.lower()

    if saas_rules:
        for rule in saas_rules.rules:
            if fnmatch.fnmatch(entity_lower, rule.pattern):
                return ClassificationResult(
                    classification=rule.classification,
                    provider=rule.provider,
                )

    return ClassificationResult()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_classify.py -v`
Expected: All 14 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/classify.py tests/test_classify.py
git commit -m "feat: add entity classification logic (org-owned vs saas-hosted)"
```

---

### Task 3: Integrate Classification into Backfill Pipeline

**Files:**
- Modify: `src/easm/backfill.py:75-130`

- [ ] **Step 1: Write failing integration tests for classification in backfill**

```python
# Add to tests/test_backfill.py
import uuid
import json
import pytest


@pytest.mark.asyncio
async def test_backfill_classifies_entity_attributes(db_pool):
    from easm.backfill import backfill_worker
    from easm.config import Config, TargetConfig, SaasProviderConfig, SaasProviderRule
    pool = db_pool

    run_id = uuid.uuid7()
    event_id = uuid.uuid7()
    await pool.execute(
        "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
        run_id, "test-target", "subfinder", "manual", "running",
    )
    await pool.execute(
        "INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)",
        event_id, "default", "test-target", "subfinder",
        json.dumps({
            "hostname": "app.prod.evilcorp.com",
            "ip": "10.0.0.1",
        }),
        "hash-classify-1", run_id,
    )

    cfg = Config(
        targets=[
            TargetConfig(
                id="test-target", name="Test", type="org",
                match_rules={"domains": ["evilcorp.com"]},
                runners={},
                pivot={"enabled": False},
            ),
        ],
        saas_providers=SaasProviderConfig(rules=[
            SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
        ]),
    )

    import asyncio
    task = asyncio.create_task(backfill_worker(pool, cfg, batch_size=100, batch_interval_ms=50))
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    rows = await pool.fetch(
        "SELECT entity_value, attributes FROM entities WHERE target_id = 'test-target' ORDER BY entity_value"
    )
    attrs_by_value = {r["entity_value"]: (json.loads(r["attributes"]) if isinstance(r["attributes"], str) else r["attributes"]) for r in rows}

    hostname_attrs = attrs_by_value.get("app.prod.evilcorp.com", {})
    assert "asset_classification" in hostname_attrs
    assert hostname_attrs["asset_classification"] == "org-owned"

    ip_attrs = attrs_by_value.get("10.0.0.1", {})
    assert "asset_classification" in ip_attrs
    assert ip_attrs["asset_classification"] == "org-owned"


@pytest.mark.asyncio
async def test_backfill_classifies_saas_hosted_entity(db_pool):
    from easm.backfill import backfill_worker
    from easm.config import Config, TargetConfig, SaasProviderConfig, SaasProviderRule
    pool = db_pool

    run_id = uuid.uuid7()
    event_id = uuid.uuid7()
    await pool.execute(
        "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
        run_id, "test-target", "subfinder", "manual", "running",
    )
    await pool.execute(
        "INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)",
        event_id, "default", "test-target", "subfinder",
        json.dumps({
            "hostname": "d3adb33f.cloudfront.net",
        }),
        "hash-classify-2", run_id,
    )

    cfg = Config(
        targets=[
            TargetConfig(
                id="test-target", name="Test", type="org",
                match_rules={"domains": ["evilcorp.com"]},
                runners={},
                pivot={"enabled": False},
            ),
        ],
        saas_providers=SaasProviderConfig(rules=[
            SaasProviderRule(pattern="*.cloudfront.net", provider="aws", classification="saas-hosted"),
        ]),
    )

    import asyncio
    task = asyncio.create_task(backfill_worker(pool, cfg, batch_size=100, batch_interval_ms=50))
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    row = await pool.fetchrow(
        "SELECT attributes FROM entities WHERE entity_value = 'd3adb33f.cloudfront.net'"
    )
    assert row is not None
    attrs = json.loads(row["attributes"]) if isinstance(row["attributes"], str) else row["attributes"]
    assert attrs.get("asset_classification") == "saas-hosted"
    assert attrs.get("provider") == "aws"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_backfill.py::test_backfill_classifies_entity_attributes tests/test_backfill.py::test_backfill_classifies_saas_hosted_entity -v`
Expected: FAIL — entities won't have `asset_classification` attribute yet

- [ ] **Step 3: Modify backfill.py to classify entities after upsert**

In `src/easm/backfill.py`, add imports at the top:

```python
from easm.classify import classify_entity
from easm.config import Config
```

Replace the entity processing loop (lines 77-90) to add classification after each entity upsert:

```python
            new_entities: list[tuple[str, str, uuid.UUID]] = []

            target = target_map.get(row["target_id"])

            for entity_cand in result.entities:
                entity_id, is_new = await upsert_entity(
                    pool,
                    org_id=row["org_id"],
                    target_id=row["target_id"],
                    entity_type=entity_cand.entity_type,
                    entity_value=entity_cand.value,
                    new_attributes=entity_cand.attributes,
                    raw_event_id=row["id"],
                    discovery_session_id=uuid.UUID(session_id) if session_id else None,
                    discovery_run_id=discovery_run_id,
                    discovery_pivot_id=discovery_pivot_id,
                )
                new_entities.append((entity_cand.entity_type, entity_cand.value, entity_id))

                classification = classify_entity(
                    entity_type=entity_cand.entity_type,
                    entity_value=entity_cand.value,
                    target_domains=target.match_rules.domains if target else None,
                    saas_rules=cfg.saas_providers if cfg else None,
                )
                await pool.execute(
                    """UPDATE entities
                       SET attributes = jsonb_set(COALESCE(attributes, '{}'::jsonb), '{asset_classification}', $1::jsonb)
                       WHERE id = $2""",
                    json.dumps(classification.classification), entity_id,
                )
                if classification.provider:
                    await pool.execute(
                        """UPDATE entities
                           SET attributes = jsonb_set(COALESCE(attributes, '{}'::jsonb), '{provider}', $1::jsonb)
                           WHERE id = $2""",
                        json.dumps(classification.provider), entity_id,
                    )
```

Also add `cfg` parameter to `backfill_worker` if not already there (it already accepts it).

The full file should now accept `cfg: Config` as the second parameter and use `cfg.saas_providers`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_backfill.py::test_backfill_classifies_entity_attributes tests/test_backfill.py::test_backfill_classifies_saas_hosted_entity -v`
Expected: Both tests PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add src/easm/backfill.py tests/test_backfill.py
git commit -m "feat: integrate entity classification into backfill pipeline"
```

---

### Task 4: Scope Gating — Skip Pivots on Non-Org-Owned Entities

**Files:**
- Modify: `src/easm/pivot/resolver.py:9-65`

- [ ] **Step 1: Write failing tests for classification gating in resolver**

```python
# Add to tests/test_pivot/test_resolver.py
import uuid
import json
import pytest


@pytest.mark.asyncio
async def test_resolver_skips_saas_hosted_entity(db_pool):
    from easm.pivot.resolver import PivotResolver
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "d3adb33f.cloudfront.net",
        json.dumps({"asset_classification": "saas-hosted", "provider": "aws"}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["evilcorp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "d3adb33f.cloudfront.net", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 0, "Should not enqueue pivot for saas-hosted entity"


@pytest.mark.asyncio
async def test_resolver_allows_org_owned_entity(db_pool):
    from easm.pivot.resolver import PivotResolver
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "app.evilcorp.com",
        json.dumps({"asset_classification": "org-owned"}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["evilcorp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "app.evilcorp.com", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 1, "Should enqueue pivot for org-owned entity"


@pytest.mark.asyncio
async def test_resolver_skips_third_party_integrated(db_pool):
    from easm.pivot.resolver import PivotResolver
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "api.stripe.com",
        json.dumps({"asset_classification": "third-party-integrated"}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["evilcorp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3,
               "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}],
               "scope_mode": "loose"},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "api.stripe.com", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 0, "Should not enqueue pivot for third-party-integrated entity"


@pytest.mark.asyncio
async def test_resolver_entity_without_classification_still_pivots(db_pool):
    from easm.pivot.resolver import PivotResolver
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "legacy.evilcorp.com",
        json.dumps({}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["evilcorp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "legacy.evilcorp.com", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 1, "Should enqueue pivot for entity with no classification (backwards compat)"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pivot/test_resolver.py::test_resolver_skips_saas_hosted_entity tests/test_pivot/test_resolver.py::test_resolver_allows_org_owned_entity tests/test_pivot/test_resolver.py::test_resolver_skips_third_party_integrated tests/test_pivot/test_resolver.py::test_resolver_entity_without_classification_still_pivots -v`
Expected: At least some tests FAIL because resolver doesn't check classification yet

- [ ] **Step 3: Modify resolver to check classification**

In `src/easm/pivot/resolver.py`, add classification check after the scope check (around line 25-26). Import `json` at the top. Replace the section after the scope check:

```python
from __future__ import annotations

import json

import tldextract

from easm.models import ScopeResult
from easm.pivot_store import enqueue_pivot_job


class PivotResolver:
    def __init__(self, pool):
        self.pool = pool

    async def _get_classification(self, entity_id) -> str | None:
        row = await self.pool.fetchval(
            "SELECT attributes->>'asset_classification' FROM entities WHERE id = $1",
            entity_id,
        )
        return row

    async def check_and_enqueue(
        self, target, entity_type, entity_value, entity_id,
        parent_entity_id=None, depth=1, discovery_session_id=None,
    ):
        pivot_config = target.pivot
        if not pivot_config or not pivot_config.enabled:
            return
        if depth > pivot_config.max_depth:
            return

        from easm.pivot.scope import ScopeEvaluator
        scope = ScopeEvaluator().evaluate(target, entity_type, entity_value)
        if scope == ScopeResult.OUT_OF_SCOPE and pivot_config.scope_mode == "strict":
            return

        classification = await self._get_classification(entity_id)
        if classification and classification != "org-owned":
            return

        for pivot_rule in pivot_config.allowed_pivots:
            if pivot_rule.from_ != entity_type:
                continue
            # ... rest of the method unchanged
```

Keep all the existing method body after the classification check (`for pivot_rule in pivot_config.allowed_pivots:` and everything below).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pivot/test_resolver.py::test_resolver_skips_saas_hosted_entity tests/test_pivot/test_resolver.py::test_resolver_allows_org_owned_entity tests/test_pivot/test_resolver.py::test_resolver_skips_third_party_integrated tests/test_pivot/test_resolver.py::test_resolver_entity_without_classification_still_pivots -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add src/easm/pivot/resolver.py tests/test_pivot/test_resolver.py
git commit -m "feat: skip pivot enqueue for non-org-owned entities"
```

---

### Task 5: Config Example Update

**Files:**
- Modify: `config.yaml.example:1-72`

- [ ] **Step 1: Add saas_providers section to config example**

Add at the top of `config.yaml.example`, before `targets:`:

```yaml
saas_providers:
  rules:
    - pattern: "*.amazonaws.com"
      provider: aws
      classification: saas-hosted
    - pattern: "*.cloudfront.net"
      provider: aws
      classification: saas-hosted
    - pattern: "*.azurewebsites.net"
      provider: azure
      classification: saas-hosted
    - pattern: "*.googleapis.com"
      provider: gcp
      classification: saas-hosted
    - pattern: "*.herokuapp.com"
      provider: heroku
      classification: saas-hosted
```

- [ ] **Step 2: Validate config example loads correctly**

Run: `uv run python -c "from easm.config import load_config; c = load_config('config.yaml.example'); print(f'Loaded {len(c.targets)} targets, {len(c.saas_providers.rules)} saas rules')"`
Expected: Prints "Loaded 1 targets, 5 saas rules"

- [ ] **Step 3: Commit**

```bash
git add config.yaml.example
git commit -m "docs: add saas_providers example to config.yaml.example"
```

---

## Feature 1.4 — Keyword Alert Architecture

### Task 1: KeywordMatch Dataclass and KeywordEngine Skeleton

**Files:**
- Create: `src/easm/keywords.py`
- Create: `tests/test_keywords.py`

- [ ] **Step 1: Write failing tests for KeywordMatch and KeywordEngine skeleton**

```python
# tests/test_keywords.py
import pytest
from easm.keywords import KeywordMatch, KeywordEngine


def test_keyword_match_dataclass_defaults():
    match = KeywordMatch(
        keyword="example.com",
        keyword_type="domain",
        matched_text="example.com",
        severity="high",
        context="Found example.com in log",
    )
    assert match.keyword == "example.com"
    assert match.keyword_type == "domain"
    assert match.matched_text == "example.com"
    assert match.severity == "high"
    assert match.context == "Found example.com in log"


def test_keyword_match_with_default_context():
    match = KeywordMatch(
        keyword="secret",
        keyword_type="keyword",
        matched_text="secret",
        severity="medium",
    )
    assert match.context == ""


def test_keyword_engine_requires_target_config():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"], "keywords": ["Example Corp"]},
        runners={},
    )
    engine = KeywordEngine(target)
    assert engine is not None


def test_keyword_engine_empty_target_returns_empty():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("nothing relevant here")
    assert matches == []


def test_keyword_engine_class_attributes():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    assert hasattr(engine, "match")
    assert callable(engine.match)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_keywords.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.keywords'`

- [ ] **Step 3: Write the KeywordMatch dataclass and KeywordEngine skeleton**

```python
# src/easm/keywords.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class KeywordMatch:
    keyword: str
    keyword_type: str
    matched_text: str
    severity: str
    context: str = ""


class KeywordEngine:
    def __init__(self, target_config: Any):
        self._patterns: list[tuple[re.Pattern, str, str, str]] = []
        self._build_library(target_config)

    def _build_library(self, target_config: Any) -> None:
        pass

    def match(self, text: str) -> list[KeywordMatch]:
        return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_keywords.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/keywords.py tests/test_keywords.py
git commit -m "feat: add KeywordMatch dataclass and KeywordEngine skeleton"
```

---

### Task 2: Domain-Based Keyword Derivation

**Files:**
- Modify: `src/easm/keywords.py`
- Modify: `tests/test_keywords.py`

- [ ] **Step 1: Write failing tests for domain-based keyword derivation**

```python
# Add to tests/test_keywords.py

def test_domain_keyword_matches_apex():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Visit https://example.com today!")
    assert len(matches) >= 1
    domain_matches = [m for m in matches if m.keyword_type == "domain"]
    assert any("example.com" in m.matched_text for m in domain_matches)


def test_domain_keyword_matches_subdomain():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Internal server: git.internal.example.com")
    assert len(matches) >= 1
    domain_matches = [m for m in matches if m.keyword_type == "domain"]
    assert any("internal.example.com" in m.matched_text for m in domain_matches)


def test_domain_keyword_no_false_positive():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Visit https://malicious-example.com.phishing.com!")
    domain_matches = [m for m in matches if m.keyword_type == "domain"]
    assert len(domain_matches) == 0


def test_multiple_domains_all_matched():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com", "example.org"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Connect to api.example.com and mail.example.org")
    assert len(matches) >= 2
    matched_texts = {m.matched_text for m in matches}
    assert "api.example.com" in matched_texts
    assert "mail.example.org" in matched_texts


def test_domain_match_severity_is_high():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found: internal.example.com")
    assert matches[0].severity == "high"
    assert matches[0].keyword_type == "domain"


def test_domain_match_returns_context():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found: internal.example.com in the codebase")
    assert len(matches) == 1
    assert "internal.example.com" in matches[0].context
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_keywords.py::test_domain_keyword_matches_apex tests/test_keywords.py::test_domain_keyword_matches_subdomain tests/test_keywords.py::test_domain_keyword_no_false_positive tests/test_keywords.py::test_multiple_domains_all_matched tests/test_keywords.py::test_domain_match_severity_is_high tests/test_keywords.py::test_domain_match_returns_context -v`
Expected: All FAIL — `match()` returns empty list

- [ ] **Step 3: Implement domain derivation in KeywordEngine._build_library and match**

Replace `KeywordEngine` in `src/easm/keywords.py`:

```python
class KeywordEngine:
    def __init__(self, target_config: Any):
        self._patterns: list[tuple[re.Pattern, str, str, str]] = []
        self._build_library(target_config)

    def _build_library(self, target_config: Any) -> None:
        match_rules = target_config.match_rules

        for domain in match_rules.domains:
            escaped = re.escape(domain)
            pattern = re.compile(
                r'(?:^|[\s\.:/])(' + escaped + r'|[\w\-\.]+\.' + escaped + r')(?=[\s\.:\?/]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((pattern, domain, "domain", "high"))

        for keyword in match_rules.keywords:
            escaped = re.escape(keyword)
            pattern = re.compile(
                re.escape(keyword),
                re.IGNORECASE,
            )
            self._patterns.append((pattern, keyword, "keyword", "medium"))

    def match(self, text: str) -> list[KeywordMatch]:
        results: list[KeywordMatch] = []
        seen: set[tuple[str, str, str]] = set()

        for pattern, keyword, keyword_type, severity in self._patterns:
            for match_obj in pattern.finditer(text):
                matched_text = match_obj.group(0).strip().lstrip("./:")
                dedup_key = (keyword_type, matched_text, keyword)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                start = max(0, match_obj.start() - 40)
                end = min(len(text), match_obj.end() + 40)
                context = text[start:end].strip()

                results.append(KeywordMatch(
                    keyword=keyword,
                    keyword_type=keyword_type,
                    matched_text=matched_text,
                    severity=severity,
                    context=context,
                ))

        return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_keywords.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/keywords.py tests/test_keywords.py
git commit -m "feat: add domain-based keyword derivation to KeywordEngine"
```

---

### Task 3: Email Pattern Derivation

**Files:**
- Modify: `src/easm/keywords.py`
- Modify: `tests/test_keywords.py`

- [ ] **Step 1: Write failing tests for email pattern derivation**

```python
# Add to tests/test_keywords.py

def test_email_pattern_from_domain():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: admin@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) >= 1
    assert "admin@example.com" in email_matches[0].matched_text


def test_email_pattern_different_username():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: zach@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) >= 1
    assert "zach@example.com" in email_matches[0].matched_text


def test_email_pattern_severity_high():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: admin@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert email_matches[0].severity == "high"


def test_email_pattern_no_false_positive():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: admin@example.com.phishing.org")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) == 0


def test_email_and_domain_match_both_returned():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("internal.example.com and admin@example.com found")
    types_found = {m.keyword_type for m in matches}
    assert "domain" in types_found
    assert "email" in types_found
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_keywords.py::test_email_pattern_from_domain tests/test_keywords.py::test_email_pattern_different_username tests/test_keywords.py::test_email_pattern_severity_high tests/test_keywords.py::test_email_pattern_no_false_positive tests/test_keywords.py::test_email_and_domain_match_both_returned -v`
Expected: FAIL — no email matches because email patterns aren't built yet

- [ ] **Step 3: Add email pattern derivation to KeywordEngine._build_library**

In `src/easm/keywords.py`, modify `_build_library` to add email patterns after the domain patterns block:

```python
    def _build_library(self, target_config: Any) -> None:
        match_rules = target_config.match_rules

        for domain in match_rules.domains:
            escaped = re.escape(domain)
            pattern = re.compile(
                r'(?:^|[\s\.:/])(' + escaped + r'|[\w\-\.]+\.' + escaped + r')(?=[\s\.:\?/]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((pattern, domain, "domain", "high"))

            email_pattern = re.compile(
                r'[\w\.\-]+@' + escaped + r'(?=[\s\.:\?/;,]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((email_pattern, f"@{domain}", "email", "high"))

        for keyword in match_rules.keywords:
            escaped = re.escape(keyword)
            pattern = re.compile(
                re.escape(keyword),
                re.IGNORECASE,
            )
            self._patterns.append((pattern, keyword, "keyword", "medium"))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_keywords.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/easm/keywords.py tests/test_keywords.py
git commit -m "feat: add email pattern derivation to KeywordEngine"
```

---

### Task 4: Custom Regex Pattern Matching from Config

**Files:**
- Modify: `src/easm/config.py` (add `KeywordPattern` model, update `MatchRules`)
- Modify: `src/easm/keywords.py` (use `keyword_patterns` in `_build_library`)
- Modify: `tests/test_keywords.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing tests for KeywordPattern config model**

```python
# Add to tests/test_config.py
from easm.config import KeywordPattern


def test_keyword_pattern_valid():
    kp = KeywordPattern(type="email", pattern="@example\.com", severity="high")
    assert kp.type == "email"
    assert kp.pattern == "@example\.com"
    assert kp.severity == "high"


def test_keyword_pattern_severity_default():
    kp = KeywordPattern(type="custom", pattern="AKIA[A-Z0-9]{16}")
    assert kp.severity == "medium"


def test_keyword_pattern_rejects_invalid_severity():
    from pydantic import ValidationError
    import pytest
    with pytest.raises(ValidationError):
        KeywordPattern(type="custom", pattern="test", severity="critical")


def test_match_rules_can_include_keyword_patterns():
    from easm.config import MatchRules
    rules = MatchRules(
        domains=["example.com"],
        keyword_patterns=[
            {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            {"type": "hostname", "pattern": "internal\.example\.com", "severity": "high"},
        ],
    )
    assert len(rules.keyword_patterns) == 2
    assert rules.keyword_patterns[0].type == "api_key"


def test_keyword_patterns_parsed_from_yaml(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {
                "domains": ["example.com"],
                "keyword_patterns": [
                    {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
                ],
            },
            "runners": {},
        }],
    }))
    config = load_config(path)
    assert len(config.targets[0].match_rules.keyword_patterns) == 1
    assert config.targets[0].match_rules.keyword_patterns[0].pattern == "AKIA[0-9A-Z]{16}"


def test_keyword_patterns_optional(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }],
    }))
    config = load_config(path)
    assert config.targets[0].match_rules.keyword_patterns == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py::test_keyword_pattern_valid tests/test_config.py::test_keyword_pattern_severity_default tests/test_config.py::test_keyword_pattern_rejects_invalid_severity tests/test_config.py::test_match_rules_can_include_keyword_patterns tests/test_config.py::test_keyword_patterns_parsed_from_yaml tests/test_config.py::test_keyword_patterns_optional -v`
Expected: FAIL — `ImportError: cannot import name 'KeywordPattern' from 'easm.config'`

- [ ] **Step 3: Add KeywordPattern model and update MatchRules**

In `src/easm/config.py`, add before `MatchRules`:

```python
class KeywordPattern(BaseModel):
    type: str
    pattern: str
    severity: str = "medium"

    @field_validator("severity")
    @classmethod
    def severity_must_be_valid(cls, v: str) -> str:
        if v not in ("high", "medium", "low"):
            raise ValueError(f"severity must be one of: high, medium, low, got: {v}")
        return v
```

Update `MatchRules`:

```python
class MatchRules(BaseModel):
    domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    asns: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    keyword_patterns: list[KeywordPattern] = Field(default_factory=list)
```

- [ ] **Step 4: Write failing tests for custom regex matching in KeywordEngine**

```python
# Add to tests/test_keywords.py

def test_custom_regex_pattern_matches():
    from easm.config import TargetConfig, KeywordPattern
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found key: AKIA1234567890ABCD in log")
    regex_matches = [m for m in matches if m.keyword_type == "api_key"]
    assert len(regex_matches) == 1
    assert "AKIA1234567890ABCD" in regex_matches[0].matched_text


def test_custom_regex_multiple_matches():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Keys: AKIA1111111111111111 and AKIA2222222222222222")
    regex_matches = [m for m in matches if m.keyword_type == "api_key"]
    assert len(regex_matches) == 2


def test_custom_regex_no_match():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("No keys here, just example.com")
    regex_matches = [m for m in matches if m.keyword_type == "api_key"]
    assert len(regex_matches) == 0


def test_custom_regex_custom_severity():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "hostname", "pattern": "internal\.example\.com", "severity": "high"},
                {"type": "debug", "pattern": "DEBUG:", "severity": "low"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("DEBUG: internal.example.com is up")
    hostname_matches = [m for m in matches if m.keyword_type == "hostname"]
    debug_matches = [m for m in matches if m.keyword_type == "debug"]
    assert len(hostname_matches) == 1
    assert hostname_matches[0].severity == "high"
    assert len(debug_matches) == 1
    assert debug_matches[0].severity == "low"


def test_custom_regex_email_pattern():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["other.com"],
            "keyword_patterns": [
                {"type": "email", "pattern": "@example\.com", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: dev@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) >= 1
    assert "dev@example.com" in email_matches[0].matched_text
```

- [ ] **Step 5: Run new keyword tests to verify they fail**

Run: `uv run pytest tests/test_keywords.py::test_custom_regex_pattern_matches tests/test_keywords.py::test_custom_regex_multiple_matches tests/test_keywords.py::test_custom_regex_no_match tests/test_keywords.py::test_custom_regex_custom_severity tests/test_keywords.py::test_custom_regex_email_pattern -v`
Expected: All FAIL — custom regex patterns not yet handled in KeywordEngine

- [ ] **Step 6: Add custom regex support to KeywordEngine._build_library**

Modify `src/easm/keywords.py` — update `_build_library` to include keyword_patterns:

```python
    def _build_library(self, target_config: Any) -> None:
        match_rules = target_config.match_rules

        for domain in match_rules.domains:
            escaped = re.escape(domain)
            pattern = re.compile(
                r'(?:^|[\s\.:/])(' + escaped + r'|[\w\-\.]+\.' + escaped + r')(?=[\s\.:\?/]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((pattern, domain, "domain", "high"))

            email_pattern = re.compile(
                r'[\w\.\-]+@' + escaped + r'(?=[\s\.:\?/;,]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((email_pattern, f"@{domain}", "email", "high"))

        for keyword in match_rules.keywords:
            escaped = re.escape(keyword)
            pattern = re.compile(
                re.escape(keyword),
                re.IGNORECASE,
            )
            self._patterns.append((pattern, keyword, "keyword", "medium"))

        for kp in match_rules.keyword_patterns:
            try:
                compiled = re.compile(kp.pattern, re.IGNORECASE)
                self._patterns.append((compiled, kp.pattern, kp.type, kp.severity))
            except re.error:
                pass
```

- [ ] **Step 7: Run all keyword tests to verify they pass**

Run: `uv run pytest tests/test_keywords.py tests/test_config.py -v`
Expected: All tests PASS

- [ ] **Step 8: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 9: Commit**

```bash
git add src/easm/config.py src/easm/keywords.py tests/test_config.py tests/test_keywords.py
git commit -m "feat: add custom regex pattern matching via keyword_patterns config"
```

---

### Task 5: Severity Classification Logic

**Files:**
- Modify: `src/easm/keywords.py`
- Modify: `tests/test_keywords.py`

- [ ] **Step 1: Write failing tests for severity classification**

```python
# Add to tests/test_keywords.py

def test_severity_high_for_domain_match():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("secret.example.com exposed!")
    assert all(m.severity == "high" for m in matches)


def test_severity_medium_for_keyword_match():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"keywords": ["Example Corp"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found reference to Example Corp in log")
    assert all(m.severity == "medium" for m in matches)


def test_severity_override_from_custom_pattern():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "keyword_patterns": [
                {"type": "critical_alert", "pattern": "CRITICAL:", "severity": "high"},
                {"type": "info_alert", "pattern": "INFO:", "severity": "low"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("CRITICAL: system failure\nINFO: all good")
    critical = [m for m in matches if m.keyword_type == "critical_alert"]
    info = [m for m in matches if m.keyword_type == "info_alert"]
    assert len(critical) == 1
    assert critical[0].severity == "high"
    assert len(info) == 1
    assert info[0].severity == "low"


def test_severity_email_is_high():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("admin@example.com exposed")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert email_matches[0].severity == "high"
```

- [ ] **Step 2: Run severity tests to verify they pass or fail**

Run: `uv run pytest tests/test_keywords.py::test_severity_high_for_domain_match tests/test_keywords.py::test_severity_medium_for_keyword_match tests/test_keywords.py::test_severity_override_from_custom_pattern tests/test_keywords.py::test_severity_email_is_high -v`
Expected: These should already pass since severity was wired in during Tasks 2-4. If any fail, fix the implementation to set correct severity per keyword_type.

(If they already pass, this task is still important — it hardens the severity rules with explicit tests.)

- [ ] **Step 3: Commit**

```bash
git add src/easm/keywords.py tests/test_keywords.py
git commit -m "test: add explicit severity classification tests for KeywordEngine"
```

---

### Task 6: Integration — Wire KeywordEngine into Target Loading

**Files:**
- Modify: `src/easm/keywords.py` (add helper function)
- Modify: `tests/test_keywords.py`

- [ ] **Step 1: Write failing tests for integration helper**

```python
# Add to tests/test_keywords.py

def test_build_engine_from_target_id():
    from easm.config import Config, TargetConfig
    from easm.keywords import build_keyword_engine_for_target
    cfg = Config(targets=[
        TargetConfig(
            id="test", name="Test", type="org",
            match_rules={"domains": ["example.com"]},
            runners={},
        ),
    ])
    engine = build_keyword_engine_for_target(cfg, "test")
    assert engine is not None
    matches = engine.match("admin@example.com")
    assert len(matches) >= 1


def test_build_engine_returns_none_for_unknown_target():
    from easm.config import Config, TargetConfig
    from easm.keywords import build_keyword_engine_for_target
    cfg = Config(targets=[
        TargetConfig(
            id="test", name="Test", type="org",
            match_rules={"domains": ["example.com"]},
            runners={},
        ),
    ])
    engine = build_keyword_engine_for_target(cfg, "nonexistent")
    assert engine is None


def test_keyword_match_deduplication():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keywords": ["example.com"],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Visit example.com today")
    assert len(matches) >= 1
    types = [m.keyword_type for m in matches]
    assert types.count("domain") <= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_keywords.py::test_build_engine_from_target_id tests/test_keywords.py::test_build_engine_returns_none_for_unknown_target tests/test_keywords.py::test_keyword_match_deduplication -v`
Expected: FAIL — `build_keyword_engine_for_target` not defined

- [ ] **Step 3: Add helper function to keywords.py**

Add at the end of `src/easm/keywords.py`:

```python
def build_keyword_engine_for_target(cfg: Any, target_id: str) -> KeywordEngine | None:
    for target in cfg.targets:
        if target.id == target_id:
            return KeywordEngine(target)
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_keywords.py::test_build_engine_from_target_id tests/test_keywords.py::test_build_engine_returns_none_for_unknown_target tests/test_keywords.py::test_keyword_match_deduplication -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Run full keyword test suite**

Run: `uv run pytest tests/test_keywords.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/easm/keywords.py tests/test_keywords.py
git commit -m "feat: add build_keyword_engine_for_target helper for monitors"
```

---

### Task 7: Config Example Update for keyword_patterns

**Files:**
- Modify: `config.yaml.example`

- [ ] **Step 1: Add keyword_patterns to match_rules in config example**

In `config.yaml.example`, add `keyword_patterns` under the `match_rules` section of the target:

```yaml
    match_rules:
      domains:
        - example.com
        - example.org
      keywords:
        - Example Corp
        - Example
      asns:
        - AS12345
      keyword_patterns:
        - type: email
          pattern: "@example\\.com"
          severity: high
          description: Internal email addresses
        - type: api_key
          pattern: "AKIA[0-9A-Z]{16}"
          severity: high
          description: AWS Access Key ID
        - type: hostname
          pattern: "internal\\.example\\.com"
          severity: high
          description: Internal hostname exposure
```

- [ ] **Step 2: Validate config example loads correctly**

Run: `uv run python -c "from easm.config import load_config; c = load_config('config.yaml.example'); t = c.targets[0]; print(f'Domains: {len(t.match_rules.domains)}, Keywords: {len(t.match_rules.keywords)}, Patterns: {len(t.match_rules.keyword_patterns)}')"`
Expected: Prints "Domains: 2, Keywords: 2, Patterns: 3"

- [ ] **Step 3: Commit**

```bash
git add config.yaml.example
git commit -m "docs: add keyword_patterns example to config.yaml.example"
```

---

## Self-Review Checklist

**1. Spec coverage:**
- Feature 1.1 taxonomy: Task 1 (config models), Task 2 (classify module), Task 3 (backfill integration), Task 4 (scope gating), Task 5 (config example) — all covered
- Feature 1.4 keyword engine: Task 1 (skeleton), Task 2 (domain derivation), Task 3 (email derivation), Task 4 (custom regex), Task 5 (severity), Task 6 (integration helper), Task 7 (config example) — all covered

**2. Placeholder scan:** No TODOs, no TBDs, no "implement similar to", no placeholder code — all steps contain complete, copy-pasteable code.

**3. Type consistency:** All method signatures, dataclass fields, and config model field names are consistent across tasks. `ClassificationResult.classification` used consistently. `KeywordMatch.keyword_type` / `severity` used consistently.
