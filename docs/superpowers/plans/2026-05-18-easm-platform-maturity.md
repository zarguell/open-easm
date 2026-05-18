# EASM Platform Maturity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn open-easm from an enumeration-and-findings engine into an evidence-rich EASM platform that can feed a source of truth with discovered assets, confidence, change history, risk, and remediation context.

**Architecture:** Keep open-easm as the discovery and evidence producer. Do not import authoritative ownership/CMDB/cloud inventory data into open-easm in this plan; instead, enrich discovered assets with confidence, evidence, lifecycle state, risk scores, and outbound export/feed APIs that downstream systems can consume. Build this in layers over the existing `entities`, `raw_events`, `entity_relationships`, `findings`, and API patterns.

**Tech Stack:** Python 3.14, asyncpg/Postgres JSONB, Alembic, pytest/pytest-asyncio, FastAPI, Docker Compose test harness.

---

## Non-Negotiable Scope Boundary

Source-of-truth imports are **out of scope**.

This plan must not add:

- CMDB import.
- Cloud account inventory import.
- IPAM import.
- HR/team ownership import.
- Asset owner import from Jira/ServiceNow/Linear/GitHub.

This plan should add:

- Discovered asset records with confidence and evidence.
- Change events and deltas.
- Risk/exposure scoring based on observed facts.
- Outbound APIs and feed formats that a source-of-truth system can ingest.
- Manual annotations that live in open-easm, such as triage state or optional owner notes, without treating them as authoritative imports.

---

## Current Repo Context

Relevant existing capabilities:

- `src/easm/store.py`
  - `upsert_entity()` handles entity dedupe, `first_seen_at`, `last_seen_at`, and JSONB attributes.
  - raw event links are stored in `entity_raw_event_links`.
  - `create_finding()`, `list_findings()`, and triage state already exist.
- `src/easm/api/routes/entities.py`
  - has `/api/entities`, `/api/entities/count`, `/api/entities/counts`, and entity detail.
- `src/easm/api/routes/findings.py`
  - has finding list/detail/status update.
- `src/easm/runners/schemas.py`
  - converts runner/pivot raw events into entity candidates.
- `src/easm/certificates/`
  - certificate lifecycle profile/analysis/findings already exist.
- `src/easm/runtime.py`
  - runtime policy controls simulation/offline behavior.

Important constraints:

- Preserve Docker backend gate:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

- No active public scanning in tests.
- Keep source-of-truth feed outbound-only.

---

## Target Capability Model

After this plan, each managed/discovered asset should be able to answer:

- What is it?
- Why do we think it belongs to the target?
- How confident are we?
- What changed?
- What evidence supports the current state?
- What is risky about it?
- What should a downstream source-of-truth/ticketing system ingest?

Target data attached to each entity:

```python
{
    "asset_profile": {
        "confidence": {
            "score": 85,
            "level": "high",
            "reasons": ["direct_target_match", "observed_from_tls", "multi_source_seen"]
        },
        "lifecycle": {
            "state": "active",
            "first_seen_at": "2026-05-18T12:00:00+00:00",
            "last_seen_at": "2026-05-18T12:30:00+00:00",
            "last_changed_at": "2026-05-18T12:30:00+00:00"
        },
        "evidence": [
            {
                "source": "subfinder",
                "raw_event_id": "uuid",
                "observed_at": "2026-05-18T12:00:00+00:00",
                "summary": "subfinder returned app.example.invalid"
            }
        ],
        "risk": {
            "score": 72,
            "level": "high",
            "reasons": ["internet_exposed", "critical_finding", "weak_certificate_deployed"]
        },
        "source_of_truth_feed": {
            "eligible": true,
            "last_exported_at": null,
            "last_export_hash": null
        }
    }
}
```

---

## File Structure

Create:

- `src/easm/assets/__init__.py` - asset helper exports.
- `src/easm/assets/profile.py` - confidence/evidence profile helpers.
- `src/easm/assets/scoring.py` - exposure/risk scoring helpers.
- `src/easm/assets/change.py` - change event construction and diff helpers.
- `src/easm/assets/export.py` - outbound source-of-truth feed serialization.
- `src/easm/api/routes/assets.py` - asset inventory, change, and export endpoints.
- `alembic/versions/20260518_0002_asset_change_events.py` - change event ledger table.
- `tests/test_assets/test_profile.py`
- `tests/test_assets/test_scoring.py`
- `tests/test_assets/test_change_events.py`
- `tests/test_assets/test_export.py`
- `tests/test_api/test_assets.py`
- `docs/easm-platform-maturity.md`

Modify:

- `src/easm/store.py` - add asset profile update, change ledger, inventory, and export query methods.
- `src/easm/runners/engine.py` - update asset profile/change ledger after entity upsert.
- `src/easm/pivot/worker.py` - update asset profile/change ledger after pivot materialization.
- `src/easm/api/app.py` - register asset router.
- `AGENTS.md` - document source-of-truth boundary and asset profile invariants.

---

## Task 1: Asset Profile Helpers

**Files:**
- Create: `src/easm/assets/__init__.py`
- Create: `src/easm/assets/profile.py`
- Create: `tests/test_assets/test_profile.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_assets/test_profile.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from easm.assets.profile import (
    build_asset_evidence,
    build_asset_profile,
    merge_asset_profiles,
)


OBSERVED_AT = datetime(2026, 5, 18, 12, 0, tzinfo=UTC)


def test_build_asset_evidence_records_source_and_summary() -> None:
    evidence = build_asset_evidence(
        source="subfinder",
        raw_event_id="00000000-0000-0000-0000-000000000001",
        observed_at=OBSERVED_AT,
        summary="subfinder returned app.example.invalid",
    )

    assert evidence == {
        "source": "subfinder",
        "raw_event_id": "00000000-0000-0000-0000-000000000001",
        "observed_at": "2026-05-18T12:00:00+00:00",
        "summary": "subfinder returned app.example.invalid",
    }


def test_build_asset_profile_scores_direct_target_match_high() -> None:
    profile = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["subfinder", "tls_cert"],
        evidence=[
            build_asset_evidence(
                source="subfinder",
                raw_event_id=None,
                observed_at=OBSERVED_AT,
                summary="subfinder returned app.example.invalid",
            )
        ],
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "high"
    assert profile["confidence"]["score"] >= 80
    assert "direct_target_match" in profile["confidence"]["reasons"]
    assert "multi_source_seen" in profile["confidence"]["reasons"]
    assert profile["lifecycle"]["state"] == "active"
    assert profile["source_of_truth_feed"]["eligible"] is True


def test_merge_asset_profiles_dedupes_sources_and_evidence() -> None:
    first = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["subfinder"],
        evidence=[build_asset_evidence("subfinder", "id-1", OBSERVED_AT, "first")],
        observed_at=OBSERVED_AT,
    )
    second = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["tls_cert"],
        evidence=[build_asset_evidence("tls_cert", "id-2", OBSERVED_AT, "second")],
        observed_at=OBSERVED_AT,
    )

    merged = merge_asset_profiles(first, second)

    assert merged["sources"] == ["subfinder", "tls_cert"]
    assert len(merged["evidence"]) == 2
    assert merged["confidence"]["level"] == "high"
```

- [ ] **Step 2: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets/test_profile.py"
```

Expected:

```text
ModuleNotFoundError: No module named 'easm.assets'
```

- [ ] **Step 3: Implement helpers**

Create `src/easm/assets/__init__.py`:

```python
from easm.assets.profile import (
    build_asset_evidence,
    build_asset_profile,
    merge_asset_profiles,
)

__all__ = [
    "build_asset_evidence",
    "build_asset_profile",
    "merge_asset_profiles",
]
```

Create `src/easm/assets/profile.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


HIGH_CONFIDENCE = 80
MEDIUM_CONFIDENCE = 50


def build_asset_evidence(
    source: str,
    raw_event_id: str | None,
    observed_at: datetime,
    summary: str,
) -> dict[str, Any]:
    return {
        "source": source,
        "raw_event_id": raw_event_id,
        "observed_at": _iso(observed_at),
        "summary": summary,
    }


def build_asset_profile(
    *,
    entity_type: str,
    entity_value: str,
    target_domains: list[str],
    sources: list[str],
    evidence: list[dict[str, Any]],
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    observed = observed_at or datetime.now(UTC)
    confidence = _confidence(entity_type, entity_value, target_domains, sources)
    return {
        "sources": sorted(set(sources)),
        "confidence": confidence,
        "lifecycle": {
            "state": "active",
            "first_seen_at": _iso(observed),
            "last_seen_at": _iso(observed),
            "last_changed_at": _iso(observed),
        },
        "evidence": _dedupe_evidence(evidence),
        "risk": {"score": 0, "level": "info", "reasons": []},
        "source_of_truth_feed": {
            "eligible": confidence["score"] >= MEDIUM_CONFIDENCE,
            "last_exported_at": None,
            "last_export_hash": None,
        },
    }
```

Also implement `_confidence()`, `_dedupe_evidence()`, `_iso()`, and `merge_asset_profiles(existing, incoming)`.

Confidence rules:

- `direct_target_match`: hostname/domain equals target domain or ends with `.{target_domain}` -> +60.
- `multi_source_seen`: two or more sources -> +25.
- `direct_target_domain`: entity type `domain` and exact target domain -> +25.
- `certificate_only`: only source is `crtsh` or `certstream` -> cap at 60.
- score max 100.
- level: `high >= 80`, `medium >= 50`, otherwise `low`.

- [ ] **Step 4: Verify tests pass**

Run the same command.

Expected:

```text
3 passed
```

---

## Task 2: Asset Risk Scoring

**Files:**
- Create: `src/easm/assets/scoring.py`
- Create: `tests/test_assets/test_scoring.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_assets/test_scoring.py`:

```python
from __future__ import annotations

from easm.assets.scoring import score_asset_exposure


def test_score_asset_exposure_prioritizes_critical_findings() -> None:
    score = score_asset_exposure(
        entity={
            "entity_type": "hostname",
            "entity_value": "app.example.invalid",
            "attributes": {
                "asset_profile": {"confidence": {"score": 90}},
                "ports": [443],
            },
        },
        findings=[{"risk": "critical", "rule_id": "certificate_deployed_expired"}],
    )

    assert score["level"] == "critical"
    assert score["score"] >= 90
    assert "critical_finding" in score["reasons"]


def test_score_asset_exposure_detects_internet_service() -> None:
    score = score_asset_exposure(
        entity={
            "entity_type": "ip",
            "entity_value": "198.51.100.10",
            "attributes": {"ports": [22, 443]},
        },
        findings=[],
    )

    assert score["level"] in {"medium", "high"}
    assert "internet_exposed_service" in score["reasons"]


def test_score_asset_exposure_includes_certificate_risk() -> None:
    score = score_asset_exposure(
        entity={
            "entity_type": "certificate",
            "entity_value": "cert-hash",
            "attributes": {
                "certificate_profile": {
                    "analysis": {
                        "risk": "high",
                        "reasons": ["rsa_key_too_small"],
                    }
                }
            },
        },
        findings=[],
    )

    assert score["level"] == "high"
    assert "certificate:rsa_key_too_small" in score["reasons"]
```

- [ ] **Step 2: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets/test_scoring.py"
```

Expected:

```text
ModuleNotFoundError or ImportError
```

- [ ] **Step 3: Implement scoring**

Create `src/easm/assets/scoring.py`:

```python
from __future__ import annotations

from typing import Any


RISK_POINTS = {"info": 5, "low": 20, "medium": 45, "high": 75, "critical": 95}
RISK_LEVELS = [(90, "critical"), (70, "high"), (40, "medium"), (15, "low"), (0, "info")]


def score_asset_exposure(
    *,
    entity: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    ...
```

Required rules:

- Critical finding -> score at least 95, reason `critical_finding`.
- High finding -> score at least 75, reason `high_finding`.
- Open ports on `ip` or `hostname` -> add at least 45, reason `internet_exposed_service`.
- Certificate profile analysis risk -> map through `RISK_POINTS`; prefix reasons with `certificate:`.
- Confidence score should not by itself create risk, but should be included in output as `confidence_score`.

- [ ] **Step 4: Verify tests pass**

Run same command.

Expected:

```text
3 passed
```

---

## Task 3: Asset Change Event Ledger

**Files:**
- Create: `alembic/versions/20260518_0002_asset_change_events.py`
- Create: `src/easm/assets/change.py`
- Modify: `src/easm/store.py`
- Create: `tests/test_assets/test_change_events.py`

- [ ] **Step 1: Add migration**

Create `alembic/versions/20260518_0002_asset_change_events.py`:

```python
"""asset change events

Revision ID: 20260518_0002
Revises: <current head revision>
Create Date: 2026-05-18
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260518_0002"
down_revision = "<fill with current alembic head>"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_change_events",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", sa.Text(), nullable=False, server_default="default"),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("change_type", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("before", sa.JSON(), nullable=True),
        sa.Column("after", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_asset_change_events_target_created", "asset_change_events", ["target_id", "created_at"])
    op.create_index("idx_asset_change_events_entity", "asset_change_events", ["entity_id"])


def downgrade() -> None:
    op.drop_index("idx_asset_change_events_entity", table_name="asset_change_events")
    op.drop_index("idx_asset_change_events_target_created", table_name="asset_change_events")
    op.drop_table("asset_change_events")
```

Before committing the plan execution, replace `<fill with current alembic head>` with the actual current revision from `alembic/versions`.

- [ ] **Step 2: Write failing store tests**

Create `tests/test_assets/test_change_events.py`:

```python
from __future__ import annotations

import pytest

from easm.store import Store


@pytest.mark.asyncio
@pytest.mark.db
async def test_record_and_list_asset_change_events(db_pool):
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        "default",
        "target-1",
        "hostname",
        "app.example.invalid",
        {"source": "subfinder"},
    )

    event_id = await store.record_asset_change_event(
        org_id="default",
        target_id="target-1",
        entity_id=entity_id,
        change_type="asset_discovered",
        source="subfinder",
        summary="Discovered app.example.invalid",
        before=None,
        after={"entity_value": "app.example.invalid"},
    )

    rows = await store.list_asset_change_events(target_id="target-1")

    assert str(event_id) == rows[0]["id"]
    assert rows[0]["change_type"] == "asset_discovered"
    assert rows[0]["summary"] == "Discovered app.example.invalid"
```

- [ ] **Step 3: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets/test_change_events.py"
```

Expected before implementation:

```text
AttributeError: 'Store' object has no attribute 'record_asset_change_event'
```

- [ ] **Step 4: Implement store methods**

Add to `Store`:

```python
async def record_asset_change_event(
    self,
    *,
    org_id: str,
    target_id: str,
    entity_id: uuid.UUID,
    change_type: str,
    source: str,
    summary: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> uuid.UUID:
    ...


async def list_asset_change_events(
    self,
    target_id: str | None = None,
    entity_id: uuid.UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    ...
```

Use `json.dumps()` for `before` and `after`, return ISO timestamps in row dicts.

- [ ] **Step 5: Verify tests pass**

Run same command.

Expected:

```text
1 passed
```

---

## Task 4: Asset Profile Store Integration

**Files:**
- Modify: `src/easm/store.py`
- Create: `tests/test_assets/test_asset_profile_store.py`

- [ ] **Step 1: Write failing DB tests**

Create `tests/test_assets/test_asset_profile_store.py`:

```python
from __future__ import annotations

import pytest

from easm.store import Store


@pytest.mark.asyncio
@pytest.mark.db
async def test_update_entity_asset_profile_merges_profile(db_pool):
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        "default",
        "target-1",
        "hostname",
        "app.example.invalid",
        {"source": "subfinder"},
    )

    await store.update_entity_asset_profile(
        entity_id,
        {
            "confidence": {"score": 85, "level": "high", "reasons": ["direct_target_match"]},
            "sources": ["subfinder"],
            "evidence": [{"source": "subfinder", "summary": "observed"}],
        },
    )

    row = await db_pool.fetchrow("SELECT attributes FROM entities WHERE id = $1", entity_id)
    assert row["attributes"]["asset_profile"]["confidence"]["score"] == 85
    assert row["attributes"]["asset_profile"]["sources"] == ["subfinder"]
```

- [ ] **Step 2: Verify test fails**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets/test_asset_profile_store.py"
```

Expected:

```text
AttributeError: 'Store' object has no attribute 'update_entity_asset_profile'
```

- [ ] **Step 3: Implement store method**

Add to `Store`:

```python
async def update_entity_asset_profile(
    self,
    entity_id: uuid.UUID,
    asset_profile: dict[str, Any],
) -> None:
    await self.pool.execute(
        """
        UPDATE entities
        SET attributes = jsonb_set(
            COALESCE(attributes, '{}'::jsonb),
            '{asset_profile}',
            $1::jsonb,
            true
        )
        WHERE id = $2
        """,
        json.dumps(asset_profile),
        entity_id,
    )
```

- [ ] **Step 4: Verify tests pass**

Run same command.

Expected:

```text
1 passed
```

---

## Task 5: Asset Inventory And Change API

**Files:**
- Create: `src/easm/api/routes/assets.py`
- Modify: `src/easm/api/app.py`
- Modify: `src/easm/store.py`
- Create: `tests/test_api/test_assets.py`

- [ ] **Step 1: Add store inventory method**

Add to `Store`:

```python
async def list_asset_inventory(
    self,
    target_id: str | None = None,
    confidence_level: str | None = None,
    risk_level: str | None = None,
    feed_eligible: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    ...
```

Return fields:

- `entity_id`
- `org_id`
- `target_id`
- `entity_type`
- `entity_value`
- `first_seen_at`
- `last_seen_at`
- `confidence_score`
- `confidence_level`
- `risk_score`
- `risk_level`
- `feed_eligible`
- `sources`
- `evidence_count`

- [ ] **Step 2: Write failing API tests**

Create `tests/test_api/test_assets.py`:

```python
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from easm.api import deps
from easm.api.app import create_app
from easm.config import Config, MatchRules, TargetConfig
from easm.store import Store


@pytest.fixture
def test_config():
    return Config(targets=[
        TargetConfig(
            id="target-1",
            name="Target",
            type="organization",
            enabled=True,
            match_rules=MatchRules(domains=["example.invalid"]),
            runners={},
        )
    ])


@pytest.fixture
async def test_api(test_config, db_pool, scheduler):
    app = create_app()
    deps.set_config(test_config)
    deps.set_store(Store(db_pool))
    deps.set_scheduler(scheduler)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def seeded_asset(db_pool):
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        "default",
        "target-1",
        "hostname",
        "app.example.invalid",
        {
            "asset_profile": {
                "sources": ["subfinder"],
                "confidence": {"score": 90, "level": "high", "reasons": ["direct_target_match"]},
                "risk": {"score": 45, "level": "medium", "reasons": ["internet_exposed_service"]},
                "evidence": [{"source": "subfinder", "summary": "observed"}],
                "source_of_truth_feed": {"eligible": True},
            }
        },
    )
    await store.record_asset_change_event(
        org_id="default",
        target_id="target-1",
        entity_id=entity_id,
        change_type="asset_discovered",
        source="subfinder",
        summary="Discovered app.example.invalid",
        before=None,
        after={"entity_value": "app.example.invalid"},
    )


@pytest.mark.asyncio
async def test_list_asset_inventory(test_api, seeded_asset):
    resp = await test_api.get("/api/assets/inventory")

    assert resp.status_code == 200
    data = resp.json()
    assert data["assets"][0]["entity_value"] == "app.example.invalid"
    assert data["assets"][0]["confidence_level"] == "high"
    assert data["assets"][0]["feed_eligible"] is True


@pytest.mark.asyncio
async def test_list_asset_changes(test_api, seeded_asset):
    resp = await test_api.get("/api/assets/changes?target_id=target-1")

    assert resp.status_code == 200
    data = resp.json()
    assert data["changes"][0]["change_type"] == "asset_discovered"
```

- [ ] **Step 3: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_api/test_assets.py"
```

Expected:

```text
assert 404 == 200
```

- [ ] **Step 4: Implement routes**

Create `src/easm/api/routes/assets.py`:

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from easm.api.deps import get_store
from easm.store import Store

router = APIRouter(tags=["assets"])


@router.get("/assets/inventory")
async def list_asset_inventory(
    target_id: str | None = Query(None),
    confidence_level: str | None = Query(None),
    risk_level: str | None = Query(None),
    feed_eligible: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    assets = await store.list_asset_inventory(
        target_id=target_id,
        confidence_level=confidence_level,
        risk_level=risk_level,
        feed_eligible=feed_eligible,
        limit=limit,
        offset=offset,
    )
    return {"assets": assets}


@router.get("/assets/changes")
async def list_asset_changes(
    target_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    changes = await store.list_asset_change_events(
        target_id=target_id,
        limit=limit,
        offset=offset,
    )
    return {"changes": changes}
```

Register in `src/easm/api/app.py`:

```python
from easm.api.routes import assets as assets_route
...
app.include_router(assets_route.router, prefix="/api")
```

- [ ] **Step 5: Verify tests pass**

Run same command.

Expected:

```text
2 passed
```

---

## Task 6: Outbound Source-Of-Truth Feed

**Files:**
- Create: `src/easm/assets/export.py`
- Modify: `src/easm/api/routes/assets.py`
- Create: `tests/test_assets/test_export.py`
- Modify: `tests/test_api/test_assets.py`

- [ ] **Step 1: Write export unit tests**

Create `tests/test_assets/test_export.py`:

```python
from __future__ import annotations

import json

from easm.assets.export import asset_to_source_of_truth_record, assets_to_ndjson


def test_asset_to_source_of_truth_record_is_outbound_only() -> None:
    record = asset_to_source_of_truth_record({
        "entity_id": "entity-1",
        "target_id": "target-1",
        "entity_type": "hostname",
        "entity_value": "app.example.invalid",
        "confidence_score": 90,
        "confidence_level": "high",
        "risk_score": 45,
        "risk_level": "medium",
        "sources": ["subfinder"],
    })

    assert record["external_id"] == "open-easm:entity-1"
    assert record["system_of_record"] == "open-easm"
    assert record["asset"]["value"] == "app.example.invalid"
    assert "owner" not in record


def test_assets_to_ndjson_outputs_one_json_object_per_line() -> None:
    payload = assets_to_ndjson([
        {"entity_id": "a", "entity_type": "domain", "entity_value": "example.invalid"},
        {"entity_id": "b", "entity_type": "hostname", "entity_value": "app.example.invalid"},
    ])

    lines = payload.splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["external_id"] == "open-easm:a"
```

- [ ] **Step 2: Implement export helpers**

Create `src/easm/assets/export.py`:

```python
from __future__ import annotations

import json
from typing import Any


def asset_to_source_of_truth_record(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "external_id": f"open-easm:{asset['entity_id']}",
        "system_of_record": "open-easm",
        "target_id": asset.get("target_id"),
        "asset": {
            "type": asset.get("entity_type"),
            "value": asset.get("entity_value"),
        },
        "confidence": {
            "score": asset.get("confidence_score"),
            "level": asset.get("confidence_level"),
        },
        "risk": {
            "score": asset.get("risk_score"),
            "level": asset.get("risk_level"),
        },
        "sources": asset.get("sources", []),
        "first_seen_at": asset.get("first_seen_at"),
        "last_seen_at": asset.get("last_seen_at"),
    }


def assets_to_ndjson(assets: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(asset_to_source_of_truth_record(asset), sort_keys=True) for asset in assets)
```

- [ ] **Step 3: Add export API test**

Append to `tests/test_api/test_assets.py`:

```python
@pytest.mark.asyncio
async def test_export_asset_feed_ndjson(test_api, seeded_asset):
    resp = await test_api.get("/api/assets/export.ndjson")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    first = resp.text.splitlines()[0]
    assert '"system_of_record": "open-easm"' in first
    assert "app.example.invalid" in first
```

- [ ] **Step 4: Implement route**

In `src/easm/api/routes/assets.py`, add:

```python
from fastapi.responses import PlainTextResponse
from easm.assets.export import assets_to_ndjson


@router.get("/assets/export.ndjson")
async def export_asset_feed_ndjson(
    target_id: str | None = Query(None),
    store: Store = Depends(get_store),
):
    assets = await store.list_asset_inventory(target_id=target_id, feed_eligible=True, limit=500, offset=0)
    return PlainTextResponse(assets_to_ndjson(assets), media_type="application/x-ndjson")
```

- [ ] **Step 5: Verify tests pass**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets/test_export.py tests/test_api/test_assets.py"
```

Expected:

```text
passed
```

---

## Task 7: Wire Asset Profile Updates Into Runner And Pivot Materialization

**Files:**
- Modify: `src/easm/runners/engine.py`
- Modify: `src/easm/pivot/worker.py`
- Create: `tests/test_assets/test_materialization_asset_profile.py`

- [ ] **Step 1: Write failing integration tests**

Create `tests/test_assets/test_materialization_asset_profile.py`:

```python
from __future__ import annotations

import pytest

from easm.runners.schemas import EntityCandidate
from easm.store import Store


@pytest.mark.asyncio
@pytest.mark.db
async def test_materialized_entity_gets_asset_profile(db_pool):
    store = Store(db_pool)
    entity_id, _ = await store.upsert_entity(
        "default",
        "target-1",
        "hostname",
        "app.example.invalid",
        {"source": "subfinder"},
    )

    await store.apply_asset_profile_for_entity(
        org_id="default",
        target_id="target-1",
        entity_id=entity_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        source="subfinder",
        raw_event_id=None,
        target_domains=["example.invalid"],
        summary="subfinder observed app.example.invalid",
    )

    row = await db_pool.fetchrow("SELECT attributes FROM entities WHERE id = $1", entity_id)
    profile = row["attributes"]["asset_profile"]
    assert profile["confidence"]["level"] == "high"
    assert profile["source_of_truth_feed"]["eligible"] is True
```

- [ ] **Step 2: Implement store helper**

Add to `Store`:

```python
async def apply_asset_profile_for_entity(
    self,
    *,
    org_id: str,
    target_id: str,
    entity_id: uuid.UUID,
    entity_type: str,
    entity_value: str,
    source: str,
    raw_event_id: uuid.UUID | None,
    target_domains: list[str],
    summary: str,
) -> None:
    ...
```

It should:

- Fetch existing `attributes.asset_profile`.
- Build incoming profile via `build_asset_profile()`.
- Merge via `merge_asset_profiles()`.
- Score risk via `score_asset_exposure()` with current findings for the entity if practical; if not, keep risk from existing profile.
- Update entity asset profile.
- Record `asset_discovered` when no existing profile existed, else `asset_observed`.

- [ ] **Step 3: Wire runner engine**

In `src/easm/runners/engine.py`, after successful `store.upsert_entity(...)`, call `store.apply_asset_profile_for_entity(...)`.

Use target domains from `target.match_rules.domains`.

- [ ] **Step 4: Wire pivot worker**

In `src/easm/pivot/worker.py`, after successful `store.upsert_entity(...)`, call `store.apply_asset_profile_for_entity(...)`.

Use target domains from target config if available; if no config, pass an empty list.

- [ ] **Step 5: Verify focused tests**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets/test_materialization_asset_profile.py tests/test_simulation_runner_flow.py tests/test_simulation_pivot_worker_integration.py"
```

Expected:

```text
passed
```

---

## Task 8: Documentation And Agent Guidance

**Files:**
- Modify: `AGENTS.md`
- Create: `docs/easm-platform-maturity.md`

- [ ] **Step 1: Update AGENTS.md**

Add:

```markdown
## Asset Profile And Source-Of-Truth Boundary

- open-easm is the discovery/evidence producer, not the authoritative CMDB.
- Do not add source-of-truth imports in this repo unless a future plan explicitly changes scope.
- Asset metadata intended for downstream systems lives under `attributes.asset_profile`.
- Keep confidence, evidence, risk, and source-of-truth feed state in the asset profile.
- Outbound feed code lives in `src/easm/assets/export.py`.
- Tests for asset inventory/export must use fixture data and must not contact public targets.
```

- [ ] **Step 2: Create docs**

Create `docs/easm-platform-maturity.md` with:

- asset profile shape
- confidence scoring rules
- risk scoring rules
- change event ledger semantics
- outbound source-of-truth feed format
- explicit statement that source-of-truth imports are out of scope
- safe testing guidance

- [ ] **Step 3: Verify docs**

Run:

```powershell
rg -n "source-of-truth|asset_profile|export.ndjson|asset_change_events" AGENTS.md docs/easm-platform-maturity.md
```

Expected: hits in both files.

---

## Final Verification

- [ ] Run focused asset suite:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_assets tests/test_api/test_assets.py"
```

- [ ] Run adjacent existing suites:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_simulation_runner_flow.py tests/test_simulation_pivot_worker_integration.py tests/test_api/test_certificates.py"
```

- [ ] Run canonical backend gate:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

- [ ] Clean Docker resources:

```powershell
docker compose -f docker-compose.test.yml down
```

---

## Subagent Ownership Map

1. **Worker A: Asset Profile Helpers**
   - Owns `src/easm/assets/__init__.py`
   - Owns `src/easm/assets/profile.py`
   - Owns `tests/test_assets/test_profile.py`

2. **Worker B: Risk Scoring**
   - Owns `src/easm/assets/scoring.py`
   - Owns `tests/test_assets/test_scoring.py`

3. **Worker C: Change Ledger**
   - Owns `alembic/versions/20260518_0002_asset_change_events.py`
   - Owns `src/easm/assets/change.py`
   - Owns change methods in `src/easm/store.py`
   - Owns `tests/test_assets/test_change_events.py`

4. **Worker D: Store/API Inventory**
   - Owns asset inventory methods in `src/easm/store.py`
   - Owns `src/easm/api/routes/assets.py`
   - Owns `src/easm/api/app.py`
   - Owns `tests/test_api/test_assets.py`

5. **Worker E: Outbound Feed**
   - Owns `src/easm/assets/export.py`
   - Owns export route in `src/easm/api/routes/assets.py`
   - Owns `tests/test_assets/test_export.py`

6. **Worker F: Materialization Integration**
   - Owns `src/easm/runners/engine.py`
   - Owns `src/easm/pivot/worker.py`
   - Owns `tests/test_assets/test_materialization_asset_profile.py`

7. **Worker G: Docs**
   - Owns `AGENTS.md`
   - Owns `docs/easm-platform-maturity.md`

---

## Follow-On Plans Not Covered Here

These should be separate plans:

- Web application inventory: HTTP headers, security headers, screenshots, favicon hash, login/admin/API-doc discovery.
- Validation engine: safe proof checks, screenshot/browser capture, replayable evidence bundles.
- Remediation workflow: assignment, SLA, accepted risk, resurfacing, ticket/webhook integrations.
- Attack path reasoning: graph path ranking across DNS, certs, cloud buckets, ports, vulnerabilities, and takeover signals.

---

## Self-Review

- Source-of-truth imports are explicitly excluded.
- The feed is outbound-only and labels open-easm as the discovery/evidence producer.
- The plan uses existing entities, attributes, findings, raw events, and API style.
- The only database addition is an append-only change ledger.
- All tests are Docker-local and fixture-backed.
- The plan leaves active web app validation for a separate, safer plan.
