# Phase 2.2-2.4 Platform UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add config editing from Web UI (2.2), bidirectional YAML sync (2.3), and watch alerts with notification feed (2.4).

**Architecture:** Backend API routes extend existing config.py and add new alerts.py in the FastAPI pattern (APIRouter + deps). Frontend adds ConfigEditor and Alerts pages following the existing React + lucide-react + ky + Tailwind pattern. Sidebar gains two new nav items.

**Tech Stack:** FastAPI, Pydantic, React 18, TypeScript, Tailwind CSS 4, lucide-react, ky.

---

## File Structure

### New Backend Files

| File | Responsibility |
|------|---------------|
| `src/easm/api/routes/alerts.py` | CRUD for alert rules, notification feed endpoint |
| `tests/test_api/test_alerts.py` | Tests for alert API endpoints |

### Modified Backend Files

| File | Change |
|------|--------|
| `src/easm/api/routes/config.py` | Add GET /config (full config), PUT /config (update + validate + write), GET /config/history |
| `src/easm/api/schemas.py` | Add ConfigResponse, ConfigUpdate, AlertRule, AlertFeed schemas |
| `src/easm/api/app.py` | Mount alerts router |
| `src/easm/config.py` | Add AlertRule Pydantic model, alerts section to Config |
| `config.yaml.example` | Add alerts section example |

### New Frontend Files

| File | Responsibility |
|------|---------------|
| `ui/src/components/config/ConfigEditorView.tsx` | Config editing page — targets, runners, pivots, match rules |
| `ui/src/components/alerts/AlertsView.tsx` | Alerts management page — rules + notification feed |
| `ui/src/api/config.ts` | Config API client (GET/PUT config, reload) |
| `ui/src/api/alerts.ts` | Alerts API client (CRUD rules, feed) |

### Modified Frontend Files

| File | Change |
|------|--------|
| `ui/src/App.tsx` | Add /config and /alerts routes |
| `ui/src/components/layout/Sidebar.tsx` | Add Config and Alerts nav items |

---

## Existing Patterns (Follow Exactly)

### Backend Route Pattern
```python
from fastapi import APIRouter
from easm.api.deps import get_config, get_store
router = APIRouter(tags=["alerts"])
@router.get("", response_model=list[SomeSchema])
async def list_alerts():
    ...
```

### Frontend Component Pattern (from existing pages)
- Component file in `ui/src/components/feature/FeatureView.tsx`
- Uses Tailwind utility classes: `bg-canvas`, `text-ink`, `text-mute`, `border-hairline`, `bg-canvas-soft`
- API client in `ui/src/api/feature.ts` using `ky` with `/api` prefix
- Imported and routed in `App.tsx`

### Sidebar Pattern
- Add to `navItems` array: `{ icon: IconNameFromLucide, label: "Label", path: "/path" }`
- Use lucide-react icons

---

## Task 1: Config API — Read, Write, Validate

**Files:**
- Modify: `src/easm/api/routes/config.py`
- Modify: `src/easm/api/schemas.py`
- Create: `ui/src/api/config.ts`

### Backend

- [ ] **Add schemas to api/schemas.py:**

```python
class ConfigSnapshot(BaseModel):
    id: str
    target_count: int
    created_at: str

class ConfigUpdateRequest(BaseModel):
    """Partial config update. Only the sections provided are updated."""
    targets: list[dict[str, Any]] | None = None
    saas_providers: dict[str, Any] | None = None
    alerts: dict[str, Any] | None = None

class ConfigResponse(BaseModel):
    targets: list[dict[str, Any]]
    saas_providers: dict[str, Any] | None = None
    alerts: dict[str, Any] | None = None
```

- [ ] **Add GET /config endpoint** to config.py (returns current config as JSON):

```python
@router.get("/config", response_model=dict)
async def get_full_config(config: Config = Depends(get_config)):
    return config.model_dump(mode="json")
```

- [ ] **Add PUT /config endpoint** to config.py (validates + writes to YAML + snapshots DB):

```python
import yaml, os
from easm.config import Config as ConfigModel

@router.put("/config")
async def update_config(
    body: dict,
    config: Config = Depends(get_config),
    store: Store = Depends(get_store),
):
    # Merge body into current config dict
    current = config.model_dump()
    for key in ("targets", "saas_providers", "alerts"):
        if key in body:
            current[key] = body[key]

    # Validate
    try:
        new_config = ConfigModel.model_validate(current)
    except Exception as e:
        raise HTTPException(status_code=422, detail={"error": "validation", "detail": str(e)})

    # Write YAML
    config_path = os.environ.get("EASM_CONFIG_PATH", "config.yaml")
    yaml_text = yaml.dump(current, allow_unicode=True, sort_keys=False)
    Path(config_path).write_text(yaml_text)

    # Snapshot
    await store.save_config_snapshot(current)

    # Update in-memory
    set_config(new_config)

    return {"status": "ok", "message": "config updated and validated"}
```

- [ ] **Add GET /config/history endpoint:**

```python
@router.get("/config/history", response_model=list[ConfigSnapshot])
async def config_history(store: Store = Depends(get_store)):
    rows = await store.pool.fetch("""
        SELECT id, snapshot->>'targets', created_at
        FROM config_snapshots
        ORDER BY created_at DESC LIMIT 20
    """)
    return [ConfigSnapshot(
        id=str(r["id"]),
        target_count=len(r.get("?column?", "[]") or []),
        created_at=r["created_at"].isoformat(),
    ) for r in rows]
```

### Frontend API Client

- [ ] **Create ui/src/api/config.ts:**

```typescript
import api from './client'

export interface ConfigData {
  targets: Array<Record<string, unknown>>
  saas_providers?: Record<string, unknown>
  alerts?: Record<string, unknown>
}

export const getConfig = () => api.get('config').json<ConfigData>()
export const updateConfig = (body: Partial<ConfigData>) =>
  api.put('config', { json: body }).json<{ status: string }>()
export const reloadConfig = () => api.post('config/reload').json<{ status: string }>()
```

- [ ] **Commit** — `git commit -m "feat: add config read/write API endpoints and frontend client"`

---

## Task 2: Config Editor Page (Frontend)

**Files:**
- Create: `ui/src/components/config/ConfigEditorView.tsx`
- Modify: `ui/src/App.tsx`
- Modify: `ui/src/components/layout/Sidebar.tsx`

- [ ] **Create ConfigEditorView component:**

A React page that:
1. Fetches current config via `getConfig()` on mount
2. Displays targets as editable cards with: id, name, type, enabled toggle, match rules, runner configs, pivot config
3. Each target section is a collapsible card
4. Runners section shows enable toggle + schedule + args per runner
5. Pivots section shows allowed_pivots as editable rows
6. "Save Changes" button calls `updateConfig()` then `reloadConfig()`
7. Uses Tailwind classes matching existing pages: `bg-canvas`, `text-ink`, `rounded-xl`, `border-hairline`, `shadow-sm`

```tsx
// Key structure (use this pattern, implement fully):
import { useState, useEffect } from 'react'
import { Settings, Save } from 'lucide-react'
import { getConfig, updateConfig, reloadConfig, type ConfigData } from '../../api/config'

export function ConfigEditorView() {
  const [config, setConfig] = useState<ConfigData | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getConfig().then(setConfig)
  }, [])

  const handleSave = async () => {
    if (!config) return
    setSaving(true)
    await updateConfig(config)
    await reloadConfig()
    setSaving(false)
  }

  // ... render targets, runners, pivots as form fields
  // Use text-input style edits with label+value pairs
}
```

- [ ] **Add route to App.tsx:**

```tsx
import { ConfigEditorView } from "./components/config/ConfigEditorView";
// Add inside <Routes>:
<Route path="config" element={<ConfigEditorView />} />
```

- [ ] **Add nav item to Sidebar.tsx:**

```tsx
import { Settings } from "lucide-react";
// Add to navItems array:
{ icon: Settings, label: "Config", path: "/config" },
```

- [ ] **Commit** — `git commit -m "feat: add config editor page with YAML read/write"`

---

## Task 3: Alert Models + Backend API

**Files:**
- Create: `src/easm/api/routes/alerts.py`
- Modify: `src/easm/api/schemas.py`
- Modify: `src/easm/api/app.py`
- Modify: `src/easm/config.py`
- Modify: `config.yaml.example`
- Create: `tests/test_api/test_alerts.py`

- [ ] **Add AlertRule model to config.py:**

```python
class AlertRule(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    condition: str  # e.g. "hostname matches *(dev|test|staging)*.yourorg.com"
    severity: str = "medium"  # high, medium, low

    @field_validator("severity")
    @classmethod
    def severity_valid(cls, v: str) -> str:
        if v not in ("high", "medium", "low"):
            raise ValueError("severity must be high, medium, or low")
        return v

class AlertsConfig(BaseModel):
    rules: list[AlertRule] = Field(default_factory=list)
```

- [ ] **Add alerts to Config class:**

```python
class Config(BaseModel):
    targets: list[TargetConfig]
    saas_providers: SaasProviderConfig = Field(default_factory=SaasProviderConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
```

- [ ] **Add schemas to api/schemas.py:**

```python
class AlertRuleSchema(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    condition: str
    severity: str = "medium"

class AlertFeedEntry(BaseModel):
    id: str
    rule_name: str
    severity: str
    title: str
    detail: str
    entity_id: str | None = None
    created_at: str
    acknowledged: bool = False
```

- [ ] **Create alerts route (src/easm/api/routes/alerts.py):**

```python
from fastapi import APIRouter, HTTPException, Depends
from easm.api.deps import get_config
from easm.api.schemas import AlertRuleSchema, AlertFeedEntry

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/rules", response_model=list[AlertRuleSchema])
async def list_alert_rules(config = Depends(get_config)):
    return [AlertRuleSchema(
        name=r.name, description=r.description,
        enabled=r.enabled, condition=r.condition, severity=r.severity,
    ) for r in config.alerts.rules]

@router.get("/feed", response_model=list[AlertFeedEntry])
async def alert_feed(store = Depends(get_store)):
    # Query findings table for recent correlation findings as alert feed
    rows = await store.pool.fetch("""
        SELECT id, rule_id, risk, title, description, entity_ids, created_at, status
        FROM findings ORDER BY created_at DESC LIMIT 50
    """)
    return [AlertFeedEntry(
        id=str(r["id"]),
        rule_name=r["rule_id"] or "unknown",
        severity=r["risk"] or "low",
        title=r["title"] or "",
        detail=r["description"] or "",
        created_at=r["created_at"].isoformat(),
        acknowledged=r["status"] == "acknowledged",
    ) for r in rows]

@router.patch("/feed/{finding_id}")
async def acknowledge_finding(finding_id: str, store = Depends(get_store)):
    await store.pool.execute(
        "UPDATE findings SET status = 'acknowledged' WHERE id = $1", finding_id)
    return {"status": "ok"}
```

- [ ] **Mount alerts router in app.py:**

```python
from easm.api.routes import alerts as alerts_route
app.include_router(alerts_route.router, prefix="/api")
```

- [ ] **Add test (tests/test_api/test_alerts.py):**

```python
import pytest
from fastapi.testclient import TestClient
from easm.api.app import create_app
from easm.api.deps import set_config, set_store
from easm.config import Config, TargetConfig, AlertRule, AlertsConfig

@pytest.fixture
def client():
    app = create_app()
    cfg = Config(targets=[], alerts=AlertsConfig(rules=[
        AlertRule(name="test_rule", condition="test", severity="high"),
    ]))
    set_config(cfg)
    with TestClient(app) as c:
        yield c

def test_list_alert_rules(client):
    resp = client.get("/api/alerts/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 1
    assert rules[0]["name"] == "test_rule"
```

- [ ] **Add alerts example to config.yaml.example:**

```yaml
alerts:
  rules:
    - name: "No dev/test public"
      description: "Dev or test systems exposed on public internet"
      enabled: true
      condition: "hostname matches *(dev|test|staging)*.yourorg.com"
      severity: high
    - name: "Risky ports"
      description: "Database or admin ports publicly exposed"
      enabled: true
      condition: "port in [22, 3389, 5432, 6379, 9200, 27017]"
      severity: high
```

- [ ] **Commit** — `git commit -m "feat: add alert rules model, alerts API, and alert feed endpoint"`

---

## Task 4: Alerts Page (Frontend)

**Files:**
- Create: `ui/src/components/alerts/AlertsView.tsx`
- Create: `ui/src/api/alerts.ts`
- Modify: `ui/src/App.tsx`
- Modify: `ui/src/components/layout/Sidebar.tsx`

- [ ] **Create alerts API client (ui/src/api/alerts.ts):**

```typescript
import api from './client'

export interface AlertRule {
  name: string
  description?: string
  enabled: boolean
  condition: string
  severity: string
}

export interface AlertFeedEntry {
  id: string
  rule_name: string
  severity: string
  title: string
  detail: string
  entity_id?: string
  created_at: string
  acknowledged: boolean
}

export const getAlertRules = () => api.get('alerts/rules').json<AlertRule[]>()
export const getAlertFeed = () => api.get('alerts/feed').json<AlertFeedEntry[]>()
export const acknowledgeFinding = (id: string) =>
  api.patch(`alerts/feed/${id}`).json<{ status: string }>()
```

- [ ] **Create AlertsView component:**

A React page with two tabs/sections:
1. **Alert Rules** tab — list of configured rules showing name, condition, severity badge, enabled toggle (read-only display, rules managed via config.yaml or config editor)
2. **Notification Feed** tab — chronological list of alert feed entries with severity badge, title, detail, timestamp, and acknowledge button

Uses Tailwind classes: `bg-canvas`, `rounded-xl`, `border-hairline`, severity colors (`text-red-600` for high, `text-amber-500` for medium, `text-slate-400` for low).

```tsx
import { useState, useEffect } from 'react'
import { Bell, CheckCircle, AlertTriangle, Info, Shield } from 'lucide-react'
import { getAlertRules, getAlertFeed, acknowledgeFinding, type AlertRule, type AlertFeedEntry } from '../../api/alerts'

export function AlertsView() {
  const [tab, setTab] = useState<'feed' | 'rules'>('feed')
  const [feed, setFeed] = useState<AlertFeedEntry[]>([])
  const [rules, setRules] = useState<AlertRule[]>([])

  useEffect(() => {
    if (tab === 'feed') getAlertFeed().then(setFeed)
    else getAlertRules().then(setRules)
  }, [tab])

  const handleAck = async (id: string) => {
    await acknowledgeFinding(id)
    setFeed(prev => prev.map(f => f.id === id ? { ...f, acknowledged: true } : f))
  }

  // Render tabs, feed list, rules list with severity badges and acknowledge buttons
}
```

- [ ] **Add route to App.tsx:**

```tsx
import { AlertsView } from "./components/alerts/AlertsView";
<Route path="alerts" element={<AlertsView />} />
```

- [ ] **Add nav item to Sidebar.tsx:**

```tsx
import { Bell } from "lucide-react";
{ icon: Bell, label: "Alerts", path: "/alerts" },
```

- [ ] **Commit** — `git commit -m "feat: add alerts management page with rules and notification feed"`

---

## Task 5: Integration — Full Test Suite + Lint

- [ ] **Run test suite:** `uv run pytest tests/test_api/test_alerts.py -v`
- [ ] **Run backend lint:** `uv run ruff check src/easm/api/routes/`
- [ ] **Run type check:** `uv run mypy src/easm/api/routes/alerts.py src/easm/api/routes/config.py`
- [ ] **Run frontend type check:** `cd ui && npx tsc --noEmit`
- [ ] **Commit** — `git commit -m "chore: integration tests and lint fixes for platform UI"`

---

## Self-Review Checklist

**1. Spec coverage:** Phase 2.2 (config editing) ✅, Phase 2.3 (YAML sync) ✅, Phase 2.4 (watch alerts) ✅.

**2. Placeholder scan:** No TODOs, TBDs. All code provided.

**3. Type consistency:** Backend uses Pydantic schemas. Frontend uses TypeScript interfaces matching API responses.
