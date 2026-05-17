# EASM UI — Implementation Spec

**Date:** 2026-05-16  
**Status:** Draft  
**Design System:** `DESIGN.md` (VoltAgent-inspired, dark canvas, electric-teal accent)

## Summary

A single-page dashboard UI for the open-easm platform. Shows task status (runs), inventory (entities), graph visualization (entity relationships), and search/filter. Single-user, no RBAC. Served as a monolith from FastAPI.

## Architecture Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Frontend framework | React 18 + TypeScript | Industry standard, best D3 integration, huge ecosystem |
| Build tool | Vite 6 | Fast HMR, native ESM, excellent Tailwind integration |
| CSS | Tailwind CSS v4 | Matches DESIGN.md token system perfectly |
| Graph visualization | D3-force (d3-force v3) | Custom force-directed graph with entity-type coloring |
| State management | TanStack Query v5 | Server state for API data; local state for UI |
| Routing | React Router v7 | Standard SPA routing with sidebar nav |
| HTTP client | ky or fetch wrapper | Simple, lightweight |
| Monolith serving | FastAPI serves built SPA from `/ui` | Single container, no CORS issues |
| Package location | `ui/` directory at repo root | Clean separation from Python backend |

## Data Model (from existing API)

The UI consumes these existing FastAPI endpoints:

### Targets
- `GET /targets` — list all targets
- `GET /targets/{id}` — target detail with runner configs

### Runs
- `GET /runs` — list runs (filterable by target_id, source, status, trigger_type, date range)
- `GET /runs/{id}` — run detail with metadata
- `POST /runs/{target_id}/{runner}` — trigger a manual run

### Entities
- `GET /entities` — list entities (filterable by target_id, entity_type, first_seen_since, last_seen_before, cursor pagination)
- `GET /entities/{id}` — entity detail with raw_event_ids
- `GET /entities/{id}/relationships` — entity relationships

### Graph
- `GET /graph/{target_id}?depth=3` — recursive graph traversal (nodes + edges)

### Events
- `GET /events` — raw events (filterable by target_id, source, date range, cursor pagination)

### Pivot Queue (needs new endpoint)
- `GET /pivot-queue` — list pending/running/completed pivot jobs (currently no API route exists)

## Views & Components

### 1. App Shell
- **Sidebar**: Collapsible (64px/240px), 5 nav items with icons
  - Dashboard (grid icon)
  - Inventory (list icon)
  - Graph Explorer (share-2 / network icon)
  - Runs (play icon)
  - Targets & Pivots (target icon)
- **Top bar**: Breadcrumbs + global search input (`search-input` component)
- **Main area**: Renders active view component

### 2. Dashboard View
- **Metric cards row** (4-up): Entity count by type (Domains, IPs, Hostnames, Certificates) with each using its entity-type color
- **Active runs card**: Shows currently running/pending runs with status badges
- **Recent discoveries feed**: Last 10 discovered entities with entity-type badge, value, timestamp
- **Quick-trigger section**: Per-target runner trigger buttons (`button-primary` style)

### 3. Inventory View
- **Type filter tabs**: All | ASN | IP Range | IP | Hostname | Domain | Certificate | Org — each tab shows count
- **Search bar**: Filters by entity_value (domain, IP, hostname)
- **Entity table**: Columns — Type (badge), Value (monospace), Target, First Seen, Last Seen, Attributes (collapsible JSON)
- **Row click**: Opens slide-over panel with entity detail
- **Pagination**: Cursor-based, "Load more" button at bottom
- **Column sorting**: Click column headers for ascending/descending

### 4. Graph Explorer View
- **Target selector**: Dropdown to select which target's graph to visualize
- **Depth control**: Slider/input for graph depth (1-10)
- **D3-force canvas**: Force-directed graph
  - Nodes: Colored by entity type (fill = entity-type color at 20% opacity, stroke = entity-type color at 100%)
  - Edges: `{colors.hairline-soft}` lines with relationship-type labels on hover
  - Click node: Highlight connected edges, show tooltip with entity value + type
  - Double-click node: Open slide-over detail panel
  - Drag nodes: Reposition in force simulation
- **Legend**: Entity-type color key in top-right corner
- **Zoom controls**: Zoom in/out/reset buttons

### 5. Runs View
- **Filter bar**: Target dropdown, runner dropdown, status filter, date range
- **Runs table**: Columns — Target, Runner, Trigger, Status (badge), Started, Duration, Inserted, Deduped, Errors
- **Row click**: Expand row to show run metadata JSON
- **Trigger button**: Per-target runner trigger (uses `POST /runs/{target_id}/{runner}`)
- **Auto-refresh**: Poll every 5s when any run has status "running" or "pending"

### 6. Targets & Pivots View
- **Target cards**: One card per configured target showing name, type, enabled status, runner configs
- **Pivot queue table**: Jobs listed with entity_type → pivot_type, status (badge), depth, timestamps
- **Cascade visualization**: For a selected target, show the discovery pipeline:
  ```
  ASN → [30] IP Ranges → [77] Hostnames → [77] IPs → [76] Domains → [?] Certificates
  ```
  Each step is a `cascade-step` component with entity-type color, count badge, and connecting arrows.

## New API Endpoints Needed

### Pivot Queue
```python
# GET /pivot-queue?status=pending&target_id=xxx&limit=50
# Returns: { "jobs": [...], "next_cursor": "..." }
```
The `pivot_store.py` already has `dequeue_pivot_job` but no list/search endpoint. We need:
- `GET /pivot-queue` — list pivot jobs with filters (status, target_id, entity_type, cursor pagination)

### Run Trigger Enhancement
The existing trigger endpoint returns immediately. Consider adding:
- WebSocket or SSE endpoint for real-time run status updates (optional for v1)

## File Structure

```
ui/
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts
├── postcss.config.js
├── public/
│   └── favicon.svg
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── DESIGN_TOKENS.ts          # Token references from DESIGN.md
    ├── api/
    │   ├── client.ts             # HTTP client wrapper
    │   ├── targets.ts            # Target API hooks (TanStack Query)
    │   ├── entities.ts           # Entity API hooks
    │   ├── runs.ts               # Runs API hooks
    │   ├── graph.ts              # Graph API hooks
    │   └── pivot-queue.ts        # Pivot queue API hooks
    ├── components/
    │   ├── layout/
    │   │   ├── Sidebar.tsx
    │   │   ├── TopBar.tsx
    │   │   └── AppShell.tsx
    │   ├── shared/
    │   │   ├── Badge.tsx          # Status + entity-type badges
    │   │   ├── Button.tsx          # Primary, outline, ghost, danger
    │   │   ├── Card.tsx            # Feature, metric cards
    │   │   ├── SlideOver.tsx       # Entity detail slide-over
    │   │   ├── SearchInput.tsx
    │   │   ├── Table.tsx           # Reusable data table
    │   │   ├── TypeFilter.tsx      # Entity type tab filter
    │   │   └── CascadeStep.tsx     # Discovery cascade step
    │   ├── dashboard/
    │   │   ├── DashboardView.tsx
    │   │   ├── MetricCards.tsx
    │   │   ├── ActiveRuns.tsx
    │   │   ├── RecentDiscoveries.tsx
    │   │   └── QuickTrigger.tsx
    │   ├── inventory/
    │   │   ├── InventoryView.tsx
    │   │   ├── EntityTable.tsx
    │   │   └── EntityDetail.tsx    # Slide-over content
    │   ├── graph/
    │   │   ├── GraphView.tsx
    │   │   ├── ForceGraph.tsx      # D3-force integration
    │   │   ├── GraphNode.tsx
    │   │   ├── GraphEdge.tsx
    │   │   ├── GraphLegend.tsx
    │   │   └── GraphControls.tsx
    │   ├── runs/
    │   │   ├── RunsView.tsx
    │   │   ├── RunsTable.tsx
    │   │   └── RunDetail.tsx
    │   └── targets/
    │       ├── TargetsView.tsx
    │       ├── TargetCards.tsx
    │       ├── PivotQueueTable.tsx
    │       └── CascadeVisualization.tsx
    ├── hooks/
    │   ├── useAutoRefresh.ts      # Polling hook for runs/pivot status
    │   └── useDebounce.ts
    └── lib/
        ├── d3-force.ts            # D3 force simulation setup
        ├── entity-colors.ts       # Entity type → color mapping
        └── format.ts              # Date/time, duration formatters
```

## FastAPI Integration

Add to `src/easm/api/app.py`:
```python
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

# After all API routes are registered:
static_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ui", "dist")
if os.path.isdir(static_dir):
    app.mount("/ui", StaticFiles(directory=static_dir, html=True), name="ui")
```

This serves the built SPA from `/ui/` when the `ui/dist` directory exists. During development, Vite dev server runs on a separate port with CORS already enabled.

## Implementation Phases

### Phase 1: Shell + Inventory (MVP)
- App shell with sidebar navigation
- Inventory view with entity table, type tabs, search, pagination
- Entity detail slide-over
- Basic DESIGN.md token integration via Tailwind config
- FastAPI static file serving

### Phase 2: Dashboard + Runs
- Dashboard with metric cards
- Runs view with filter bar and table
- Auto-refresh for running/pending runs
- Run trigger buttons

### Phase 3: Graph Explorer
- D3-force graph visualization
- Target selector, depth control
- Node click/hover interactions
- Slide-over for node details
- Graph legend

### Phase 4: Targets & Pivots
- Target configuration cards
- Pivot queue table
- Cascade visualization
- New `/pivot-queue` API endpoint

## Success Criteria

1. **Show the work**: From a single ASN seed, the UI displays the full discovery cascade end-to-end
2. **Task status visibility**: Running, pending, completed, failed states are always visible
3. **Entity inventory browsable**: All entity types filterable, searchable, paginated
4. **Graph exploration works**: Click a target, see entity graph, drill into relationships
5. **Discoverable**: Fresh visitor can understand what the tool does within 30 seconds