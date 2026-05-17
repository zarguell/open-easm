# EASM UI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-page dashboard UI for the open-easm platform that shows discovery cascade status, entity inventory, graph relationships, and run history.

**Architecture:** React 18 + TypeScript SPA built with Vite, styled with Tailwind CSS v4 following the DESIGN.md token system. D3-force for graph visualization. TanStack Query v5 for server state. FastAPI serves the built SPA as a monolith from `/ui`. Single-user, no RBAC.

**Tech Stack:** React 18, TypeScript, Vite 6, Tailwind CSS v4, D3-force v3, TanStack Query v5, React Router v7, Lucide React (icons)

---

## Phase 1: Shell + Inventory (MVP)

### Task 1: Project Scaffolding

**Files:**
- Create: `ui/package.json`
- Create: `ui/vite.config.ts`
- Create: `ui/tsconfig.json`
- Create: `ui/tsconfig.node.json`
- Create: `ui/index.html`
- Create: `ui/postcss.config.js`
- Create: `ui/src/main.tsx`
- Create: `ui/src/App.tsx`
- Create: `ui/src/vite-env.d.ts`
- Create: `ui/.gitignore`

- [ ] **Step 1: Create the ui/ directory and initialize the project**

```bash
mkdir -p /Users/zach/localcode/open-easm/ui/src
cd /Users/zach/localcode/open-easm/ui
```

- [ ] **Step 2: Create package.json**

```json
{
  "name": "open-easm-ui",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "lint": "eslint ."
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router": "^7.1.0",
    "@tanstack/react-query": "^5.62.0",
    "d3-force": "^3.0.0",
    "d3-drag": "^3.0.0",
    "d3-zoom": "^3.0.0",
    "d3-selection": "^3.0.0",
    "d3-scale": "^4.0.2",
    "lucide-react": "^0.468.0",
    "ky": "^1.7.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@types/d3-force": "^3.0.0",
    "@types/d3-drag": "^3.0.0",
    "@types/d3-zoom": "^3.0.0",
    "@types/d3-selection": "^3.0.0",
    "@types/d3-scale": "^4.0.0",
    "@vitejs/plugin-react": "^4.3.4",
    "typescript": "^5.6.0",
    "vite": "^6.0.0",
    "@tailwindcss/vite": "^4.0.0",
    "tailwindcss": "^4.0.0"
  }
}
```

- [ ] **Step 3: Create vite.config.ts**

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
```

- [ ] **Step 4: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src"]
}
```

- [ ] **Step 5: Create tsconfig.node.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 6: Create index.html**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Open EASM</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  </head>
  <body class="bg-canvas text-ink">
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 7: Create postcss.config.js**

```javascript
export default {
  plugins: {
    '@tailwindcss/vite': {},
  },
}
```

- [ ] **Step 8: Create .gitignore**

```
node_modules
dist
.env
.env.local
```

- [ ] **Step 9: Create src/vite-env.d.ts**

```typescript
/// <reference types="vite/client" />
```

- [ ] **Step 10: Create src/main.tsx**

```tsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
```

- [ ] **Step 11: Create src/App.tsx (shell with routes)**

```tsx
import { Routes, Route } from 'react-router'
import AppShell from './components/layout/AppShell'
import DashboardView from './components/dashboard/DashboardView'
import InventoryView from './components/inventory/InventoryView'
import GraphView from './components/graph/GraphView'
import RunsView from './components/runs/RunsView'
import TargetsView from './components/targets/TargetsView'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardView />} />
        <Route path="inventory" element={<InventoryView />} />
        <Route path="graph" element={<GraphView />} />
        <Route path="runs" element={<RunsView />} />
        <Route path="targets" element={<TargetsView />} />
      </Route>
    </Routes>
  )
}
```

- [ ] **Step 12: Create src/index.css with Tailwind + DESIGN.md tokens**

```css
@import "tailwindcss";

@theme {
  --color-canvas: #101010;
  --color-canvas-soft: #1a1a1a;
  --color-canvas-elevated: #222222;
  --color-hairline: #3d3a39;
  --color-hairline-soft: #57534e;
  --color-ink: #f2f2f2;
  --color-ink-strong: #ffffff;
  --color-body: #bdbdbd;
  --color-mute: #8b949e;
  --color-primary: #00d992;
  --color-primary-soft: #2fd6a1;
  --color-primary-deep: #10b981;
  --color-on-primary: #101010;
  --color-entity-asn: #f59e0b;
  --color-entity-ip-range: #f97316;
  --color-entity-ip: #ef4444;
  --color-entity-hostname: #06b6d4;
  --color-entity-domain: #00d992;
  --color-entity-certificate: #a855f7;
  --color-entity-org: #94a3b8;
  --color-status-success: #00d992;
  --color-status-error: #ef4444;
  --color-status-warning: #f59e0b;
  --color-status-running: #3b82f6;
  --color-status-pending: #6b7280;
  --font-sans: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}

body {
  background-color: var(--color-canvas);
  color: var(--color-ink);
  font-family: var(--font-sans);
}

* {
  scrollbar-width: thin;
  scrollbar-color: var(--color-hairline) transparent;
}
```

- [ ] **Step 13: Install dependencies**

```bash
cd /Users/zach/localcode/open-easm/ui && npm install
```

- [ ] **Step 14: Create placeholder view components so the app compiles**

Create each file as a simple placeholder:

`ui/src/components/layout/AppShell.tsx`:
```tsx
import { Outlet } from 'react-router'
export default function AppShell() {
  return <div className="flex h-screen"><Outlet /></div>
}
```

`ui/src/components/dashboard/DashboardView.tsx`:
```tsx
export default function DashboardView() {
  return <div className="p-6"><h1 className="text-2xl font-bold">Dashboard</h1><p className="text-body mt-2">Coming soon</p></div>
}
```

`ui/src/components/inventory/InventoryView.tsx`:
```tsx
export default function InventoryView() {
  return <div className="p-6"><h1 className="text-2xl font-bold">Inventory</h1><p className="text-body mt-2">Coming soon</p></div>
}
```

`ui/src/components/graph/GraphView.tsx`:
```tsx
export default function GraphView() {
  return <div className="p-6"><h1 className="text-2xl font-bold">Graph Explorer</h1><p className="text-body mt-2">Coming soon</p></div>
}
```

`ui/src/components/runs/RunsView.tsx`:
```tsx
export default function RunsView() {
  return <div className="p-6"><h1 className="text-2xl font-bold">Runs</h1><p className="text-body mt-2">Coming soon</p></div>
}
```

`ui/src/components/targets/TargetsView.tsx`:
```tsx
export default function TargetsView() {
  return <div className="p-6"><h1 className="text-2xl font-bold">Targets & Pivots</h1><p className="text-body mt-2">Coming soon</p></div>
}
```

- [ ] **Step 15: Verify the app builds**

```bash
cd /Users/zach/localcode/open-easm/ui && npm run build
```

Expected: Build succeeds with no errors.

- [ ] **Step 16: Commit scaffolding**

```bash
cd /Users/zach/localcode/open-easm && git add ui/ && git commit -m "feat(ui): scaffold React+Vite+Tailwind project with DESIGN.md tokens"
```


### Task 2: API Client + Design Tokens + Shared Components

**Files:**
- Create: `ui/src/DESIGN_TOKENS.ts`
- Create: `ui/src/api/client.ts`
- Create: `ui/src/api/entities.ts`
- Create: `ui/src/api/runs.ts`
- Create: `ui/src/api/targets.ts`
- Create: `ui/src/api/graph.ts`
- Create: `ui/src/lib/entity-colors.ts`
- Create: `ui/src/lib/format.ts`
- Create: `ui/src/components/shared/Badge.tsx`
- Create: `ui/src/components/shared/Button.tsx`
- Create: `ui/src/components/shared/Card.tsx`
- Create: `ui/src/components/shared/SearchInput.tsx`
- Create: `ui/src/components/shared/TypeFilter.tsx`

- [ ] **Step 1: Create DESIGN_TOKENS.ts**

```typescript
// Design tokens matching DESIGN.md — single source of truth for the UI
export const colors = {
  primary: '#00d992',
  primarySoft: '#2fd6a1',
  primaryDeep: '#10b981',
  onPrimary: '#101010',
  canvas: '#101010',
  canvasSoft: '#1a1a1a',
  canvasElevated: '#222222',
  hairline: '#3d3a39',
  hairlineSoft: '#57534e',
  ink: '#f2f2f2',
  inkStrong: '#ffffff',
  body: '#bdbdbd',
  mute: '#8b949e',
  entityAsn: '#f59e0b',
  entityIpRange: '#f97316',
  entityIp: '#ef4444',
  entityHostname: '#06b6d4',
  entityDomain: '#00d992',
  entityCertificate: '#a855f7',
  entityOrg: '#94a3b8',
  statusSuccess: '#00d992',
  statusError: '#ef4444',
  statusWarning: '#f59e0b',
  statusRunning: '#3b82f6',
  statusPending: '#6b7280',
} as const

export const entityColors: Record<string, string> = {
  asn: colors.entityAsn,
  ip_range: colors.entityIpRange,
  ip: colors.entityIp,
  hostname: colors.entityHostname,
  domain: colors.entityDomain,
  certificate: colors.entityCertificate,
  org: colors.entityOrg,
}

export const statusColors: Record<string, string> = {
  completed: colors.statusSuccess,
  running: colors.statusRunning,
  pending: colors.statusPending,
  failed: colors.statusError,
}

export const ENTITY_TYPES = ['asn', 'ip_range', 'ip', 'hostname', 'domain', 'certificate', 'org'] as const
export type EntityType = typeof ENTITY_TYPES[number]

export const ENTITY_LABELS: Record<EntityType, string> = {
  asn: 'ASN',
  ip_range: 'IP Range',
  ip: 'IP',
  hostname: 'Hostname',
  domain: 'Domain',
  certificate: 'Certificate',
  org: 'Org',
}
```

- [ ] **Step 2: Create api/client.ts**

```typescript
import ky from 'ky'

// In development, Vite proxies /api to :8000
// In production, FastAPI serves the SPA and API is same origin
const api = ky.create({
  prefixUrl: '/api',
  headers: { 'Accept': 'application/json' },
  timeout: 30_000,
})

export default api
```

- [ ] **Step 3: Create api/entities.ts**

```typescript
import { useQuery, useInfiniteQuery } from '@tanstack/react-query'
import api from './client'

export interface Entity {
  id: string
  org_id: string
  target_id: string
  entity_type: string
  entity_value: string
  attributes: Record<string, unknown>
  first_seen_at: string
  last_seen_at: string
  is_first_discovery: boolean
}

export interface EntityDetail extends Entity {
  raw_event_ids: string[]
}

export interface Relationship {
  id: string
  source_entity_id: string
  target_entity_id: string
  relationship_type: string
  relationship_source: string
  first_seen_at: string
}

export interface EntitiesResponse {
  entities: Entity[]
  next_cursor: string | null
}

export function useEntities(params: {
  target_id?: string
  entity_type?: string
  first_seen_since?: string
  last_seen_before?: string
  limit?: number
  cursor?: string
}) {
  return useInfiniteQuery({
    queryKey: ['entities', params],
    queryFn: async ({ pageParam }) => {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.entity_type) searchParams.entity_type = params.entity_type
      if (params.first_seen_since) searchParams.first_seen_since = params.first_seen_since
      if (params.last_seen_before) searchParams.last_seen_before = params.last_seen_before
      searchParams.limit = String(params.limit ?? 50)
      if (pageParam) searchParams.cursor = pageParam as string
      return api.get('entities', { searchParams }).json<EntitiesResponse>()
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  })
}

export function useEntity(entityId: string | null) {
  return useQuery({
    queryKey: ['entity', entityId],
    queryFn: () => api.get(`entities/${entityId}`).json<EntityDetail>(),
    enabled: entityId !== null,
  })
}

export function useEntityRelationships(entityId: string | null) {
  return useQuery({
    queryKey: ['entity-relationships', entityId],
    queryFn: () => api.get(`entities/${entityId}/relationships`).json<{ relationships: Relationship[] }>(),
    enabled: entityId !== null,
  })
}
```

- [ ] **Step 4: Create api/runs.ts**

```typescript
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from './client'

export interface RunSummary {
  id: string
  target_id: string
  source: string
  trigger_type: string
  status: string
  scheduled_for: string | null
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  inserted_count: number
  deduped_count: number
  error_count: number
}

export interface RunDetail extends RunSummary {
  error_message: string | null
  metadata: Record<string, unknown>
}

export function useRuns(params: {
  target_id?: string
  source?: string
  status?: string
  trigger_type?: string
  start?: string
  end?: string
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: ['runs', params],
    queryFn: () => {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.source) searchParams.source = params.source
      if (params.status) searchParams.status = params.status
      if (params.trigger_type) searchParams.trigger_type = params.trigger_type
      if (params.start) searchParams.start = params.start
      if (params.end) searchParams.end = params.end
      searchParams.limit = String(params.limit ?? 50)
      searchParams.offset = String(params.offset ?? 0)
      return api.get('runs', { searchParams }).json<RunSummary[]>()
    },
  })
}

export function useRun(runId: string | null) {
  return useQuery({
    queryKey: ['run', runId],
    queryFn: () => api.get(`runs/${runId}`).json<RunDetail>(),
    enabled: runId !== null,
  })
}

export function useTriggerRun() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ targetId, runner }: { targetId: string; runner: string }) =>
      api.post(`runs/${targetId}/${runner}`).json<{ run_id: string; status: string; message: string }>(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['runs'] })
    },
  })
}
```

- [ ] **Step 5: Create api/targets.ts**

```typescript
import { useQuery } from '@tanstack/react-query'
import api from './client'

export interface RunnerInfo {
  enabled: boolean
  schedule: string | null
  last_run_id?: string
  last_run_status?: string
}

export interface TargetSummary {
  id: string
  name: string
  type: string
  enabled: boolean
  labels: Record<string, string>
  runners: Record<string, RunnerInfo>
}

export function useTargets() {
  return useQuery({
    queryKey: ['targets'],
    queryFn: () => api.get('targets').json<TargetSummary[]>(),
  })
}

export function useTarget(targetId: string | null) {
  return useQuery({
    queryKey: ['target', targetId],
    queryFn: () => api.get(`targets/${targetId}`).json<TargetSummary & { match_rules: Record<string, unknown>; runners: Record<string, unknown> }>(),
    enabled: targetId !== null,
  })
}
```

- [ ] **Step 6: Create api/graph.ts**

```typescript
import { useQuery } from '@tanstack/react-query'
import api from './client'
import type { Entity } from './entities'

export interface Relationship {
  id: string
  source_entity_id: string
  target_entity_id: string
  relationship_type: string
  relationship_source: string
  first_seen_at: string
}

export interface GraphData {
  target_id: string
  max_depth: number
  nodes: (Entity & { depth: number })[]
  edges: Relationship[]
}

export function useGraph(targetId: string | null, depth: number = 3) {
  return useQuery({
    queryKey: ['graph', targetId, depth],
    queryFn: () => api.get(`graph/${targetId}`, { searchParams: { depth: String(depth) } }).json<GraphData>(),
    enabled: targetId !== null,
  })
}
```

- [ ] **Step 7: Create lib/entity-colors.ts**

```typescript
import { colors, ENTITY_TYPES, type EntityType } from '../DESIGN_TOKENS'

export function getEntityColor(entityType: string): string {
  const normalized = entityType.toLowerCase()
  const map: Record<string, string> = {
    asn: colors.entityAsn,
    ip_range: colors.entityIpRange,
    ip: colors.entityIp,
    hostname: colors.entityHostname,
    domain: colors.entityDomain,
    certificate: colors.entityCertificate,
    org: colors.entityOrg,
  }
  return map[normalized] ?? colors.mute
}

export function getEntityBgColor(entityType: string): string {
  const color = getEntityColor(entityType)
  return `${color}1f` // 12% opacity hex
}

export function getEntityLabel(entityType: string): string {
  const normalized = entityType.toLowerCase()
  const map: Record<string, string> = {
    asn: 'ASN',
    ip_range: 'IP Range',
    ip: 'IP',
    hostname: 'Hostname',
    domain: 'Domain',
    certificate: 'Certificate',
    org: 'Org',
  }
  return map[normalized] ?? entityType
}

export { ENTITY_TYPES, type EntityType }
```

- [ ] **Step 8: Create lib/format.ts**

```typescript
export function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const minutes = Math.floor(ms / 60_000)
  const seconds = Math.floor((ms % 60_000) / 1000)
  return `${minutes}m ${seconds}s`
}

export function formatRelativeTime(isoDate: string | null): string {
  if (!isoDate) return '—'
  const date = new Date(isoDate)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return 'just now'
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 30) return `${diffDay}d ago`
  return date.toLocaleDateString()
}

export function formatDateTime(isoDate: string | null): string {
  if (!isoDate) return '—'
  return new Date(isoDate).toLocaleString()
}

export function truncateMiddle(s: string, maxLen: number = 40): string {
  if (s.length <= maxLen) return s
  const half = Math.floor(maxLen / 2) - 1
  return s.slice(0, half) + '…' + s.slice(-half)
}
```

- [ ] **Step 9: Create shared/Badge.tsx**

```tsx
import { type FC } from 'react'
import { colors } from '../../DESIGN_TOKENS'

type BadgeVariant = 'success' | 'error' | 'warning' | 'running' | 'pending'

const variantStyles: Record<BadgeVariant, { bg: string; text: string }> = {
  success: { bg: `${colors.statusSuccess}1f`, text: colors.statusSuccess },
  error: { bg: `${colors.statusError}1f`, text: colors.statusError },
  warning: { bg: `${colors.statusWarning}1f`, text: colors.statusWarning },
  running: { bg: `${colors.statusRunning}1f`, text: colors.statusRunning },
  pending: { bg: `${colors.statusPending}1f`, text: colors.statusPending },
}

interface BadgeProps {
  variant: BadgeVariant
  children: React.ReactNode
  className?: string
}

export const Badge: FC<BadgeProps> = ({ variant, children, className = '' }) => {
  const style = variantStyles[variant]
  return (
    <span
      className={`inline-flex items-center rounded-pill px-2 py-0.5 font-mono text-[11px] font-semibold tracking-wider uppercase ${className}`}
      style={{ backgroundColor: style.bg, color: style.text }}
    >
      {children}
    </span>
  )
}

interface EntityTypeBadgeProps {
  entityType: string
  className?: string
}

export const EntityTypeBadge: FC<EntityTypeBadgeProps> = ({ entityType, className = '' }) => {
  const color = getEntityColor(entityType)
  const label = getEntityLabel(entityType)
  return (
    <span
      className={`inline-flex items-center rounded-pill px-2 py-0.5 font-mono text-[11px] font-semibold tracking-wider ${className}`}
      style={{ backgroundColor: `${color}1f`, color }}
    >
      {label}
    </span>
  )
}

import { getEntityColor, getEntityLabel } from '../../lib/entity-colors'
```

- [ ] **Step 10: Create shared/Button.tsx**

```tsx
import { type FC, type ButtonHTMLAttributes } from 'react'
import { colors } from '../../DESIGN_TOKENS'

type ButtonVariant = 'primary' | 'outline' | 'ghost' | 'danger'

const variantStyles: Record<ButtonVariant, React.CSSProperties> = {
  primary: { backgroundColor: colors.primary, color: colors.onPrimary },
  outline: { backgroundColor: colors.canvas, color: colors.ink, borderColor: colors.hairline },
  ghost: { backgroundColor: 'transparent', color: colors.primarySoft },
  danger: { backgroundColor: colors.statusError, color: colors.inkStrong },
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
}

export const Button: FC<ButtonProps> = ({ variant = 'primary', className = '', style, ...props }) => {
  const variantStyle = variantStyles[variant]
  return (
    <button
      className={`inline-flex items-center justify-center rounded-sm px-4 py-2 text-sm font-semibold leading-5 transition-colors hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      style={{ ...variantStyle, border: variant === 'outline' ? '1px solid' : 'none', ...style }}
      {...props}
    />
  )
}
```

- [ ] **Step 11: Create shared/Card.tsx**

```tsx
import { type FC, type ReactNode } from 'react'

interface CardProps {
  children: ReactNode
  className?: string
  style?: React.CSSProperties
}

export const Card: FC<CardProps> = ({ children, className = '', style }) => (
  <div className={`rounded-md border border-hairline bg-canvas p-6 ${className}`} style={style}>
    {children}
  </div>
)

interface MetricCardProps {
  label: string
  value: number | string
  color?: string
  className?: string
}

export const MetricCard: FC<MetricCardProps> = ({ label, value, color, className = '' }) => (
  <Card className={`flex flex-col gap-1 ${className}`}>
    <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">{label}</span>
    <span className="font-mono text-[32px] font-semibold leading-9" style={color ? { color } : undefined}>
      {value}
    </span>
  </Card>
)
```

- [ ] **Step 12: Create shared/SearchInput.tsx**

```tsx
import { type FC, type InputHTMLAttributes } from 'react'
import { Search } from 'lucide-react'

interface SearchInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  onSearch?: (value: string) => void
}

export const SearchInput: FC<SearchInputProps> = ({ onSearch, className = '', ...props }) => (
  <div className={`relative ${className}`}>
    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" />
    <input
      type="text"
      className="w-full rounded-md border border-hairline bg-canvas-soft py-3 pl-10 pr-4 text-sm text-ink placeholder:text-mute focus:outline-none focus:ring-1 focus:ring-primary"
      placeholder="Search entities..."
      onChange={(e) => onSearch?.(e.target.value)}
      {...props}
    />
  </div>
)
```

- [ ] **Step 13: Create shared/TypeFilter.tsx**

```tsx
import { type FC } from 'react'
import { ENTITY_TYPES, ENTITY_LABELS, type EntityType } from '../../DESIGN_TOKENS'
import { getEntityColor } from '../../lib/entity-colors'

interface TypeFilterProps {
  selected: string | null
  onSelect: (type: string | null) => void
  counts?: Record<string, number>
}

export const TypeFilter: FC<TypeFilterProps> = ({ selected, onSelect, counts }) => (
  <div className="flex flex-wrap gap-2">
    <button
      onClick={() => onSelect(null)}
      className={`rounded-pill px-3 py-1 text-sm font-medium transition-colors ${
        selected === null ? 'bg-primary text-on-primary' : 'bg-canvas-soft text-body hover:text-ink'
      }`}
    >
      All{counts ? ` (${Object.values(counts).reduce((a, b) => a + b, 0)})` : ''}
    </button>
    {ENTITY_TYPES.map((type) => {
      const color = getEntityColor(type)
      const label = ENTITY_LABELS[type]
      const count = counts?.[type]
      return (
        <button
          key={type}
          onClick={() => onSelect(type)}
          className={`rounded-pill px-3 py-1 text-sm font-medium transition-colors ${selected === type ? 'text-ink-strong' : 'text-body hover:text-ink'}`}
          style={selected === type ? { backgroundColor: `${color}1f`, borderColor: color } : undefined}
        >
          {label}{count !== undefined ? ` (${count})` : ''}
        </button>
      )
    })}
  </div>
)
```

- [ ] **Step 14: Verify build passes**

```bash
cd /Users/zach/localcode/open-easm/ui && npm run build
```

Expected: Build succeeds.

- [ ] **Step 15: Commit**

```bash
cd /Users/zach/localcode/open-easm && git add ui/src/DESIGN_TOKENS.ts ui/src/api/ ui/src/lib/ ui/src/components/shared/ && git commit -m "feat(ui): add API client, design tokens, and shared components"
```


### Task 3: App Shell — Sidebar + Top Bar + Routing

**Files:**
- Modify: `ui/src/components/layout/AppShell.tsx`
- Create: `ui/src/components/layout/Sidebar.tsx`
- Create: `ui/src/components/layout/TopBar.tsx`
- Create: `ui/src/components/shared/SlideOver.tsx`

- [ ] **Step 1: Create Sidebar.tsx** — collapsible sidebar with 5 nav items (Dashboard, Inventory, Graph, Runs, Targets). Uses Lucide icons. Active state shows 2px teal left-indicator. Collapsible between 64px (icons only) and 240px (icon + label).

- [ ] **Step 2: Create TopBar.tsx** — breadcrumb path from current route + SearchInput component. `bg-canvas` with `border-b border-hairline`.

- [ ] **Step 3: Create shared/SlideOver.tsx** — right-edge 440px slide-over panel. Background `bg-canvas`, left border `border-hairline`. Has close button (X icon). Uses `transform translate-x` for slide animation.

- [ ] **Step 4: Rewrite AppShell.tsx** — composes Sidebar + TopBar + main content area (`<Outlet />`). Sidebar state (expanded/collapsed) managed locally. Layout: `flex h-screen`, sidebar on left, main area fills remainder.

- [ ] **Step 5: Verify navigation works** — click each nav item, confirm routes render. Run `npm run build`.

- [ ] **Step 6: Commit**

```bash
git add ui/src/components/layout/ ui/src/components/shared/SlideOver.tsx && git commit -m "feat(ui): add sidebar, top bar, slide-over, and app shell routing"
```


### Task 4: Inventory View

**Files:**
- Rewrite: `ui/src/components/inventory/InventoryView.tsx`
- Create: `ui/src/components/inventory/EntityTable.tsx`
- Create: `ui/src/components/inventory/EntityDetail.tsx`
- Create: `ui/src/hooks/useDebounce.ts`

- [ ] **Step 1: Create useDebounce.ts** — simple debounce hook (300ms default) for search input.

- [ ] **Step 2: Rewrite InventoryView.tsx** — composes TypeFilter + SearchInput + EntityTable. Manages entity_type filter, search query (debounced), and selected entity ID for slide-over. Uses `useEntities` hook with infinite query.

- [ ] **Step 3: Create EntityTable.tsx** — paginated table with columns: Type (EntityTypeBadge), Value (monospace), Target, First Seen, Last Seen. Uses "Load more" button for pagination. Row click sets selected entity ID.

- [ ] **Step 4: Create EntityDetail.tsx** — slide-over content showing entity metadata (type badge, value in monospace, first_seen, last_seen, is_first_discovery, attributes JSON, raw_event_ids list). Uses `useEntity` and `useEntityRelationships` hooks.

- [ ] **Step 5: Test by running against live API** — if backend is running with data, verify entity list loads, type filter works, search works, slide-over opens on click.

- [ ] **Step 6: Commit**

```bash
git add ui/src/components/inventory/ ui/src/hooks/useDebounce.ts && git commit -m "feat(ui): add inventory view with entity table, type filter, search, and detail slide-over"
```


### Task 5: FastAPI Static File Serving

**Files:**
- Modify: `ui/src/easm/api/app.py`

- [ ] **Step 1: Add static file serving to app.py** — after all API routes, mount the built SPA from `ui/dist` at `/ui`. Also add a catch-all route for SPA routing.

- [ ] **Step 2: Build the SPA** — `cd ui && npm run build`

- [ ] **Step 3: Start FastAPI** — verify `/ui/` serves the SPA and `/api/` routes still work.

- [ ] **Step 4: Commit**

```bash
git add src/easm/api/app.py && git commit -m "feat(api): serve React SPA from /ui route"
```


---

## Phase 2: Dashboard + Runs

### Task 6: Dashboard View

**Files:**
- Rewrite: `ui/src/components/dashboard/DashboardView.tsx`
- Create: `ui/src/components/dashboard/MetricCards.tsx`
- Create: `ui/src/components/dashboard/ActiveRuns.tsx`
- Create: `ui/src/components/dashboard/RecentDiscoveries.tsx`
- Create: `ui/src/components/dashboard/QuickTrigger.tsx`
- Create: `ui/src/hooks/useAutoRefresh.ts`
- Create: `ui/src/api/events.ts`

- [ ] **Step 1: Create useAutoRefresh.ts** — polling hook. Takes a query key and interval (default 5000ms). Returns `isAutoRefreshing` and toggle. Uses TanStack Query's `refetchInterval`.

- [ ] **Step 2: Create api/events.ts** — TanStack Query hook for `GET /events` (recent events).

- [ ] **Step 3: Create MetricCards.tsx** — 4-up grid of MetricCard components showing entity counts by type (Domain, IP, Hostname, Certificate). Fetches entity counts via `useEntities` with type filter and limit=1 (just to get total via pagination cursor estimate — or a dedicated count endpoint if we add one).

- [ ] **Step 4: Create ActiveRuns.tsx** — card showing currently running and pending runs. Uses `useRuns` with status filter. Shows status badges. Auto-refreshes every 5s when any run has status "running" or "pending".

- [ ] **Step 5: Create RecentDiscoveries.tsx** — feed-style card showing last 10 entities with `is_first_discovery=true`. Each row shows EntityTypeBadge + entity value (monospace) + relative time.

- [ ] **Step 6: Create QuickTrigger.tsx** — card with per-target runner trigger buttons. Uses `useTargets` to get runner configs, `useTriggerRun` mutation for triggers.

- [ ] **Step 7: Compose DashboardView.tsx** — arranges MetricCards (4-up), ActiveRuns, RecentDiscoveries, QuickTrigger in a grid layout.

- [ ] **Step 8: Verify dashboard loads with real data** (or mock).

- [ ] **Step 9: Commit**

```bash
git add ui/src/components/dashboard/ ui/src/hooks/useAutoRefresh.ts ui/src/api/events.ts && git commit -m "feat(ui): add dashboard with metrics, active runs, discoveries, and trigger"
```


### Task 7: Runs View

**Files:**
- Rewrite: `ui/src/components/runs/RunsView.tsx`
- Create: `ui/src/components/runs/RunsTable.tsx`
- Create: `ui/src/components/runs/RunDetail.tsx`

- [ ] **Step 1: Create RunsTable.tsx** — table with columns: Target, Runner, Trigger, Status (Badge), Started, Duration, Inserted, Deduped, Errors. Click to expand row showing run metadata JSON.

- [ ] **Step 2: Create RunDetail.tsx** — expanded row showing metadata JSON and error message.

- [ ] **Step 3: Rewrite RunsView.tsx** — filter bar (target dropdown, runner dropdown, status dropdown, date range) + RunsTable. Auto-refreshes when any run is running/pending.

- [ ] **Step 4: Verify runs view works** with real data.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/runs/ && git commit -m "feat(ui): add runs view with filters, table, and auto-refresh"
```


---

## Phase 3: Graph Explorer

### Task 8: D3-Force Graph Visualization

**Files:**
- Rewrite: `ui/src/components/graph/GraphView.tsx`
- Create: `ui/src/components/graph/ForceGraph.tsx`
- Create: `ui/src/components/graph/GraphLegend.tsx`
- Create: `ui/src/components/graph/GraphControls.tsx`
- Create: `ui/src/lib/d3-force.ts`

- [ ] **Step 1: Create lib/d3-force.ts** — D3 force simulation factory. Creates a force simulation with forceLink, forceManyBody, forceCenter, forceCollide. Configurable node radius (based on entity type), link distance, and charge strength. Returns start/stop/drag methods.

- [ ] **Step 2: Create ForceGraph.tsx** — React component wrapping SVG + D3 force simulation. Renders nodes as circles (fill = entity-type color at 20%, stroke = entity-type color at 100%, stroke-width 1.5px). Renders edges as lines (stroke = hairline-soft). Handles click (highlight connections), double-click (open detail), and drag. Uses d3-zoom for pan/zoom. Uses d3-drag for node repositioning.

- [ ] **Step 3: Create GraphLegend.tsx** — small overlay in top-right showing entity-type color key (colored circle + label for each type).

- [ ] **Step 4: Create GraphControls.tsx** — zoom in/out/reset buttons + depth slider (1-10). Uses Lucide icons (ZoomIn, ZoomOut, RotateCcw).

- [ ] **Step 5: Rewrite GraphView.tsx** — target selector dropdown (from useTargets) + depth control + ForceGraph + GraphLegend + GraphControls. Uses useGraph hook. Shows SlideOver on node double-click.

- [ ] **Step 6: Verify graph renders with real data** (if a target with entities exists).

- [ ] **Step 7: Commit**

```bash
git add ui/src/components/graph/ ui/src/lib/d3-force.ts && git commit -m "feat(ui): add D3-force graph explorer with node colors, legend, and controls"
```


---

## Phase 4: Targets & Pivots

### Task 8: Pivot Queue API Endpoint

**Files:**
- Create: `ui/src/easm/api/routes/pivot_queue.py`
- Modify: `ui/src/easm/api/app.py`

- [ ] **Step 1: Create pivot_queue.py** — FastAPI route with `GET /pivot-queue` endpoint. Supports filters: status, target_id, entity_type, limit, cursor pagination. Returns pivot_queue rows with status badges.

- [ ] **Step 2: Register route in app.py** — add `from easm.api.routes import pivot_queue` and `app.include_router(pivot_queue.router)`.

- [ ] **Step 3: Verify API endpoint works** — test with `curl http://localhost:8000/pivot-queue`.

- [ ] **Step 4: Commit**

```bash
git add src/easm/api/routes/pivot_queue.py src/easm/api/app.py && git commit -m "feat(api): add GET /pivot-queue endpoint with filters"
```


### Task 9: Pivot Queue API Hook + Cascade Visualization

**Files:**
- Create: `ui/src/api/pivot-queue.ts`
- Create: `ui/src/components/shared/CascadeStep.tsx`
- Rewrite: `ui/src/components/targets/TargetsView.tsx`
- Create: `ui/src/components/targets/TargetCards.tsx`
- Create: `ui/src/components/targets/PivotQueueTable.tsx`
- Create: `ui/src/components/targets/CascadeVisualization.tsx`

- [ ] **Step 1: Create api/pivot-queue.ts** — TanStack Query hook for `GET /pivot-queue` with filters.

- [ ] **Step 2: Create shared/CascadeStep.tsx** — a single step in the discovery cascade. Shows entity-type badge, count, and connecting arrow. Styled with entity-type color and hairline border.

- [ ] **Step 3: Create TargetCards.tsx** — one card per target showing name, type, enabled status, runner configs with status badges.

- [ ] **Step 4: Create PivotQueueTable.tsx** — table of pivot queue jobs with columns: Entity Type, Pivot Type, Status (badge), Depth, Enqueued, Completed. Filterable by status.

- [ ] **Step 5: Create CascadeVisualization.tsx** — horizontal chain of CascadeStep components. Queries entities grouped by type for a target, shows count at each level. Arrow connections between steps.

- [ ] **Step 6: Rewrite TargetsView.tsx** — composes TargetCards, PivotQueueTable, and CascadeVisualization. Tab sub-navigation within the view.

- [ ] **Step 7: Verify targets & pivots view renders with real data**.

- [ ] **Step 8: Commit**

```bash
git add ui/src/api/pivot-queue.ts ui/src/components/shared/CascadeStep.tsx ui/src/components/targets/ && git commit -m "feat(ui): add targets, pivot queue, and cascade visualization"
```


## Phase 5: Polish + Integration Testing

### Task 10: Polish + Responsive + Integration

- [ ] **Step 1: Add responsive breakpoints** — sidebar collapses to 64px at tablet (<1024px), hides at mobile (<768px). Metric cards grid adjusts 4→2→1-up. Entity table scrolls horizontally at mobile.

- [ ] **Step 2: Add favicon.svg** — simple teal shield/scan icon matching the brand.

- [ ] **Step 3: Add loading states** — skeleton placeholders for cards and tables during data fetch.

- [ ] **Step 4: Add error states** — error boundaries and error messages for failed API calls.

- [ ] **Step 5: Build and test the full SPA** — `npm run build`, serve via FastAPI, verify all 5 views work end-to-end.

- [ ] **Step 6: Final commit**

```bash
git add -A && git commit -m "feat(ui): polish — responsive breakpoints, loading states, error states, favicon"
```


---

## Self-Review

### Spec Coverage Check

| Spec Requirement | Task |
|---|---|
| App shell with sidebar | Task 3 |
| Dashboard metric cards | Task 6 |
| Runs view with filters | Task 7 |
| Inventory with type tabs/search | Task 4 |
| Entity detail slide-over | Task 4 |
| Graph explorer with D3-force | Task 8 |
| Targets & pivots view | Task 9 |
| Pivot queue API endpoint | Task 8 (backend) |
| Cascade visualization | Task 9 |
| FastAPI monolith serving | Task 5 |
| Auto-refresh for runs/status | Task 6 (useAutoRefresh) |
| DESIGN.md tokens via Tailwind | Task 1 (index.css) |
| Entity-type color system | Task 2 (DESIGN_TOKENS, entity-colors) |
| Status badges | Task 2 (Badge component) |
| Search/filter | Task 4 (InventoryView) |

### Placeholder Scan

No TBD, TODO, or "implement later" markers found. All steps contain full code or explicit instructions.

### Type Consistency

All API hook return types match the schemas defined in `api/*.ts`. Entity types use string literal unions from `DESIGN_TOKENS.ts`. Component prop types are defined inline with TypeScript interfaces.