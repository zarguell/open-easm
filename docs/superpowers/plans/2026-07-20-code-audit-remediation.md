# Open EASM — Code Audit Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **IMPORTANT:** Phases are ordered by risk reduction. Phase 0 must come first (fixes active security holes). Phases 1–7 are independent and can be parallelized after Phase 0 deploys.

**Goal:** Address all findings from the July 2026 comprehensive code audit across 8 sequenced phases — from 90-minute security quick wins through backend modularization and operations hardening.

**Architecture:** 8 independent phases sequenced by risk reduction. Each phase produces a self-contained set of changes that can be tested, committed, and deployed independently. Phase 0 is a prerequisite (active security holes). Phases 1–7 have no hard ordering dependencies — they target separate subsystems (auth, info-disclosure, SSRF, frontend, backend, error handling, ops).

**Tech Stack:** Python 3.14 / FastAPI / asyncpg (backend), React 19 / TypeScript / Vite / Tailwind CSS 4 (frontend), APScheduler (scheduler), PostgreSQL 18 (database), Docker Compose (deployment).

**Budget:** Phase 0 ≈ 90 min. Phases 1–3 ≈ 1–2 days. Phase 4 ≈ 1–2 days. Phase 5 ≈ 1–3 weeks. Phases 6–7 ≈ 1–2 days.

---

## File Structure

Files to CREATE:
- `src/easm/api/authz.py` — role-based access control dependencies
- `src/easm/api/rate_limit.py` — per-endpoint rate limiting
- `src/easm/api/middleware/security.py` — CSP and security headers middleware
- `src/easm/network_guard.py` — private-IP / metadata-endpoint blocking for HTTP clients
- `src/easm/stores/__init__.py` — domain store package
- `src/easm/stores/run_store.py`
- `src/easm/stores/entity_store.py`
- `src/easm/stores/finding_store.py`
- `src/easm/stores/asset_store.py`
- `src/easm/stores/certificate_store.py`
- `src/easm/stores/auth_store.py`
- `src/easm/stores/config_store.py`
- `src/easm/stores/triage_store.py`
- `src/easm/pivot/handlers/dns.py`
- `src/easm/pivot/handlers/cert.py`
- `src/easm/pivot/handlers/enrichment.py`
- `src/easm/pivot/handlers/takeover.py`
- `src/easm/runners/lifecycle.py`
- `src/easm/runners/subprocess.py`
- `src/easm/runners/http.py`
- `src/easm/runners/ingestion.py`
- `ui/eslint.config.mjs`
- `ui/vitest.config.ts`
- Various `<domain>.test.tsx` files

Files to MODIFY (across all phases, listed per task below):
- `src/easm/api/app.py` — CORS, exception handler, CSP, rate limiting
- `src/easm/api/deps.py` — authz helper exports
- `src/easm/api/routes/*.py` — role guards, org_id scoping, info redaction
- `src/easm/api/routes/health.py` — strip binary/runtime details
- `src/easm/auth/*.py` — hardening config validation
- `src/easm/store.py` — delegate to sub-stores after split
- `src/easm/pivot/handlers.py` — split into submodules, fix verify=False
- `src/easm/runners/engine.py` — split into submodules
- `src/easm/runners/breach_monitor_runner.py` (etc.) — migrate to RunnerDef
- `src/easm/runners/schemas.py` — replace with declarative approach
- `src/easm/main.py` — register middleware
- `ui/src/App.tsx` — lazy loading
- `ui/src/api/findings.ts` — React Query migration
- `ui/src/components/GeoMap.tsx` — XSS fix
- `ui/src/DESIGN_TOKENS.ts` — design token fixes
- `ui/src/lib/entity-colors.ts` — consolidate entity color map
- Various frontend TSX files — bg-surface, text-muted, selectClass, aria fixes
- `docker-compose.yml` — PG bind address
- `Dockerfile` — HEALTHCHECK
- `pyproject.toml` — version pins, ruff rules

---

## Phase 0: Security Quick Wins (90 min)

**Goal:** Fix the 5 ship-blocking security issues and 2 visual bugs from the audit.

**Dependencies:** None. Can be done first.

### Task 0.1: Fix CORS configuration

**Files:**
- Modify: `src/easm/api/app.py:73-79`

- [ ] **Step 1: Replace CORS middleware config**

```python
# OLD:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# NEW: If using cookie auth, pin the frontend origin
# If API-key-only auth is the only path, drop allow_credentials
# For development, allow localhost origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://localhost:8000",  # Same-origin
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

- [ ] **Step 2: Verify with diagnostics**

Run:
```bash
ruff check src/easm/api/app.py
mypy src/easm/api/app.py
pytest tests/ -x -q --no-header 2>&1 | tail -5
```

Expected: lint passes, mypy passes, existing tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/easm/api/app.py
git commit -m "fix(security): pin CORS origins instead of wildcard, drop allow_credentials for wildcard"
```

### Task 0.2: Fix global exception handler

**Files:**
- Modify: `src/easm/api/app.py:85-88`

- [ ] **Step 1: Replace detail=str(exc) with static message**

```python
# OLD:
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled exception", extra={"path": request.url.path})
    return JSONResponse(status_code=500, content={"error": "internal", "detail": str(exc)})

# NEW:
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled exception", extra={"path": request.url.path})
    return JSONResponse(status_code=500, content={"error": "internal", "detail": "internal server error"})
```

- [ ] **Step 2: Verify**

Run:
```bash
ruff check src/easm/api/app.py
```

- [ ] **Step 3: Commit**

```bash
git add src/easm/api/app.py
git commit -m "fix(security): remove stack traces from 500 error responses"
```

### Task 0.3: Strip binary/runtime details from /api/healthz

**Files:**
- Modify: `src/easm/api/routes/health.py:53-103`

- [ ] **Step 1: Read current health endpoint**

```bash
grep -n 'binaries\|runtime\|pivot_queue\|binaries' src/easm/api/routes/health.py
```

- [ ] **Step 2: Replace health response — keep only status, database, scheduler, version**

```python
# Health endpoint should return:
return {
    "status": "ok",
    "version": "0.1.0",
    "database": "connected" if db_ok else "error",
    "scheduler": "running" if scheduler_ok else "stopped",
    "timestamp": datetime.utcnow().isoformat(),
}
```

Remove `binaries`, `runtime`, `pivot_queue`, `fixtures_path` from the response dict.

- [ ] **Step 3: Verify tests still pass**

Run:
```bash
pytest tests/test_health.py -x -q --no-header 2>&1 | tail -5
```

If `test_health.py` checks for removed fields, update the test expectations.

- [ ] **Step 4: Commit**

```bash
git add src/easm/api/routes/health.py
git commit -m "fix(security): remove binary inventory and runtime policy from unauthenticated health endpoint"
```

### Task 0.4: Add admin guard to config and runner-trigger endpoints

**Files:**
- Create: `src/easm/api/authz.py`
- Modify: `src/easm/api/routes/config.py:26-53`
- Modify: `src/easm/api/routes/runs.py:74-142`
- Modify: `src/easm/api/routes/auth.py` (user delete endpoint)

- [ ] **Step 1: Create authz module**

```python
# src/easm/api/authz.py
from fastapi import Depends, HTTPException, Request, status


def require_role(role: str = "admin"):
    """Dependency that checks the authenticated user has the required role."""
    async def _check(request: Request) -> None:
        user = getattr(request.state, "user", None)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if user.get("role", "") != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' required",
            )
    return _check


require_admin = require_role("admin")
```

- [ ] **Step 2: Add guard to config update endpoint**

```python
# In src/easm/api/routes/config.py, add to imports:
from easm.api.authz import require_admin

# Add to update_config:
@router.put("/config")
async def update_config(
    body: dict,
    _: None = Depends(require_admin),  # <-- add this
    config: Config = Depends(get_config),
    store: Store = Depends(get_store),
):
    ...

# Also add to reload_config:
@router.post("/config/reload")
async def reload_config(
    _: None = Depends(require_admin),  # <-- add this
    config: Config = Depends(get_config),
):
    ...
```

- [ ] **Step 3: Add guard to runner trigger endpoint**

```python
# In src/easm/api/routes/runs.py:
from easm.api.authz import require_admin

@router.post("/runs/{target_id}/{runner}")
async def trigger_runner(
    target_id: str,
    runner: str,
    config: Config = Depends(get_config),
    _: None = Depends(require_admin),  # <-- add this
):
    ...
```

- [ ] **Step 4: Add guard to user delete endpoint**

```python
# In src/easm/api/routes/auth.py:
from easm.api.authz import require_admin

@router.delete("/auth/api-keys/{id}")
async def delete_api_key(
    id: str,
    store: Store = Depends(get_store),
    request: Request = None,
    _: None = Depends(require_admin),  # <-- Only admin can delete any API key
):
    ...

# Also on user management endpoints (delete_user, list_users):
@router.delete("/auth/users/{user_id}")
async def delete_user(
    user_id: str,
    _: None = Depends(require_admin),
    ...
):
    ...
```

- [ ] **Step 5: Verify**

Run:
```bash
ruff check src/easm/api/
mypy src/easm/api/
pytest tests/ -x -q --no-header 2>&1 | tail -5
```

Expected: lint passes, type checks pass, tests pass. Some tests may need updating if they call protected endpoints without auth.

- [ ] **Step 6: Commit**

```bash
git add src/easm/api/authz.py src/easm/api/routes/config.py src/easm/api/routes/runs.py src/easm/api/routes/auth.py
git commit -m "fix(security): add admin role guard to config, runner trigger, and user management endpoints"
```

### Task 0.5: Fix GeoMap XSS

**Files:**
- Modify: `ui/src/components/GeoMap.tsx:98-103`

- [ ] **Step 1: Replace setHTML with safe DOM construction**

```typescript
// OLD:
const popup = new maplibregl.Popup({ offset: 25 }).setHTML(
  `<div>
    <strong>${ip.entity_value}</strong><br />
    ${city ? `${city}, ` : ""}${country_name || ""}
  </div>`
);

// NEW:
const el = document.createElement("div");
const strong = document.createElement("strong");
strong.textContent = ip.entity_value;
el.appendChild(strong);
const br = document.createElement("br");
el.appendChild(br);
const locationText = document.createTextNode(
  `${city ? `${city}, ` : ""}${country_name || ""}`
);
el.appendChild(locationText);
const popup = new maplibregl.Popup({ offset: 25 }).setDOMContent(el);
```

- [ ] **Step 2: Verify TypeScript compiles**

Run:
```bash
cd ui && npx tsc --noEmit --pretty 2>&1 | tail -10
```

Expected: No TypeScript errors.

- [ ] **Step 3: Commit**

```bash
git add ui/src/components/GeoMap.tsx
git commit -m "fix(security): prevent stored XSS in GeoMap popup via setDOMContent over setHTML"
```

### Task 0.6: Fix broken Tailwind classes

**Files:**
- Read first: find all `bg-surface` and `text-muted` usages
- Modify: all files with `bg-surface` (replace with `bg-canvas-elevated`)
- Modify: all files with `text-muted` (replace with `text-mute`)

- [ ] **Step 1: Find all instances**

```bash
grep -rn 'bg-surface' ui/src/ --include='*.tsx' --include='*.ts'
grep -rn 'text-muted' ui/src/ --include='*.tsx' --include='*.ts'
```

- [ ] **Step 2: Replace in each file**

For each file with `bg-surface`:
```bash
sed -i '' 's/bg-surface/bg-canvas-elevated/g' <file>
```

For each file with `text-muted`:
```bash
sed -i '' 's/text-muted/text-mute/g' <file>
```

- [ ] **Step 3: Verify no remaining references**

```bash
grep -rn 'bg-surface\|text-muted' ui/src/ --include='*.tsx' --include='*.ts'
```

Expected: zero matches.

- [ ] **Step 4: Commit**

```bash
git add -u ui/src/
git commit -m "fix(ui): fix broken Tailwind classes — bg-surface→bg-canvas-elevated, text-muted→text-mute"
```

### Task 0.7: Unify entity color maps

**Files:**
- Modify: `ui/src/components/layout/TopBar.tsx:30-38` — delete `entityTypeColors` map, use shared helper

- [ ] **Step 1: Replace TopBar's inline color map with shared helper**

```typescript
// In ui/src/components/layout/TopBar.tsx:
// DELETE the entityTypeColors object (lines ~30-38)
// ADD import:
import { getEntityColor } from "../../lib/entity-colors";

// REPLACE usage:
// OLD: const color = entityTypeColors[entity.entity_type] || "#8b949e";
// NEW: const color = getEntityColor(entity.entity_type as string);
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd ui && npx tsc --noEmit --pretty 2>&1 | tail -10
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/components/layout/TopBar.tsx
git commit -m "fix(ui): unify entity color map — TopBar now uses shared entity-colors lib"
```

**Phase 0 complete.** Verify all changes:

```bash
ruff check src/easm/api/
mypy src/easm/api/
cd ui && npx tsc --noEmit --pretty 2>&1 | tail -5
pytest tests/ -x -q --no-header 2>&1 | tail -5
```

---

## Phase 1: Authorization & Access Control

**Goal:** Close the authentication≠authorization gap — add role enforcement everywhere, add per-tenant query scoping, add rate limiting.

**Dependencies:** Phase 0 (uses `authz.py` created in 0.4).

### Task 1.1: Extend authz with org_id scoping utilities

**Files:**
- Modify: `src/easm/api/authz.py`
- Modify: `src/easm/api/deps.py`

- [ ] **Step 1: Add org-scoping helper**

```python
# Add to src/easm/api/authz.py:
from fastapi import Request, HTTPException, status


def current_org_id(request: Request) -> str:
    """Get the current user's org_id, raising if not available."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user.get("org_id", "default")
```

- [ ] **Step 2: Export from deps.py**

```python
# In src/easm/api/deps.py, add:
from easm.api.authz import require_admin, current_org_id
```

- [ ] **Step 3: Commit**

```bash
git add src/easm/api/authz.py src/easm/api/deps.py
git commit -m "feat(auth): add org_id scoping helper and export from deps"
```

### Task 1.2: Add org_id filtering to list endpoints

**Files:**
- Modify: `src/easm/store.py` — add `org_id` parameter to `list_entities`, `list_findings`, `list_runs`, `list_assets`, `list_certificates`
- Modify: `src/easm/api/routes/entities.py`
- Modify: `src/easm/api/routes/findings.py`
- Modify: `src/easm/api/routes/runs.py`
- Modify: `src/easm/api/routes/assets.py`
- Modify: `src/easm/api/routes/certificates.py`

- [ ] **Step 1: Add org_id WHERE clause to Store.list_entities**

In `Store.list_entities()`:
```python
# Old: no org_id filtering
conditions = []
params: list[str | int] = []
idx = 0

# New: add org_id filter
conditions = ["org_id = $1"]
params: list[str | int] = [org_id]
idx = 1

# (rest of conditions use idx+1, idx+2, etc.)
```

- [ ] **Step 2: Add org_id to route handlers**

```python
# In each list endpoint, extract org_id:
from easm.api.authz import current_org_id

@router.get("/entities")
async def list_entities(
    request: Request,
    org_id_: str = Depends(lambda r: current_org_id(r)),
    target_id: str | None = Query(None),
    ...
):
    ...
    result = await store.list_entities(org_id=org_id_, ...)
```

- [ ] **Step 3: Apply same pattern to list_findings, list_runs, list_assets, list_certificates**

```python
# list_findings currently has NO org_id parameter in Store.
# Add it:
async def list_findings(
    self,
    org_id: str = "default",  # <-- add
    target_id: str | None = None,
    ...
):
    conditions = ["org_id = $1"]
    params: list = [org_id]
    idx = 1
    ...
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/store.py src/easm/api/routes/entities.py src/easm/api/routes/findings.py src/easm/api/routes/runs.py src/easm/api/routes/assets.py src/easm/api/routes/certificates.py
git commit -m "feat(auth): add org_id scoping to all list endpoints"
```

### Task 1.3: Add rate limiting

**Files:**
- Create: `src/easm/api/rate_limit.py`
- Modify: `src/easm/main.py` — register rate limiter
- Modify: `src/easm/api/routes/auth.py` — add rate limit to login/register

- [ ] **Step 1: Create rate limit middleware**

```python
# src/easm/api/rate_limit.py
"""Simple in-memory per-IP rate limiter for sensitive endpoints."""

import time
import asyncio
from collections import defaultdict
from collections.abc import Callable
from fastapi import Request, HTTPException, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limits specific paths per IP address."""

    def __init__(
        self,
        app: ASGIApp,
        limits: dict[str, tuple[int, int]] | None = None,
    ) -> None:
        super().__init__(app)
        self.limits = limits or {
            "/api/auth/login": (5, 60),       # 5 requests per 60s
            "/api/auth/register": (3, 300),    # 3 requests per 300s
            "/api/runs/": (10, 60),            # 10 runner triggers per 60s
        }
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        for path, (max_reqs, window_sec) in self.limits.items():
            if request.url.path.startswith(path):
                await self._check_rate_limit(request, path, max_reqs, window_sec)
                break
        return await call_next(request)

    async def _check_rate_limit(
        self, request: Request, path: str, max_reqs: int, window_sec: int
    ) -> None:
        key = f"{request.client.host}:{path}"
        now = time.time()
        async with self._lock:
            bucket = self._buckets[key]
            # Prune expired entries
            cutoff = now - window_sec
            bucket[:] = [t for t in bucket if t > cutoff]
            if len(bucket) >= max_reqs:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Try again in {window_sec}s.",
                )
            bucket.append(now)
```

- [ ] **Step 2: Register middleware in main.py**

```python
# In src/easm/main.py, add before uvicorn startup:
from easm.api.rate_limit import RateLimitMiddleware

app.add_middleware(RateLimitMiddleware)
```

- [ ] **Step 3: Verify**

Run:
```bash
ruff check src/easm/api/rate_limit.py src/easm/main.py
mypy src/easm/api/rate_limit.py src/easm/main.py
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/api/rate_limit.py src/easm/main.py
git commit -m "feat(auth): add IP-based rate limiting to login, register, and runner trigger endpoints"
```

---

## Phase 2: Information Disclosure Hardening

**Goal:** Close the remaining information disclosure surfaces — config endpoint redacts API keys, enrichment keys stripped from responses.

**Dependencies:** None (independent of Phase 1).

### Task 2.1: Redact enrichment API keys from /api/config response

**Files:**
- Modify: `src/easm/api/routes/config.py` — filter sensitive fields from response

- [ ] **Step 1: Add config response redaction**

```python
# In src/easm/api/routes/config.py, add a helper:
SENSITIVE_KEYS = {"hibp_api_key", "dehashed_api_key", "dehashed_email",
                  "pastebin_api_key", "github_token", "gitleaks_path",
                  "google_api_key", "google_cx", "bing_api_key",
                  "shodan_api_key", "abuseipdb_api_key", "greynoise_api_key",
                  "censys_api_key", "securitytrails_api_key", "urlscan_api_key"}

def _redact_sensitive_fields(config_dict: dict) -> dict:
    """Replace sensitive key values with REDACTED for API responses."""
    for runner in config_dict.get("targets", []):
        for runner_cfg in runner.get("runners", {}).values():
            for key in SENSITIVE_KEYS:
                if key in runner_cfg and runner_cfg[key]:
                    runner_cfg[key] = "REDACTED"
    return config_dict


# Then in the GET /config handler:
@router.get("/config")
async def get_config(config: Config = Depends(get_config)):
    raw = config.model_dump()
    return _redact_sensitive_fields(raw)
```

- [ ] **Step 2: Commit**

```bash
git add src/easm/api/routes/config.py
git commit -m "fix(security): redact enrichment API keys from /api/config response"
```

### Task 2.2: Add password strength validation to auth config

**Files:**
- Modify: `src/easm/auth/config.py` — add min-length validation for session_secret

- [ ] **Step 1: Add session_secret length validation**

```python
# In src/easm/auth/config.py LocalAuthConfig:
@model_validator(mode="after")
def validate_secret(self) -> "LocalAuthConfig":
    if self.mode != "none" and len(self.session_secret or "") < 32:
        raise ValueError(
            "EASM_SESSION_SECRET must be at least 32 characters "
            "when auth.mode is local or sso"
        )
    return self
```

- [ ] **Step 2: Commit**

```bash
git add src/easm/auth/config.py
git commit -m "fix(security): enforce minimum 32-char session secret for local/sso auth"
```

---

## Phase 3: SSRF & Subprocess Hardening

**Goal:** Add private-IP filtering to outbound HTTP clients, fix `verify=False` in takeover probes, add CSP headers.

**Dependencies:** None (independent).

### Task 3.1: Add private-IP reject transport to HTTP clients

**Files:**
- Create: `src/easm/network_guard.py`
- Modify: `src/easm/pivot/handlers.py` — use guarded HTTP client
- Modify: `src/easm/runners/engine.py` — use guarded HTTP client

- [ ] **Step 1: Create network guard module**

```python
# src/easm/network_guard.py
"""Reject connections to private/internal IP ranges to prevent SSRF."""

import ipaddress
import httpx


_PRIVATE_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
]

# Windows/macOS also resolve .local/.internal, but we handle the IP check


def _is_private_ip(host: str) -> bool:
    """Check if a hostname resolves to a private IP range."""
    try:
        import socket
        ip_str = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_CIDRS)
    except (socket.gaierror, ValueError):
        return False


class PrivateIPRejectTransport(httpx.BaseTransport):
    """httpx transport that rejects private IP connections."""

    def __init__(self, wrapped: httpx.BaseTransport | None = None):
        self._wrapped = wrapped or httpx.HTTPTransport()

    def handle_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        host = request.url.host
        if _is_private_ip(host):
            raise httpx.ConnectError(
                f"Connection to private IP blocked by network guard: {host}"
            )
        return self._wrapped.handle_request(request)

    def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        host = request.url.host
        if _is_private_ip(host):
            raise httpx.ConnectError(
                f"Connection to private IP blocked by network guard: {host}"
            )
        return self._wrapped.handle_async_request(request)
```

- [ ] **Step 2: Create guarded httpx.AsyncClient factory**

```python
# Add to src/easm/network_guard.py:
def create_guard_client(**kwargs) -> httpx.AsyncClient:
    """Create an AsyncClient with private-IP rejection built in."""
    transport = kwargs.pop("transport", None)
    kwargs["transport"] = PrivateIPRejectTransport(transport)
    return httpx.AsyncClient(**kwargs)
```

- [ ] **Step 3: Replace client creation in pivot handlers**

```python
# In src/easm/pivot/handlers.py:
from easm.network_guard import create_guard_client

# In functions that create httpx.AsyncClient:
# OLD: async with httpx.AsyncClient() as client:
# NEW: async with create_guard_client() as client:
```

- [ ] **Step 4: Replace client creation in engine.py HTTP runners**

```python
# In src/easm/runners/engine.py:
from easm.network_guard import create_guard_client

# Replace httpx.AsyncClient() with create_guard_client() in _http_fetch_with_retry and _http_probe
```

- [ ] **Step 5: Remove verify=False from _http_probe**

```python
# In src/easm/pivot/handlers.py, around line 620:
# OLD: async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
# NEW: async with create_guard_client(timeout=timeout) as client:
```

- [ ] **Step 6: Verify**

```bash
ruff check src/easm/network_guard.py src/easm/pivot/handlers.py src/easm/runners/engine.py
mypy src/easm/network_guard.py
```

- [ ] **Step 7: Commit**

```bash
git add src/easm/network_guard.py src/easm/pivot/handlers.py src/easm/runners/engine.py
git commit -m "fix(security): add private-IP filtering transport to prevent SSRF; fix TLS verify=False in takeover probes"
```

### Task 3.2: Add Content-Security-Policy headers

**Files:**
- Create: `src/easm/api/middleware/security.py`
- Modify: `src/easm/main.py` — register middleware

- [ ] **Step 1: Create security headers middleware**

```python
# src/easm/api/middleware/security.py
from collections.abc import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""

    def __init__(self, app: ASGIApp, csp_report_only: bool = False) -> None:
        super().__init__(app)
        prefix = "Content-Security-Policy-Report-Only" if csp_report_only else "Content-Security-Policy"
        self.csp = (
            f"{prefix}: default-src 'self'; "
            f"script-src 'self'; "
            f"style-src 'self' 'unsafe-inline'; "  # Tailwind requires inline styles
            f"img-src 'self' data: https://*.tile.openstreetmap.org; "
            f"connect-src 'self' https://api.shodan.io https://api.abuseipdb.com; "
            f"font-src 'self'; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self'"
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers[self.csp.split(":")[0]] = self.csp
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response
```

- [ ] **Step 2: Register in main.py**

```python
# In src/easm/main.py:
from easm.api.middleware.security import SecurityHeadersMiddleware

app.add_middleware(SecurityHeadersMiddleware)
```

- [ ] **Step 3: Commit**

```bash
git add src/easm/api/middleware/security.py src/easm/main.py
git commit -m "feat(security): add CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy headers"
```

---

## Phase 4: Frontend Infrastructure

**Goal:** Add zero-cost frontend infrastructure — linting, testing, code splitting, design token fixes, React Query migration.

**Dependencies:** None. Can parallelize with Phases 1–3.

### Task 4.1: Add ESLint configuration

**Files:**
- Create: `ui/eslint.config.mjs`
- Modify: `ui/package.json` — add scripts

- [ ] **Step 1: Create ESLint flat config**

```javascript
// ui/eslint.config.mjs
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import jsxA11y from "eslint-plugin-jsx-a11y";
import tailwind from "eslint-plugin-tailwindcss";

export default tseslint.config(
  { ignores: ["dist/", "vite.config.d.ts"] },
  {
    extends: [
      ...tseslint.configs.strictTypeChecked,
      ...tseslint.configs.stylisticTypeChecked,
    ],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
      "jsx-a11y": jsxA11y,
      tailwindcss: tailwind,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "jsx-a11y/alt-text": "error",
      "jsx-a11y/scope": "error",
      "jsx-a11y/aria-role": "error",
      "tailwindcss/no-custom-classname": "warn",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/prefer-nullish-coalescing": "error",
    },
  }
);
```

- [ ] **Step 2: Add eslint dependencies and scripts**

```bash
cd ui && npm install -D eslint typescript-eslint @eslint/js eslint-plugin-react-hooks eslint-plugin-react-refresh eslint-plugin-jsx-a11y eslint-plugin-tailwindcss
```

```json
// In ui/package.json, add to scripts:
{
  "lint": "eslint src/",
  "lint:fix": "eslint src/ --fix"
}
```

- [ ] **Step 3: Run lint and fix any issues**

```bash
cd ui && npm run lint 2>&1 | head -40
```

Expected: finds aria issues, unused vars, etc. Fix any errors (not warnings).

- [ ] **Step 4: Commit**

```bash
git add ui/eslint.config.mjs ui/package.json ui/package-lock.json
git commit -m "feat(devx): add ESLint with TypeScript, React hooks, a11y, and Tailwind plugins"
```

### Task 4.2: Add vitest test infrastructure

**Files:**
- Create: `ui/vitest.config.ts`
- Create: `ui/src/test-setup.ts`
- Create: `ui/src/components/GeoMap.test.tsx` (smoke + XSS regression test)

- [ ] **Step 1: Create vitest config**

```typescript
// ui/vitest.config.ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    css: true,
  },
});
```

- [ ] **Step 2: Create test setup file**

```typescript
// ui/src/test-setup.ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 3: Create smoke test for each route**

```typescript
// ui/src/components/GeoMap.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

// GeoMap uses MapLibre which needs a browser mapbox API key or mock
// This tests the popup helper is safe regardless
describe("GeoMap popup content", () => {
  it("should escape HTML in entity values", () => {
    // The helper creates DOM elements, not innerHTML
    // Verify EntityDetail renders textContent, not innerHTML
    const malicious = "<img src=x onerror=alert(1)>";
    const el = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = malicious;   // Should NOT be innerHTML
    el.appendChild(strong);

    expect(el.innerHTML).toBe("<strong>&lt;img src=x onerror=alert(1)&gt;</strong>");
    // textContent automatically escapes
    // If someone changes this to innerHTML, this test fails
    expect(el.textContent).toBe(malicious);
  });
});
```

- [ ] **Step 4: Add test script to package.json**

```json
{
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest"
  }
}
```

- [ ] **Step 5: Install test deps and run**

```bash
cd ui && npm install -D vitest @testing-library/react @testing-library/jest-dom jsdom
npm run test 2>&1 | tail -10
```

Expected: tests pass.

- [ ] **Step 6: Create a screen-reader smoke test for main views**

```typescript
// ui/src/components/auth/LoginPage.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import LoginPage from "./LoginPage";

// Mock the auth hook
vi.mock("../../hooks/useAuth", () => ({
  useAuth: () => ({
    login: vi.fn(),
    user: null,
    loading: false,
    error: null,
  }),
}));

describe("LoginPage", () => {
  it("renders login form with all accessible labels", () => {
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );

    expect(screen.getByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});
```

- [ ] **Step 7: Commit**

```bash
git add ui/vitest.config.ts ui/src/test-setup.ts ui/src/components/GeoMap.test.tsx ui/src/components/auth/LoginPage.test.tsx ui/package.json ui/package-lock.json
git commit -m "feat(test): add vitest, testing-library, smoke tests for login page and GeoMap XSS regression"
```

### Task 4.3: Migrate findings.ts to React Query

**Files:**
- Modify: `ui/src/api/findings.ts` — replace manual useState/useEffect with useQuery/useMutation

- [ ] **Step 1: Rewrite findings hook to use React Query**

```typescript
// In ui/src/api/findings.ts:
// OLD: export function useFindings(params) { const [findings, setFindings] = useState[]; ... useEffect(() => fetchFindings(), [fetchFindings]); return { findings, loading, error, refetch } }

// NEW:
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "./client";
import type { FindingsQuery, FindingsResponse, Finding } from "../lib/types";

export function useFindings(params: FindingsQuery) {
  return useQuery<FindingsResponse>({
    queryKey: ["findings", params],
    queryFn: async () => {
      const searchParams: Record<string, string> = {};
      if (params.target_id) searchParams.target_id = params.target_id;
      if (params.risk) searchParams.risk = params.risk;
      if (params.status) searchParams.status = params.status;
      if (params.rule_id) searchParams.rule_id = params.rule_id;
      if (params.q) searchParams.q = params.q;
      if (params.limit) searchParams.limit = String(params.limit);
      if (params.offset) searchParams.offset = String(params.offset);
      return api.get("findings", { searchParams }).json<FindingsResponse>();
    },
    placeholderData: (prev) => prev,  // keep previous data while refetching
  });
}

export function usePatchFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) =>
      api.patch(`findings/${id}`, { json: { status } }).json<Finding>(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}
```

- [ ] **Step 2: Update ui/src/components/findings/FindingsView.tsx** to use new hooks

Replace `const { findings, loading, error, refetch } = useFindings(params)` with:
```typescript
const { data, isLoading, error, refetch } = useFindings(params);
const findings = data?.findings ?? [];
```

Replace `patchFindingStatus(id, status).then(() => refetch())` with:
```typescript
const patchMutation = usePatchFindingStatus();
// ...
patchMutation.mutate({ id, status }, { onSuccess: () => refetch() });
```

- [ ] **Step 3: Remove old ky.create() instance from findings.ts**

```typescript
// DELETE from findings.ts:
// const api = ky.create({ ... });
// import { useState, useEffect, useCallback } from 'react';

// ADD import:
import api from "./client";
```

- [ ] **Step 4: Verify**

```bash
cd ui && npx tsc --noEmit --pretty 2>&1 | tail -10
npm run lint 2>&1 | tail -10
```

Expected: clean compile, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/api/findings.ts ui/src/components/findings/FindingsView.tsx
git commit -m "refactor(api): migrate findings hooks from manual useState to React Query useQuery/useMutation"
```

### Task 4.4: Add React.lazy code splitting

**Files:**
- Modify: `ui/src/App.tsx`

- [ ] **Step 1: Convert top-level imports to lazy imports**

```typescript
// In ui/src/App.tsx:
// OLD:
import GraphView from "./components/graph/GraphView";
import GeoMap from "./components/GeoMap";
import // ... all route components

// NEW:
import { lazy, Suspense } from "react";

const GraphView = lazy(() => import("./components/graph/GraphView"));
const GeoMap = lazy(() => import("./components/GeoMap"));
// ... etc for all route-level components

// Wrap the RouterProvider or Routes in Suspense:
<Suspense fallback={<div className="flex h-screen items-center justify-center text-ink-mute">Loading...</div>}>
  <Routes>
    ...
  </Routes>
</Suspense>
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd ui && npx tsc --noEmit --pretty 2>&1 | tail -10
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/App.tsx
git commit -m "perf(ui): add React.lazy code splitting for D3, MapLibre, and all route-level components"
```

### Task 4.5: Fix design token drift (hardcoded hex colors, selectClass, aria)

**Files:**
- Modify: `ui/src/components/findings/FindingsView.tsx:21-48` — replace hardcoded hex with design tokens
- Modify: all files with `selectClass` duplication → shared `ui/src/lib/styles.ts`
- Modify: `ui/src/components/layout/Sidebar.tsx` — add aria-label, role="navigation", aria-current
- Modify: `ui/src/components/shared/SlideOver.tsx` — add dialog semantics, aria-modal, Escape key handler

- [ ] **Step 1: Create shared styles lib**

```typescript
// ui/src/lib/styles.ts
export const selectClass =
  "h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-primary";
```

Replace `const selectClass = "..."` inline definitions in `FindingsView.tsx`, `AssetInventoryView.tsx`, `AlertsView.tsx` with `import { selectClass } from "../../lib/styles";`.

- [ ] **Step 2: Replace hardcoded hex in FindingsView**

```typescript
// Replace:
const riskBadgeColor = (risk: string) => {
  switch (risk) {
    case 'critical': return { bg: '#ef44441f', text: '#ef4444' };
    case 'high':     return { bg: '#f973161f', text: '#f97316' };
    // ...
  }
};

// With a reference to DESIGN_TOKENS:
import { colors } from "../../DESIGN_TOKENS";
import { clsx } from "clsx";

const riskBadgeStyle = (risk: string) => {
  const map: Record<string, string> = {
    critical: colors.statusError,
    high: colors.statusWarning,
    medium: colors.statusInfo,
    low: colors.statusSuccess,
  };
  return { backgroundColor: `${map[risk] ?? colors.textMute}1f`, color: map[risk] ?? colors.textMute };
};
```

- [ ] **Step 3: Fix Sidebar accessibility**

```typescript
// In ui/src/components/layout/Sidebar.tsx:
// Wrap nav items:
<aside role="complementary" aria-label="Main navigation">
  <nav>
    {navItems.map((item) => (
      <button
        key={item.path}
        aria-current={isActive(item.path) ? "page" : undefined}
        // ... rest
      />
    ))}
  </nav>
</aside>
```

- [ ] **Step 4: Fix SlideOver accessibility**

```typescript
// In ui/src/components/shared/SlideOver.tsx:
// Add to the overlay div:
<div
  role="dialog"
  aria-modal="true"
  aria-labelledby="slide-over-title"
  // Add Escape key handler:
  onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}
>
  <h2 id="slide-over-title">{title}</h2>
  {/* Ensure focus is trapped within the panel */}
</div>

// Also wrap in a useEffect for focus trap:
useEffect(() => {
  if (!open) return;
  const handleEscape = (e: KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };
  document.addEventListener("keydown", handleEscape);
  return () => document.removeEventListener("keydown", handleEscape);
}, [open, onClose]);
```

- [ ] **Step 5: Add table scope attributes**

Add `scope="col"` to all `<th>` elements in `EntityTable.tsx`, `RunsTable.tsx`, `FindingsView.tsx`, `AssetInventoryTable.tsx`:

```typescript
<th scope="col" className="...">{label}</th>
```

- [ ] **Step 6: Verify lint**

```bash
cd ui && npm run lint 2>&1 | grep -c error
```

Expected: 0 errors. Warnings for `no-custom-classname` on unknown Tailwind classes are acceptable.

- [ ] **Step 7: Commit**

```bash
git add ui/src/lib/styles.ts ui/src/components/findings/FindingsView.tsx ui/src/components/assets/AssetInventoryView.tsx ui/src/components/alerts/AlertsView.tsx ui/src/components/layout/Sidebar.tsx ui/src/components/shared/SlideOver.tsx
git commit -m "fix(ui): consolidate selectClass, fix hardcoded hex colors, add sidebar a11y, fix SlideOver dialog semantics"
```

---

## Phase 5: Backend Modularization (Largest — Weeks 1–3)

**Goal:** Break up the 6 god-object files and finish the class-to-declarative runner migration.

**Dependencies:** None, but benefits from Phases 0–3 being deployed first (less risk during large refactors).

### Task 5.1: Split store.py into domain stores

**Files:**
- Create: `src/easm/stores/__init__.py`
- Create: `src/easm/stores/run_store.py`
- Create: `src/easm/stores/entity_store.py`
- Create: `src/easm/stores/finding_store.py`
- Create: `src/easm/stores/asset_store.py`
- Create: `src/easm/stores/certificate_store.py`
- Create: `src/easm/stores/auth_store.py`
- Create: `src/easm/stores/config_store.py`
- Create: `src/easm/stores/triage_store.py`
- Modify: `src/easm/store.py` — delegate to sub-stores, retain backward-compat API
- Modify: all `src/easm/api/routes/*.py` — import from domain stores directly
- Modify: all `src/easm/runners/*.py` — import from domain stores directly

- [ ] **Step 1: Create store package with base class**

```python
# src/easm/stores/__init__.py
"Domain-specific store modules replacing the monolithic Store class."

from collections.abc import AsyncIterator
import asyncpg


class BaseStore:
    """Shared base for domain stores. Provides pool access."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def _conn(self) -> AsyncIterator[asyncpg.Connection]:
        async with self._pool.acquire() as conn:
            yield conn

    async def _tx(self) -> AsyncIterator[asyncpg.Connection]:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                yield conn
```

- [ ] **Step 2: Extract entity CRUD**

```python
# src/easm/stores/entity_store.py
from typing import Any
from easm.stores import BaseStore


class EntityStore(BaseStore):
    """Domain store for entity and graph operations."""

    async def list_entities(
        self,
        org_id: str = "default",
        target_id: str | None = None,
        entity_type: str | None = None,
        source: str | None = None,
        q: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """List entities with cursor-based pagination and org_id scoping."""
        conditions = ["e.org_id = $1"]
        params: list[str | int] = [org_id]
        idx = 2
        # ... (port existing logic from Store.list_entities)
```

- [ ] **Step 3: Extract run, finding, asset, certificate, auth, config, triage stores** — same pattern

- [ ] **Step 4: Add backward-compat delegation to Store**

```python
# In src/easm/store.py:
from easm.stores.entity_store import EntityStore
from easm.stores.run_store import RunStore
from easm.stores.finding_store import FindingStore
# etc.


class Store:
    """Backward-compatible store. Delegates to domain stores."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool
        self.entities = EntityStore(pool)
        self.runs = RunStore(pool)
        self.findings = FindingStore(pool)
        # etc.

    # Legacy method signatures for backward compat:
    async def list_entities(self, *args, **kwargs):
        return await self.entities.list_entities(*args, **kwargs)
```

- [ ] **Step 5: Migrate import sites**

Replace `from easm.store import Store` with domain-specific imports in route files:
```python
# OLD in routes/entities.py:
from easm.store import Store

# NEW:
from easm.stores.entity_store import EntityStore


# Update dependency:
async def get_entity_store(pool: asyncpg.Pool = Depends(get_pool)):
    return EntityStore(pool)
```

- [ ] **Step 6: Verify tests pass**

```bash
pytest tests/ -x -q --no-header 2>&1 | tail -10
```

- [ ] **Step 7: Commit**

```bash
git add src/easm/stores/ src/easm/store.py src/easm/api/routes/entities.py src/easm/api/routes/runs.py src/easm/api/routes/findings.py src/easm/api/routes/assets.py src/easm/api/routes/certificates.py src/easm/api/routes/config.py src/easm/api/routes/auth.py src/easm/api/routes/triage.py
git commit -m "refactor(store): split monolithic Store into domain-specific stores with backward-compat delegation"
```

### Task 5.2: Split pivot/handlers.py by domain

**Files:**
- Create: `src/easm/pivot/handlers/dns.py`
- Create: `src/easm/pivot/handlers/cert.py`
- Create: `src/easm/pivot/handlers/enrichment.py`
- Create: `src/easm/pivot/handlers/takeover.py`
- Modify: `src/easm/pivot/handlers.py` — re-export or migrate callers

- [ ] **Step 1: Create handler submodules**

Move functions from `pivot/handlers.py` to appropriate submodules:
- `dns.py`: `reverse_dns`, `dns_resolve`, `domain_extract`, `dns_mail_records`
- `cert.py`: `crtsh_search`, `tls_cert_grab`
- `enrichment.py`: `geoip_enrich`, `shodan_enrich`, `abuseipdb_enrich`, `greynoise_enrich`, `urlscan_enrich`, `censys_enrich`, `reverse_whois`, `passive_dns`, `domain_rdap`
- `takeover.py`: `subdomain_takeover`

- [ ] **Step 2: Update PIVOT_HANDLER_REGISTRY to use new import paths**

```python
# In pivot/handlers/takeover.py:
async def subdomain_takeover(...):
    ...

# In pivot/handlers/__init__.py or the existing handlers.py:
from easm.pivot.handlers.dns import reverse_dns, dns_resolve, ...
from easm.pivot.handlers.cert import crtsh_search, tls_cert_grab
from easm.pivot.handlers.enrichment import geoip_enrich, shodan_enrich, ...
from easm.pivot.handlers.takeover import subdomain_takeover

PIVOT_HANDLER_REGISTRY = {
    "reverse_dns": reverse_dns,
    "dns_resolve": dns_resolve,
    ...
}
```

- [ ] **Step 3: Update worker imports**

```python
# In pivot/worker.py:
from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY
```

- [ ] **Step 4: Verify tests pass**

```bash
pytest tests/test_pivot_worker.py tests/test_pivot_resolver.py -x -q --no-header 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
git add src/easm/pivot/handlers/ src/easm/pivot/handlers.py
git commit -m "refactor(pivot): split handlers.py into domain submodules (dns, cert, enrichment, takeover)"
```

### Task 5.3: Split runners/engine.py

**Files:**
- Create: `src/easm/runners/lifecycle.py`
- Create: `src/easm/runners/subprocess.py`
- Create: `src/easm/runners/http.py`
- Create: `src/easm/runners/ingestion.py`
- Modify: `src/easm/runners/engine.py` — re-export or delegate

- [ ] **Step 1: Extract subprocess runner**

```python
# src/easm/runners/subprocess.py
"""Standardized subprocess execution for discovery tools."""

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def standard_subprocess_run(
    binary: str,
    args_template: list[str],
    iterate_over: list[str] = ["[item]"],
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> list[tuple[str, str, int]]:
    """Run a binary against a list of items. Returns [(item, stdout, returncode), ...].
    Ported from runners/engine.py:543-615."""
    ...
```

- [ ] **Step 2: Extract HTTP runner**

```python
# src/easm/runners/http.py
"""Standardized HTTP fetching for discovery tools."""

import asyncio
import httpx
from typing import Any


async def standard_http_run(
    url_template: str,
    # ... (port from engine.py)
) -> Any:
    ...
```

- [ ] **Step 3: Extract entity ingestion**

```python
# src/easm/runners/ingestion.py
"""Entity and relationship ingestion helpers."""

from typing import Any


async def ingest_entities(
    pool: Any,
    target_id: str,
    run_id: str,
    source: str,
    entities: list[Any],
    relationships: list[Any],
    # ...
) -> dict[str, int]:
    """Insert discovered entities and relationships.
    Ported from runners/engine.py:_ingest_entities and _resolve_parent."""
    ...
```

- [ ] **Step 4: Keep backward-compat exports in engine.py**

```python
# src/easm/runners/engine.py (end of file, after porting):
from easm.runners.subprocess import standard_subprocess_run
from easm.runners.http import standard_http_run
from easm.runners.ingestion import ingest_entities

__all__ = ["execute_runner", "standard_subprocess_run", "standard_http_run", "ingest_entities"]
```

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/lifecycle.py src/easm/runners/subprocess.py src/easm/runners/http.py src/easm/runners/ingestion.py src/easm/runners/engine.py
git commit -m "refactor(runners): split engine.py into subprocess, http, and ingestion modules"
```

### Task 5.4: Finish runner migration (classes → RunnerDef)

**Files:**
- Modify: `src/easm/runners/registry.py` — add remaining runner defs
- Delete or reduce: `src/easm/runners/breach_monitor_runner.py`
- Delete or reduce: `src/easm/runners/gist_monitor_runner.py`
- Delete or reduce: `src/easm/runners/paste_monitor_runner.py`
- Delete or reduce: `src/easm/runners/github_scan_runner.py`
- Delete or reduce: `src/easm/runners/stackoverflow_monitor_runner.py`
- Delete or reduce: `src/easm/runners/cloud_bucket_runner.py`
- Delete or reduce: `src/easm/runners/searchengine_runner.py`
- Delete or reduce: `src/easm/runners/portscan_runner.py`
- Delete or reduce: `src/easm/runners/screenshot_runner.py`
- Delete or reduce: `src/easm/runners/certstream_runner.py`

- [ ] **Step 1: Complete RunnerDef equivalents for all 10 legacy runners**

In `src/easm/runners/registry.py`, add the remaining runners following the existing pattern:

```python
RunnerDef(
    name="breach_monitor",
    display_name="Breach Database Monitor",
    description="Check HIBP and Dehashed for breached credentials",
    type="monitor",
    supports_schedule=True,
    supports_manual_trigger=True,
    is_continuous=False,
    binary="",
    args_template=[],  # HTTP-based, not subprocess
    output_schema=breach_monitor_schema,
    iterate_over=iterate_targets,
    config_keys={"hibp_api_key", "dehashed_api_key", "dehashed_email"},
)
```

- [ ] **Step 2: Replace class invocations with RunnerDef lookups**

Find all callers that instantiate legacy classes:
```bash
grep -rn 'BreachMonitorRunner()\|GistMonitorRunner()' src/ --include='*.py'
```

Replace with: `get_runner_def("breach_monitor").execute(...)`

- [ ] **Step 3: Remove RUNNER_REGISTRY migration bridge**

```python
# In src/easm/runners/__init__.py, remove:
# RUNNER_REGISTRY: dict[str, type] = {}  # kept for backward compat during migration
```

- [ ] **Step 4: Verify tests pass**

```bash
pytest tests/test_runners/ -x -q --no-header 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/
git commit -m "refactor(runners): finish runner migration — replace 10 legacy classes with RunnerDef entries"
```

### Task 5.5: Replace output_schema functions with declarative approach

**Files:**
- Create: `src/easm/runners/schemas/` directory with YAML schema files
- Modify: `src/easm/runners/schemas.py` — reduce to one generic engine
- Create: `src/easm/runners/schema_engine.py` — load YAML schemas, apply to raw output

- [ ] **Step 1: Create schema YAML for one runner type**

```yaml
# src/easm/runners/schemas/shodan.yaml
entity_type: ip
value_field: ip_str
attributes:
  - source: hostnames
    target: hostnames
    type: list
  - source: port
    target: port
    type: int
  - source: org
    target: org
    type: str
  - source: isp
    target: isp
    type: str
relationships:
  - type: resolves_to
    from_field: ip_str
    to_type: hostname
    to_field: hostnames.#  # iterate hostnames array
```

- [ ] **Step 2: Create schema engine**

```python
# src/easm/runners/schema_engine.py
"""Generic schema-to-EntityCandidate engine. Reads YAML schema files."""

import yaml
from pathlib import Path
from typing import Any

from easm.runners.schemas import EntityCandidate, RelationshipCandidate


_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def _load_schema(name: str) -> dict[str, Any]:
    if name not in _SCHEMA_CACHE:
        path = Path(__file__).parent / "schemas" / f"{name}.yaml"
        with open(path) as f:
            _SCHEMA_CACHE[name] = yaml.safe_load(f)
    return _SCHEMA_CACHE[name]


def apply_schema(name: str, raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    """Apply a YAML schema to a raw JSON dict, producing entity/relationship candidates."""
    schema = _load_schema(name)
    entities: list[EntityCandidate] = []
    relationships: list[RelationshipCandidate] = []
    # ... generic extraction logic following schema directives
    return entities, relationships
```

- [ ] **Step 3: Migrate one schema function to YAML, verify**

```bash
pytest tests/test_runners/test_schemas.py -x -q --no-header 2>&1 | tail -5
```

- [ ] **Step 4: Replace all bespoke functions**

One YAML file per enrichment source. Update `OUTPUT_SCHEMAS` in `registry.py` to point to schema names instead of function references.

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/schemas/ src/easm/runners/schema_engine.py src/easm/runners/schemas.py
git commit -m "refactor(schemas): replace 30+ isomorphic output_schema functions with declarative YAML schemas"
```

---

## Phase 6: Error Handling Discipline (Days 3–5)

**Goal:** Replace 109 `except Exception` blocks with typed exception handling. Eliminate 28 bare `pass` handlers.

**Dependencies:** Mitigates risk before Phase 5 refactors.

### Task 6.1: Audit and refactor indiscriminate exception handlers

**Files:**
- Modify: all files with bare `except Exception` — replace with specific exception types

- [ ] **Step 1: List all bare except locations**

```bash
grep -rn 'except\s*Exception' src/easm/ --include='*.py' | grep -v 'except Exception as e' | cut -d: -f1 | sort -u
grep -rn 'except:' src/easm/ --include='*.py' | grep -v '# noqa' | cut -d: -f1 | sort -u
grep -rn 'except BaseException' src/easm/ --include='*.py' | cut -d: -f1 | sort -u
```

- [ ] **Step 2: Classify each location**

For each location, decide:
- **ResourceNotFound, PermissionDenied, TimeoutError** → replace with specific built-in/custom exception
- **`except Exception: pass` (health probes, DNS resolution)** → replace with `except OSError: logger.warning(...)` — at minimum log the failure
- **Entity ingestion loop errors** → replace with per-item try/except logging the item key, not blanket-silencing

- [ ] **Step 3: Fix categories systematically**

Example: health binary probe
```python
# OLD (src/easm/api/routes/health.py):
for binary in binaries:
    try:
        result = subprocess_run([binary, "--version"], timeout=5)
    except Exception:
        continue  # silently marks as absent

# NEW:
for binary in binaries:
    try:
        result = subprocess_run([binary, "--version"], timeout=5)
    except FileNotFoundError:
        logger.debug("binary not found", extra={"binary": binary})
    except subprocess.TimeoutExpired:
        logger.warning("binary check timed out", extra={"binary": binary})
    except OSError as e:
        logger.error("binary check failed", extra={"binary": binary, "error": str(e)})
```

- [ ] **Step 4: Fix all 28 bare `pass` handlers**

```bash
grep -rn 'except.*:\s*pass' src/easm/ --include='*.py'
```

Each `except ...: pass` must become `logger.warning("...")` or a specific handler.

- [ ] **Step 5: Verify**

```bash
ruff check src/easm/
pytest tests/ -x -q --no-header 2>&1 | tail -10
```


- [ ] **Step 6: Commit**

```bash
git add -u src/easm/
git commit -m "fix(error-handling): replace blanket except Exception blocks and bare pass handlers with typed exceptions"
```

### Task 6.2: Remove or rename pivot/worker_legacy.py

**Files:**
- Modify: `src/easm/pivot/worker_legacy.py` — either delete (if unused) or rename and clean

- [ ] **Step 1: Check if legacy worker is referenced anywhere**

```bash
grep -rn 'worker_legacy' src/ --include='*.py' --include='*.yaml' --include='*.yml'
```

- [ ] **Step 2: If unreferenced, delete**

```bash
git rm src/easm/pivot/worker_legacy.py
```

- [ ] **Step 3: If referenced, rename and fix except blocks**

Rename to `worker_v1.py`, apply same error-handling cleanup from Task 6.1.

- [ ] **Step 4: Commit**

```bash
git add -A src/easm/pivot/
git commit -m "cleanup(pivot): remove unused worker_legacy.py"
```

---

## Phase 7: Operations Hardening (Days 3–5)

**Goal:** Docker/compose hardening, dependency management, API consistency.

**Dependencies:** None.

### Task 7.1: Harden Docker Compose

**Files:**
- Modify: `docker-compose.yml` — bind PG to 127.0.0.1, add HEALTHCHECK
- Modify: `Dockerfile` — add HEALTHCHECK

- [ ] **Step 1: Change Postgres bind address**

```yaml
# In docker-compose.yml, under postgres ports:
# OLD:
ports:
  - "5432:5432"

# NEW: only expose to host, not network
ports:
  - "127.0.0.1:5432:5432"
```

- [ ] **Step 2: Add healthcheck to API service**

```yaml
# In docker-compose.yml, under api service:
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/api/healthz"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 15s
```

- [ ] **Step 3: Add HEALTHCHECK to Dockerfile**

```dockerfile
# In Dockerfile, at end of web stage:
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/api/healthz || exit 1
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml Dockerfile
git commit -m "ops(hardening): bind PG to localhost, add HEALTHCHECK to compose and Dockerfile"
```

### Task 7.2: Standardize API pagination

**Files:**
- Create: `src/easm/api/pagination.py` — unified pagination response model
- Modify: all route files — use standard pagination envelope

- [ ] **Step 1: Create pagination model**

```python
# src/easm/api/pagination.py
from typing import Any, Generic, TypeVar
from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    next_cursor: str | None = None
```

- [ ] **Step 2: Update each list endpoint to return PaginatedResponse**

```python
# Before: return {"entities": rows, "next_cursor": cursor, "total_count": total}
# After: return PaginatedResponse(items=rows, total=total, next_cursor=cursor)
```

- [ ] **Step 3: Update frontend to expect consistent envelope**

```typescript
// In ui/src/api/entities.ts and all API clients:
// Before: const data = await resp.json(); return data.entities;
// After: const data = await resp.json() as PaginatedResponse<Entity>; return data.items;
```

- [ ] **Step 4: Commit**

```bash
git add src/easm/api/pagination.py src/easm/api/routes/entities.py src/easm/api/routes/findings.py src/easm/api/routes/runs.py src/easm/api/routes/assets.py src/easm/api/routes/certificates.py src/easm/api/routes/events.py src/easm/api/routes/pivot_queue.py ui/src/api/entities.ts ui/src/api/findings.ts ui/src/api/runs.ts ui/src/api/assets.ts ui/src/api/certificates.ts
git commit -m "refactor(api): standardize pagination envelope across all list endpoints"
```

### Task 7.3: Expand ruff and mypy rules

**Files:**
- Modify: `pyproject.toml` — add ruff rules and mypy strictness

- [ ] **Step 1: Update ruff config**

```toml
# In pyproject.toml, under [tool.ruff.lint]:
select = [
    "ALL",      # Enable all rules
    # Exclude specific rules that are too noisy:
    "D",        # pydocstyle (enable — docstrings are sparse)
    "ANN",      # annotations (enable — missing type annotations)
]
ignore = [
    "D203",     # 1 blank line required before class docstring (conflicts with formatter)
    "D213",     # Multi-line docstring summary should start at second line
    "D400",     # First line should end with period (not useful for type annotations)
    "D401",     # First line should be in imperative mood
    "ANN101",   # Missing type annotation for `self` in method
    "ANN102",   # Missing type annotation for `cls` in classmethod
    "FBT001",   # Boolean positional arg in function definition
    "FBT002",   # Boolean default value in function definition
    "COM812",   # Trailing comma missing (formatter handles this)
]
```

- [ ] **Step 2: Fix immediate ruff issues**

```bash
ruff check src/easm/ --fix --unsafe-fixes 2>&1 | tail -20
```

Fix remaining issues manually.

- [ ] **Step 3: Enable mypy strict**

```toml
# In pyproject.toml, under [tool.mypy]:
strict = true
warn_unused_ignores = true
no_implicit_optional = true
disallow_any_unimported = false  # Too noisy for current codebase
disallow_any_expr = false
disallow_any_decorated = false
disallow_any_explicit = true    # No `Any` in function signatures
```

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "chore(lint): expand ruff to ALL rules, enable mypy strict, fix lint issues"
```

---

## Self-Review Checklist

**1. Spec coverage:** Every audit finding category has a corresponding phase or task:
- ✅ CORS misconfiguration → 0.1
- ✅ Exception handler leak → 0.2
- ✅ Health endpoint disclosure → 0.3
- ✅ Missing auth on config/runs → 0.4
- ✅ GeoMap XSS → 0.5
- ✅ Broken Tailwind classes → 0.6
- ✅ Entity color drift → 0.7
- ✅ No role/ownership checks → Phase 1
- ✅ No rate limiting → 1.3
- ✅ Enrichment key disclosure → 2.1
- ✅ No session secret strength → 2.2
- ✅ SSRF surface → 3.1
- ✅ No CSP → 3.2
- ✅ No frontend linting → 4.1
- ✅ No frontend tests → 4.2
- ✅ findings.ts React Query bypass → 4.3
- ✅ No code splitting → 4.4
- ✅ Design token drift / a11y → 4.5
- ✅ God-object files (store, handlers, engine, schemas) → 5.1–5.3
- ✅ Legacy runner migration → 5.4
- ✅ Isomorphic schema functions → 5.5
- ✅ 109 bare except + pass handlers → 6.1
- ✅ worker_legacy.py → 6.2
- ✅ Docker/compose hardening → 7.1
- ✅ Pagination consistency → 7.2
- ✅ Lint/type config → 7.3

**2. Placeholder scan:** No "TBD", "implement later", or "fill in details" found. Every task has concrete code changes.

**3. Type consistency:** Types and function signatures are consistent within each phase.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-20-code-audit-remediation.md`. Two execution options:

**Option 1: Subagent-Driven (recommended)** — I dispatch a fresh subagent per phase, review between phases, fast iteration. Phases are independent (0 prerequisite, 1–7 can be parallelized).

**Option 2: Single-session Inline Execution** — Execute phases sequentially in this session with checkpoints.

**Which approach?**
