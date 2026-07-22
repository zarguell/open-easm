# Open EASM — Comprehensive Code Audit

**Synthesized master report from five specialist audits**
**Date:** 2026-07-20
**Scope:** Full repository at `/Users/zach/localcode/open-easm` (current working tree)

---

## How This Audit Was Conducted

Five specialist agents worked in parallel, each with a distinct expert persona and scope:

| # | Specialist | Persona | Scope |
|---|---|---|---|
| 1 | 🎨 Frontend | Principal Frontend Engineer (15y React/TS/a11y) | `ui/src/` — React 19 SPA, TypeScript, Vite, Tailwind 4, D3, MapLibre |
| 2 | ⚙️ Backend | Staff Backend Engineer (FastAPI, asyncpg, async) | `src/easm/` — Python 3.14, FastAPI, asyncpg, APScheduler |
| 3 | ♻️ Code Quality | Distinguished Engineer (AI-slop, DRY, simplification) | Both sides — duplication, dead abstraction, complexity |
| 4 | 🗺️ Attack Surface | Director of Attack Surface Management | Trust boundaries, endpoint inventory, exposure map |
| 5 | 🔐 Cyber Auditor | Principal Security Auditor (offensive) | CVE-class vulnerabilities, exploitability |

Their full findings are in `BACKEND_AUDIT_REPORT.md`, `ATTACK_SURFACE_ASSESSMENT.md`, and the inline reports for Frontend, Code Quality, and Security. This document unifies them.

---

## Executive Summary

Open EASM is a **substantial, ambitious, well-typed codebase** with strong primitive engineering — modern stacks (Python 3.14, React 19, TS 6, Tailwind 4), parameterized SQL, `create_subprocess_exec` (no shell injection), HMAC-SHA256 API keys with `hmac.compare_digest`, bcrypt, HS256 JWTs with `iss`/`aud` validation, httpOnly+SameSite cookies, and 90+ backend test files.

It also has **systemic authorization, exposure, and maintainability gaps** that disqualify the default configuration from any networked deployment:

- **Authentication exists. Authorization largely does not.** The auth middleware sets `request.state.user`, but no route checks it for role or ownership before mutating config, triggering subprocess runners, or reading another user's data. Grep for `Depends(get_current_user)` across all 20 route files: **zero matches**.
- **Insecure defaults ship by design.** `auth.mode="none"` + `host="0.0.0.0"` + PostgreSQL on `0.0.0.0:5432` + default DB password `easm` + ephemeral API-key pepper.
- **Information disclosure is broad.** Unauthenticated `/api/healthz` enumerates installed security tools, runtime policy, and pivot queue state. Global exception handler returns `detail=str(exc)` to clients. `.env` is committed with **two live API keys** (`PDCP_API_KEY`, `CERTSPOTTER_API_KEY`).
- **CORS spec violation.** `allow_origins=["*"]` combined with `allow_credentials=True`.
- **One stored XSS vector** in the frontend (`GeoMap.tsx:98` — MapLibre `.setHTML()` with unsanitized entity values).
- **Six god-object files** consume 55% of backend LOC (`store.py` 1577, `pivot/handlers.py` 1144, `runners/engine.py` 701, `runners/schemas.py` 571, `runners/registry.py` 415).
- **109 `except Exception` blocks + 28 bare `pass`** handlers blanket-silence failures across 33 files.
- **~1,485 LOC of duplicative boilerplate** (10 legacy runner classes 70% identical, 30+ isomorphic schema functions, `_STATUS_MAP` copy-pasted 3×, 8 frontend hooks with identical param builders).
- **Zero frontend tests.** Zero ESLint. Zero code splitting. Broken design-token references (`bg-surface` × 5, `text-muted` × 8) cause silent visual breakage.

The primitives are right; the **system-level discipline** (authorization, defaults, information boundaries, modularization, error handling, frontend infrastructure) is what needs investment.

---

## Cross-Cutting Themes (Multiple Agents Independently Flagged)

These are the highest-confidence findings — they were surfaced independently by 2+ specialists looking from different angles.

### Theme 1: Authentication ≠ Authorization
**Flagged by:** Cyber Auditor (High), Attack Surface (High), Backend (High)

The auth middleware authenticates. The routes do not authorize.

- `PUT /api/config` — writes new YAML to `config.yaml` on disk and replaces in-memory config. **No admin role check.**
- `POST /api/config/reload` — hot-reloads config from disk. **No admin role check.**
- `POST /api/runs/{target_id}/{runner}` — triggers subprocess runner (nuclei, nmap, etc.). **No role check, no per-user rate limit.**
- `DELETE /api/auth/api-keys/{id}` — only the API key owner can delete (this one is checked).
- All read endpoints (`/api/entities`, `/api/findings`, `/api/runs`, `/api/graph`, `/api/assets`, `/api/certificates`) — **no `org_id` scoping**. `Store.list_findings()` has no `org_id` parameter at all. The schema has `org_id` and `role` columns; the queries don't use them.

**Why this matters:** A `viewer`-role user (or in `none` mode, any network caller) can rewrite the entire system configuration, trigger active scanning against arbitrary targets, and read every entity in the database. The forward-compatible RBAC/tenancy story is incomplete.

### Theme 2: Insecure Default Posture
**Flagged by:** Attack Surface (Critical), Cyber Auditor (High)

The README quick-start produces a system with no authentication bound to all interfaces. Default values:

| Setting | Default | Risk |
|---|---|---|
| `auth.mode` | `"none"` | Zero authentication |
| `uvicorn` host | `0.0.0.0:8000` | Reachable from any interface |
| `docker-compose.yml` postgres ports | `5432:5432` (binds `0.0.0.0`) | DB reachable from host network |
| `POSTGRES_PASSWORD` | `easm` | Default password |
| `EASM_API_KEY_PEPPER` | unset → ephemeral per-process | Multi-worker deployment breaks API key validation |
| `EASM_SESSION_SECRET` | unset | `local` mode startup fails — good — but `none` mode skips it |

### Theme 3: Information Disclosure
**Flagged by:** Cyber Auditor (High), Attack Surface (High)

| Surface | What leaks | Where |
|---|---|---|
| `GET /api/healthz` (unauthenticated) | Installed binaries + versions, runtime mode (live/simulate), fixtures path, `allow_subprocess`/`allow_active_scanning`/`allow_external_network` flags, pivot queue state | `routes/health.py:53-103` |
| Global exception handler | `{"error": "internal", "detail": str(exc)}` — leaks Pydantic/asyncpg/internal library error text | `api/app.py:85-88` |
| `.env` committed to repo | Live `PDCP_API_KEY` + `CERTSPOTTER_API_KEY` | `.env:6-7` |
| `GET /api/config` | Returns full config including enrichment API keys (Shodan, HIBP, GitHub, etc.) to any authenticated user | flagged by Backend specialist |

### Theme 4: Indiscriminate Error Handling
**Flagged by:** Code Quality (Critical), Backend (High)

- **109 `except Exception` blocks across 33 files.** Failure modes are flattened into "log and continue." Examples: health binary probes, DNS resolution, entity ingestion, all 10 legacy runners' `run_once()` loops.
- **28 bare `pass` exception handlers.** The health-check binary probe and DNS resolver silently fall back to "absent" / "no answer" without distinguishing missing-binary from permission-error from crash.
- Result: the system **fails open silently.** A misconfigured runner doesn't error — it produces zero results, which look identical to "no findings."

### Theme 5: God Objects and AI-Slop Duplication
**Flagged by:** Code Quality (Critical), Backend (Critical), Frontend (Medium)

Backend:
- `store.py` — 1577 LOC, handles runs + entities + findings + assets + certificates + auth + triage + config + graph + pivot queue. **6.3× the 250-LOC ceiling.**
- `pivot/handlers.py` — 1144 LOC, 22 handler functions + cert crypto + DNS + GeoIP + takeover detection in one file.
- `runners/engine.py` — 701 LOC mixing lifecycle, subprocess, HTTP, ingestion, parent resolution.
- 10 legacy class-based runners (BreachMonitor, GistMonitor, PasteMonitor, GithubScan, StackOverflowMonitor, CloudBucket, SearchEngine, PortScan, Screenshot, CertStream) with **70% structural overlap**.
- 30+ isomorphic `output_schema()` functions in `schemas.py` (571 LOC of structural repetition).
- `_STATUS_MAP` dict copy-pasted in `routes/health.py`, `routes/workers.py`, `routes/pivot_queue.py`.

Frontend:
- 3 divergent entity color maps (`DESIGN_TOKENS.ts`, `lib/entity-colors.ts`, `TopBar.tsx`) — the same entity type renders different colors in different parts of the UI.
- 8 frontend API hooks each contain the identical 15-line searchParams builder.
- `findings.ts` uses manual `useState`/`useEffect` while 14 sibling modules use React Query. Inconsistent and loses caching.
- Duplicated `ky` client in `findings.ts` (no 401 redirect on that page).

### Theme 6: Trust Boundary Gaps for Untrusted Data
**Flagged by:** Attack Surface (High), Cyber Auditor (Medium)

The product ingests external untrusted data — CT log feed, crt.sh HTTP responses, RDAP/WHOIS, Pastebin scrapes, GitHub code search, search-engine HTML — and then:
1. Stores it in the DB as entity values.
2. Passes those values as **argv elements** to subprocess tools (nuclei, wappalyzer, nmap) — not shell injection (shell=False, list args), but **argument-injection risk for tools with positional parsing**.
3. Renders those values in the frontend (mostly safe via React JSX auto-escape), **except** `GeoMap.tsx:98` which uses MapLibre `.setHTML()` with unsanitized entity values → **stored XSS**.
4. Uses those values in URLs for outbound HTTP enrichment (Shodan, AbuseIPDB, Censys, urlscan, RDAP, crt.sh) — endpoints are hardcoded (low SSRF risk), but **no private-IP filtering** in any HTTP client.
5. TLS verification disabled (`verify=False`) in `_http_probe` for takeover detection — DNS hijack of a discovered hostname can serve malicious HTML that the system parses and stores.

---

## Consolidated Top 15 Findings (Severity × Confidence × Exploitability)

| # | Sev | Finding | Source | Location |
|---|---|---|---|---|
| 1 | **Critical** | Live API keys committed in `.env` (`PDCP_API_KEY`, `CERTSPOTTER_API_KEY`) | Cyber Auditor | `.env:6-7` |
| 2 | **Critical** | `auth.mode="none"` is the default — any deployed instance is wide open | Attack Surface, Cyber Auditor | `auth/config.py:36` |
| 3 | **Critical** | No role check on `PUT /api/config` — any authenticated user can rewrite server config on disk | Cyber Auditor, Attack Surface, Backend | `routes/config.py:26-53` |
| 4 | **Critical** | CORS spec violation: `allow_origins=["*"]` + `allow_credentials=True` | Cyber Auditor | `api/app.py:73-79` |
| 5 | **High** | Unauthenticated `/api/healthz` leaks binary inventory + runtime policy + queue state | Cyber Auditor, Attack Surface | `routes/health.py:53-103` |
| 6 | **High** | Global exception handler returns `str(exc)` to clients — information disclosure | Cyber Auditor | `api/app.py:85-88` |
| 7 | **High** | No `org_id` scoping on read endpoints — `list_findings()` has no org filter at all | Backend, Attack Surface | `store.py` |
| 8 | **High** | Stored XSS in `GeoMap.tsx:98` — MapLibre `.setHTML()` with unsanitized entity values | Frontend | `ui/src/components/GeoMap.tsx:98-103` |
| 9 | **High** | Ephemeral API-key pepper when `EASM_API_KEY_PEPPER` unset → multi-worker key validation breaks | Attack Surface | `auth/api_keys.py` |
| 10 | **High** | `verify=False` in `_http_probe` for takeover detection → TLS-MITM/DNS-hijack content injection | Cyber Auditor | `pivot/handlers.py:620` |
| 11 | **High** | God-object files: `store.py` (1577 LOC), `pivot/handlers.py` (1144), `runners/engine.py` (701) | Backend, Code Quality | `src/easm/` |
| 12 | **High** | 109 `except Exception` + 28 bare `pass` — silent failure mode across 33 files | Backend, Code Quality | across `src/easm/` |
| 13 | **High** | PostgreSQL bound to `0.0.0.0:5432` with default password `easm` | Cyber Auditor, Attack Surface | `docker-compose.yml` |
| 14 | **High** | Zero frontend tests — no test runner, no test files, no test deps in package.json | Frontend | `ui/` |
| 15 | **High** | 3 divergent entity color maps + `bg-surface`/`text-muted` undefined Tailwind classes (13 broken elements) | Frontend | `DESIGN_TOKENS.ts`, `lib/entity-colors.ts`, `TopBar.tsx` |

---

## Top 7 Quick Wins (≤2 hours each, high impact)

| # | Fix | Effort | Files Touched |
|---|---|---|---|
| 1 | **Rotate committed API keys** + `git rm --cached .env` + add to `.gitignore` | 10 min | `.env`, `.gitignore` |
| 2 | **Add `_require_admin(request)` guard** to `PUT /api/config`, `POST /api/config/reload`, `POST /api/runs/{target_id}/{runner}`, `DELETE /api/users/{id}` | 30 min | `routes/config.py`, `routes/runs.py`, `routes/auth.py` |
| 3 | **Strip `binaries` + `runtime` from `/api/healthz`** response (keep only `status`, `database`, `scheduler`) | 15 min | `routes/health.py:53-103` |
| 4 | **Replace `detail=str(exc)` with static `"internal server error"`** in global exception handler | 5 min | `api/app.py:85-88` |
| 5 | **Fix CORS**: drop `allow_credentials=True` OR replace `allow_origins=["*"]` with explicit frontend origin | 5 min | `api/app.py:73-79` |
| 6 | **Fix GeoMap XSS**: replace `.setHTML()` with `.setDOMContent()` (or `.setText()`) | 10 min | `ui/src/components/GeoMap.tsx:98-103` |
| 7 | **Fix broken Tailwind classes**: `bg-surface` → `bg-canvas-elevated` (5×), `text-muted` → `text-mute` (8×) | 15 min | 6 frontend files |

**Total time to dramatically improve posture:** ~90 minutes of focused work.

---

## Larger Investments (Weeks 1–4)

### Security hardening (Week 1)
- Implement per-tenant query scoping in `Store` (every `list_*` method takes `org_id`, every write stamps it).
- Add admin/viewer role enforcement via a `Depends(require_role("admin"))` dependency on destructive endpoints.
- Replace ephemeral pepper fallback with **fail-fast** on missing `EASM_API_KEY_PEPPER` in production.
- Add rate limiting to `/api/auth/login`, `/api/auth/register`, and runner trigger endpoints.
- Remove `verify=False` from `_http_probe`; treat TLS errors as a takeover signal.
- Bind Postgres to `127.0.0.1:5432` in `docker-compose.yml`.
- Add `Content-Security-Policy` header (no `unsafe-inline`).

### Frontend infrastructure (Week 1)
- Add `vitest` + `@testing-library/react` + `msw`. Write smoke tests for every route, then a regression test for the GeoMap XSS.
- Add ESLint with `typescript-eslint`, `eslint-plugin-react-hooks`, `eslint-plugin-jsx-a11y`, `eslint-plugin-tailwindcss`.
- Migrate `findings.ts` to React Query (`useQuery`, `useMutation`).
- Wrap route components in `React.lazy()` + `<Suspense>`.
- Add `AbortController`/`signal` to React Query `queryFn`s.
- Consolidate entity color maps → single source of truth.

### Backend modularization (Weeks 2–3)
- Split `store.py` into `RunStore`, `EntityStore`, `FindingStore`, `AssetStore`, `CertificateStore`, `TriageStore`, `AuthStore`, `ConfigStore`. Each ≤250 LOC.
- Split `pivot/handlers.py` by domain: `handlers/dns.py`, `handlers/cert.py`, `handlers/enrichment.py`, `handlers/takeover.py`.
- Split `runners/engine.py` into `lifecycle.py`, `subprocess.py`, `http.py`, `ingestion.py`.
- Migrate the 10 legacy class-based runners to the declarative `RunnerDef` registry (7 of 18 already done — finish the migration).
- Replace 30+ bespoke `output_schema` functions with declarative YAML schemas + one generic engine.
- Extract shared `_STATUS_MAP`, `cleanParams`, query-builder utilities into shared modules.
- Standardize pagination envelope: `{"items": [...], "total": N, "next_cursor": "..." | null}`.

### Error handling discipline (Week 2)
- Audit all 109 `except Exception` blocks. Replace with specific exception types or remove.
- Replace all 28 bare `pass` handlers with explicit "log + decide" logic.
- Add structured logging with correlation IDs across runner → pivot → finding flow.

### Documentation (Week 3)
- Remove `discord_monitor` from README (not in `VALID_RUNNER_NAMES`).
- Add ADRs for load-bearing decisions: procrastinate, cursor pagination on entities, YAML correlation rules, `auth.mode="none"` default.
- Write CONTRIBUTING.md with the test/lint/typecheck gates.

---

## Aggregate Scorecard

Combining the five specialists' scores (weighted equally):

| Dimension | Score | Strongest Signal |
|---|---|---|
| Architecture (backend) | **4/10** | God objects; migration from class-based runners half-finished |
| Architecture (frontend) | **7/10** | Clean feature-based component layout, but no code splitting |
| Async Hygiene | **8/10** | httpx + asyncpg throughout, minimal blocking calls |
| DB Layer | **6/10** | Parameterized SQL everywhere; offset pagination; no tenant scoping |
| Runner Safety | **7/10** | `create_subprocess_exec`, `shell=False`, timeouts — solid; PATH-resolved binaries |
| Error Handling | **5/10** | 109 indiscriminate except blocks; silent failure mode |
| Type Safety (backend) | **3/10** | 340+ `Any` matches; `RunnerConfig` is a 27-field grab-bag |
| Type Safety (frontend) | **9/10** | `strict: true`, `noUncheckedIndexedAccess`, 2 `any` only |
| React Hygiene | **6/10** | `useFindings` bypasses React Query; `setQueryDefaults` in render |
| Testing (backend) | **7/10** | 90+ behavior-driven test files |
| Testing (frontend) | **0/10** | Zero test infrastructure |
| Authentication | **7/10** | JWT/bcrypt/HMAC implementations correct |
| Authorization | **3/10** | Middleware authenticates; routes don't check roles or ownership |
| Input Validation | **8/10** | Pydantic + parameterized SQL |
| Secret Management | **4/10** | Live keys committed; ephemeral pepper; no strength check on session secret |
| Subprocess Containment | **9/10** | Best-in-class — `shell=False`, list args, timeouts |
| SSRF Controls | **6/10** | Hardcoded endpoints (low risk); no private-IP filtering (defense-in-depth gap) |
| Crypto | **8/10** | HMAC-SHA256 + `hmac.compare_digest`, bcrypt, HS256 JWT |
| Tenant Isolation | **2/10** | Schema supports it; queries don't |
| Dependency Hygiene | **7/10** | Modern versions, no upper bounds, passlib in maintenance mode |
| Container Hardness | **7/10** | Non-root user in production stages; PG exposed on 0.0.0.0 |
| Accessibility (frontend) | **3/10** | Only 5 aria-* attributes total; mute text fails WCAG AA |
| Performance (frontend) | **5/10** | No code splitting, no virtualization, 5000-row GeoMap fetch |
| Consistency (frontend) | **5/10** | 3 divergent color maps; undefined Tailwind classes |
| AI-Slop Density | **5/10** | Sloppy in runner classes/config models; clean in correlation loader |
| DRY-ness | **4/10** | ~1,485 LOC of duplicate boilerplate identified |
| Naming/API Consistency | **5/10** | 4 different pagination envelope shapes |

**Overall security posture:** 5.3/10 (with the disclaimer that primitives are strong but system-level discipline gaps compound).
**Overall maintainability posture:** 5.5/10 (ambitious scope, but modularization debt is large).

---

## What Was Done Well (Don't Lose This)

Worth preserving during refactors:

1. **Subprocess containment** — `shell=False`, argument lists, timeouts, `network_guard` for active scans.
2. **SQL parameterization** — every query uses `$1, $2` placeholders; no string interpolation.
3. **HMAC-SHA256 API keys** with `hmac.compare_digest` and `secrets.token_urlsafe(32)` for generation.
4. **JWT validation** — HS256 only, `iss`/`aud`/`exp` verified.
5. **Cookies** — httpOnly + SameSite=Strict + configurable Secure.
6. **YAML safe loading** — `yaml.safe_load` throughout; no `yaml.load`.
7. **No `pickle`** anywhere. No `eval`/`exec`.
8. **Backend test suite** — 90+ behavior-driven files.
9. **Frontend TypeScript discipline** — `strict: true`, `noUncheckedIndexedAccess`, near-zero `any`.
10. **Declarative pivot handler registry** — dict dispatch, not if/elif chains.
11. **Migration under way** — 7 of 18 runners already ported from classes to declarative `RunnerDef`.
12. **Asyncpg + httpx** instead of blocking `requests`/`psycopg2`.
13. **`.dockerignore` present**, multi-stage build with non-root user in production stages.
14. **No secrets in frontend** — httpOnly cookies, no `localStorage`, no hardcoded tokens.

---

## How to Read the Specialist Reports

- **`BACKEND_AUDIT_REPORT.md`** — Backend specialist's full ~500-line report with 40+ findings.
- **`ATTACK_SURFACE_ASSESSMENT.md`** — Attack Surface specialist's 645-line report with full 71-route inventory + trust boundary diagram + 22 findings.
- **Frontend, Code Quality, and Cyber Auditor reports** — delivered inline in the orchestrator session; preserved in the orchestrator's turn history.

---

## Final Verdict

**Ship-blocking for networked deployment:**
1. Committed API keys (Critical — rotate today).
2. Default `auth.mode="none"` + `0.0.0.0` binding (Critical — never deploy to a network without changing this).
3. No authorization on config/runs (Critical for any multi-user deployment).
4. CORS spec violation (Critical — fix is 5 minutes).

**Ship-ready for single-user private-network deployment** (after the 7 Quick Wins in 90 minutes), with the caveat that the frontend is currently regression-untested and the backend god-objects are accumulating merge-conflict risk.

**For multi-tenant or SaaS deployment:** Substantial investment required in authorization, tenant isolation, and modularization before this codebase should be exposed to multiple organizations.
