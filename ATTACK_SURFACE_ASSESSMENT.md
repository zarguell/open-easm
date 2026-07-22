# Open EASM — Attack Surface Map & Exposure Assessment

**Assessment Date:** 2026-07-20  
**Scope:** The open-easm product itself (NOT the targets it scans)  
**Version:** 0.2.0  
**File Coverage:** 19 route files, 7 auth files, 15 runner files, all config/docker files read

---

## Executive Summary

1. **Auth mode `"none"` is the default** — and dangerous endpoints (`PUT /api/config`, `POST /api/runs/{id}/{runner}`) have **no route-level auth checks**, meaning a default deployment is fully open to configuration tampering and arbitrary subprocess execution via the API.

2. **Externally-derived hostnames flow directly into subprocess argv** for `nuclei`, `webanalyze`, and `nmap` with **zero sanitization** — data from crt.sh, certstream, and reverse DNS passes through the database into command-line arguments for external tools.

3. **Only one of three active-scan runners uses the network guard** — `nuclei` and `webanalyze` scan discovered hostnames without checking if they resolve to private IPs, creating an SSRF vector.

4. **Multi-tenant isolation is incomplete** — `list_findings()` and several entity queries have no `org_id` filtering, meaning any authenticated user can see data from all tenants.

5. **CORS is wide open** (`allow_origins=["*"]` with `allow_credentials=True`), API key pepper is ephemeral by default, no brute-force protection exists, and SSO lacks PKCE — these are deployment-posture risks that compound in production.

---

## Methodology

- **Static code review** of 100% of route files (`src/easm/api/routes/*.py`), auth modules (`src/easm/auth/*.py`), runner files (`src/easm/runners/*.py`), and infrastructure files (`app.py`, `main.py`, `store.py`, `config.py`, `Dockerfile`, `docker-compose.yml`).
- **Every route** enumerated via `@router.` decorator grep.
- **Every subprocess call** traced from argv construction through data sources.
- **Every HTTP outbound call** mapped for SSRF potential.
- **Trust boundaries** traced through middleware → route handler → data layer.
- **No active testing** — 100% code-level analysis grounded in exact file:line references.

---

## Exposed HTTP Endpoint Inventory

**Middleware Chain (app.py:73-81):**
```
CORS (* origins, all methods, all headers) → auth_middleware → Route
```

**Exempt Routes (no auth required — middleware.py:13-22):**
| Method | Path |
|--------|------|
| GET | `/api/healthz` |
| POST | `/api/auth/login` |
| POST | `/api/auth/register` |
| POST | `/api/auth/logout` |
| GET | `/api/auth/sso/{provider}` |
| GET | `/api/auth/sso/{provider}/callback` |
| All | `/ui/*` |
| GET | `/` |

### Complete Route Table (71 routes across 19 files)

Grouped by file for readability. `Risk` is relative to auth posture.

#### health.py — Health Check
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 1 | GET | `/api/healthz` | Exempt | None | **DB read**, **subprocess** (checks 6 binaries with `--version`), leaks binary paths | **INFO** |

#### auth.py — Authentication (13 routes)
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 2 | POST | `/auth/register` | Exempt (bootstrap), then Admin | `username` (3-64), `password` (8-128), `email?`, `display_name?` | DB write (bcrypt) | **MED** |
| 3 | POST | `/auth/login` | Exempt | `username`, `password` | DB read, sets httpOnly cookie (JWT) | **MED** |
| 4 | POST | `/auth/logout` | Exempt | None | Clears session cookie | **LOW** |
| 5 | GET | `/auth/me` | Yes | None | DB read | **LOW** |
| 6 | POST | `/auth/api-keys` | Yes | `name` (1-64), `expires_in_days?` (1-3650) | DB write (HMAC-SHA256 + pepper) | **MED** |
| 7 | GET | `/auth/api-keys` | Yes | None | DB read | **LOW** |
| 8 | DELETE | `/auth/api-keys/{id}` | Yes | `api_key_id` | DB write | **LOW** |
| 9 | GET | `/auth/users` | Yes (Admin) | None | DB read (strips `password_hash`) | **LOW** |
| 10 | PUT | `/auth/users/{id}` | Yes | `email?`, `display_name?`, `current_password?`, `new_password?` | DB write (re-hash) | **MED** |
| 11 | DELETE | `/auth/users/{id}` | Yes (Admin) | `user_id` | DB write | **MED** |
| 12 | GET | `/auth/sso/{provider}` | Exempt | `provider` (google/github/microsoft) | SSO redirect | **LOW** |
| 13 | GET | `/auth/sso/{provider}/callback` | Exempt | `provider`, query params from IdP | DB write (may create user as admin), sets session cookie | **HIGH** |

#### targets.py — Target Config
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 14 | GET | `/targets` | Yes | None | DB read (last_run per runner) | **LOW** |
| 15 | GET | `/targets/{id}` | Yes | `target_id` | Reads config from memory | **LOW** |

#### runs.py — Run Management
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 16 | GET | `/runs/count` | Yes | `target_id?, source?, status?, trigger_type?, start?, end?` | DB read | **LOW** |
| 17 | GET | `/runs` | Yes | Same + `limit(1-500)`, `offset` | DB read | **LOW** |
| 18 | GET | `/runs/{id}` | Yes | `run_id` (UUID) | DB read | **LOW** |
| 19 | POST | `/runs/{id}/{runner}` | **NO route-level check** | `target_id`, `runner` | **Defers async task** (spawns runner subprocess), DB write | **CRITICAL** |

#### events.py — Raw Events
| # | Method | Path | Auth | Inputs | Risk |
|---|--------|------|------|--------|------|
| 20-22 | GET | `/events/*` | Yes | `target_id?, source?, start?, end?, limit, cursor` | **LOW** |

#### entities.py — Entity Inventory
| # | Method | Path | Auth | Inputs | Risk |
|---|--------|------|------|--------|------|
| 23-28 | GET | `/entities/*` | Yes | `target_id?, entity_type?, q?, limit(1-5000), cursor` | **LOW** |

#### graph.py — Graph Visualization
| # | Method | Path | Auth | Inputs | Risk |
|---|--------|------|------|--------|------|
| 29 | GET | `/graph/{id}` | Yes | `target_id`, `depth` (1-10) | **LOW** |

#### config.py — Configuration Management
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 30 | GET | `/config` | Yes | None | Reads in-memory config (includes enrichment keys?) | **HIGH** |
| 31 | PUT | `/config` | **NO route-level check** | Body: `{targets, saas_providers, alerts}` | **File write** (overwrites config.yaml), DB write, in-memory reload | **CRITICAL** |
| 32 | GET | `/config/history` | Yes | None | DB read | **LOW** |
| 33 | POST | `/config/reload` | **NO route-level check** | None | File read, in-memory reload, DB write, scheduler mutation | **CRITICAL** |

#### pivot_queue.py — Pivot Job Management
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 34 | POST | `/pivot-queue/trigger` | Yes | `target_id`, `entity_type`, `entity_value`, `pivot_type`, `org_id="default"`, `depth=1` | Defers async task, DB write | **MED** |
| 35 | POST | `/pivot-queue/{id}/retry` | Yes | `job_id` (bigint) | Re-submits pivot task | **MED** |
| 36-37 | GET | `/pivot-queue/*` | Yes | `status?, target_id?, entity_type?, pivot_type?` | DB read | **LOW** |

#### findings.py — Correlation Findings
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 38-43 | GET | `/findings/*` | Yes | `target_id?, risk?, status?, rule_id?, q?, confidence_min?` | DB read, SSE streaming | **LOW** |
| 44 | PATCH | `/findings/{id}` | Yes | `finding_id`, `status` (valid enum) | DB write | **LOW** |

#### certificates.py, assets.py, alerts.py, scoring.py, reports.py
| # | Method | Path | Auth | Risk |
|---|--------|------|------|------|
| 45-66 | GET | `/certificates/*`, `/assets/*`, `/alerts/*`, `/scoring/*`, `/reports/*` | Yes | **LOW** |
| 52 | PATCH | `/alerts/feed/{id}` | Yes | **LOW** |

#### notifications.py — Notification Channels
| # | Method | Path | Auth | Inputs | Side Effects | Risk |
|---|--------|------|------|--------|-------------|------|
| 53 | POST | `/notifications/test` | Yes | `channel_name` | **Sends arbitrary notification** to configured channel | **MED** |
| 54 | GET | `/notifications/channels` | Yes | None | Reads dispatcher config | **LOW** |

#### legal.py, verification.py, triage.py, workers.py
| # | Method | Path | Auth | Side Effects | Risk |
|---|--------|------|------|-------------|------|
| 55-57 | GET/POST | `/legal/*` | Yes | DB write (acceptance) | **LOW** |
| 58-62 | POST/GET/DELETE | `/domains/*/verification*` | Yes | DB write, DNS check | **MED** |
| 67-70 | GET/PATCH/POST | `/api/triage/*` | Yes (`org_id` as query param) | DB read/write | **LOW** |
| 71 | GET | `/api/workers/queue` | Yes | DB read | **LOW** |

---

## Trust Boundaries Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERNET                                  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ :8000
        ┌───────────────┴────────────────┐
        │   Docker: web container        │
        │   uvicorn 0.0.0.0:8000        │
        └───────────────┬────────────────┘
                        │
        ┌───────────────┴────────────────┐
        │   CORS: * origins (app.py:73)  │  ← ⚠️ No origin restriction
        └───────────────┬────────────────┘
                        │
        ┌───────────────┴────────────────┐
        │  auth_middleware (app.py:81)    │  ← TRUST CHECKPOINT 1
        │  ┌───────────────────────┐     │
        │  │ Exempt check?         │     │  ← SSO callback exempt
        │  │ API key header?       │     │  ← HMAC-SHA256 + DB lookup
        │  │ mode=none? → PASS     │     │  ← ⚠️ DEFAULT, no auth
        │  │ mode=rev_proxy? → IP  │     │  ← CIDR match on direct IP
        │  │ mode=local/sso? → JWT │     │  ← httpOnly cookie, HS256
        │  └───────────────────────┘     │
        └───────────────┬────────────────┘
                        │
        ┌───────────────┴────────────────┐
        │     Route Handler               │  ← ⚠️ No defense-in-depth checks
        │  ┌───────────────────────┐     │     on config, runs, verification
        │  │ PUT /api/config       │     │
        │  │ POST /runs/{id}/{r}   │     │
        │  │ GET /api/config       │     │
        │  └───────────────────────┘     │
        └───────┬───────────┬───────────┘
                │           │
    ┌───────────┴──┐  ┌─────┴──────────────┐
    │  PostgreSQL  │  │  File System        │
    │  (asyncpg)   │  │  config.yaml write  │  ← ⚠️ Direct overwrite
    │              │  │  screenshots/       │  ← Playwright screenshots
    └──────────────┘  └────────────────────┘
                │
    ┌───────────┴──────────────────────────┐
    │      External Reconnaissance          │  ← ⚠️ Externally-derived data
    │  ┌─────────────────────────────────┐ │
    │  │ Subprocess: nmap, nuclei,       │ │  ← Hostname→argv, no sanitize
    │  │   subfinder, asnmap, dnstwist,  │ │  ← PATH-resolved binaries
    │  │   webanalyze, gitleaks          │ │
    │  ├─────────────────────────────────┤ │
    │  │ HTTP Outbound: crt.sh, urlscan, │ │  ← ⚠️ No private-IP filtering
    │  │   CommonCrawl, DuckDuckGo,      │ │     on outbound HTTP
    │  │   RDAP, SecurityTrails, etc.    │ │
    │  └─────────────────────────────────┘ │
    └──────────────────────────────────────┘
```

**Key:** `⚠️` = security gap, `←` = note

---

## Attack Surface Findings (Ranked by Severity)

---

### Auth Bypass / Weak Boundary

#### Finding #1 **[Severity: CRITICAL]** Auth mode "none" is the default; dangerous endpoints have no route-level gating

- **Trust boundary crossed:** Unauthenticated external user → config/run mutation
- **Location:** `src/easm/auth/config.py:36`, `src/easm/api/routes/config.py:26,72`, `src/easm/api/routes/runs.py:74`
- **Evidence:**
  ```python
  # config.py:36 — DEFAULT IS NONE
  class AuthConfig(BaseModel):
      mode: Literal["none", "reverse_proxy", "local", "sso"] = "none"
  
  # config.py:26-46 — NO request.state.user CHECK
  @router.put("/config")
  async def update_config(body: dict, config=Depends(get_config), store=Depends(get_store)):
      # ... validates, writes config.yaml to disk, reloads in-memory config
  
  # runs.py:74-131 — NO request.state.user CHECK
  @router.post("/{target_id}/{runner}")
  async def trigger_run(target_id: str, runner: str):
      # ... defers runner execution via procrastinate
  ```
- **Attacker path:** 
  1. Deploy default open-easm (mode="none") 
  2. `PUT /api/config` with malicious targets/runners 
  3. Or `POST /api/runs/evil-target/nuclei` to trigger scanning
- **Blast radius:** Complete server compromise — modify config, trigger arbitrary runners, overwrite config.yaml
- **Recommendation:** 
  1. Add `request.state.user` check at route level for all mutating endpoints (defense-in-depth)
  2. Change default mode to `"local"` with bootstrap-first-user or emit prominent startup warning
  3. Add `Depends(get_current_user)` dependency on all dangerous routes

#### Finding #2 **[Severity: HIGH]** GET /api/config exposes enrichment API keys

- **Location:** `src/easm/api/routes/config.py:22`, `src/easm/config.py` (EnrichmentKeys model)
- **Evidence:**
  ```python
  # config.py:21-22 — Returns entire config including secrets
  @router.get("/config", response_model=dict)
  async def get_full_config(config: Config = Depends(get_config)):
      return config.model_dump(mode="json")
  ```
- **Attacker path:** Any authenticated user calls `GET /api/config` and receives `enrichment.shodan`, `enrichment.abuseipdb`, etc. API keys.
- **Blast radius:** Exposure of all third-party service API keys to every authenticated user.
- **Recommendation:** Redact sensitive keys (`shodan`, `abuseipdb`, `greynoise`, `censys_secret`, `securitytrails`) from config dump, or add admin-only filter.

---

### Header / Cookie / CSRF

#### Finding #3 **[Severity: HIGH]** CORS allows all origins with credentials

- **Location:** `src/easm/api/app.py:73-79`
- **Evidence:**
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],         # ❌ Wildcard
      allow_credentials=True,      # ❌ Credentials + wildcard = spec violation
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```
- **Attacker path:** Any website can make credentialed cross-origin requests (browsers technically reject `*`+credentials, but some renderers don't; still indicates overly permissive posture). If deployed behind a reverse proxy that sets Origin, same-origin policy is bypassed entirely.
- **Blast radius:** Cross-origin data access from any malicious site a user visits.
- **Recommendation:** Restrict `allow_origins` to the actual deployment URL. Never combine `*` with `allow_credentials=True`.

#### Finding #4 **[Severity: MEDIUM]** Session cookie missing Domain restriction

- **Location:** `src/easm/api/routes/auth.py:41-49`
- **Evidence:**
  ```python
  def _set_session_cookie(response, token, max_age, cookie_name, secure=True):
      response.set_cookie(
          key=cookie_name,
          value=token,
          max_age=max_age,
          httponly=True,          # ✅
          secure=secure,           # ✅ (configurable, default True)
          samesite="strict",       # ✅
          path="/",               # ⚠️ / only, no Domain
      )
  ```
- **Attacker path:** No explicit Domain restriction — cookie sent to all subdomains of the deployment host if DNS allows.
- **Blast radius:** Cookie leakage to sibling subdomains.
- **Recommendation:** Set explicit `domain` parameter in production if subdomain scope is known.

---

### SSO Flow

#### Finding #5 **[Severity: HIGH]** SSO auto-provisions all users as admin; no PKCE

- **Location:** `src/easm/api/routes/auth.py:388-396`, `src/easm/auth/sso.py:1-38`
- **Evidence:**
  ```python
  # auth.py:388-396 — ALL SSO users get admin
  user = await store.create_user(
      org_id="default",
      username=username,
      email=sso_user.email,
      display_name=sso_user.display_name,
      role="admin",               # ❌ Hardcoded admin
      sso_provider=provider,
      sso_provider_id=provider_id,
  )
  
  # sso.py — No PKCE in fastapi-sso
  return GoogleSSO(client_id=..., client_secret=..., redirect_uri=...)
  ```
- **Attacker path:**
  1. Attacker obtains a valid Google/GitHub/Microsoft account
  2. Navigates to `/api/auth/sso/google` 
  3. Completes OAuth flow
  4. Gets admin access automatically
- **Blast radius:** Any valid external identity gets full admin access. PKCE absence means auth code interception attack is possible.
- **Recommendation:** 
  1. Auto-provision as `"viewer"` by default, not `"admin"`
  2. Switch to `authlib` for PKCE support, or add manual PKCE implementation
  3. Validate `redirect_uri` against a configured whitelist

---

### API Key & JWT Model

#### Finding #6 **[Severity: HIGH]** API key pepper is ephemeral by default

- **Location:** `src/easm/auth/api_keys.py:17-30`
- **Evidence:**
  ```python
  def _get_pepper() -> bytes:
      global _pepper
      if _pepper is None:
          env = os.environ.get("EASM_API_KEY_PEPPER")
          if env:
              _pepper = env.encode()
          else:
              _pepper = secrets.token_bytes(32)  # ❌ Random per process
              logger.warning("EASM_API_KEY_PEPPER not set — using ephemeral pepper...")
      return _pepper
  ```
- **Attacker path:** Server restart → all API keys invalidated (denial-of-service). Multi-worker deployment → keys only valid for one worker.
- **Blast radius:** Operational — all API keys break on restart. But also: if attacker restarts the process (DoS), all API keys become invalid.
- **Recommendation:** Require `EASM_API_KEY_PEPPER` in `.env.example` with a prominent comment. Consider generating from `EASM_SESSION_SECRET` as fallback.

#### Finding #7 **[Severity: MEDIUM]** No brute-force protection on login or API key endpoints

- **Location:** `src/easm/auth/middleware.py:48-67`, `src/easm/api/routes/auth.py:118-156`
- **Evidence:** No rate limiter, no account lockout, no incremental backoff on any auth endpoint.
- **Attacker path:** Attacker brute-forces login passwords or API keys without restriction.
- **Blast radius:** Credential compromise through brute force.
- **Recommendation:** Add token-bucket or sliding-window rate limiter on `POST /auth/login`, `POST /auth/api-keys`, and the middleware's API key validation path.

#### Finding #8 **[Severity: LOW]** No server-side JWT revocation

- **Location:** `src/easm/auth/session.py`, `src/easm/api/routes/auth.py:159-172`
- **Evidence:** Logout only clears the cookie — the JWT remains valid until expiry. No token blacklist.
- **Blast radius:** Stolen JWT cannot be revoked without changing `session_secret` (invalidates ALL sessions).
- **Recommendation:** Add a short-lived access token model or a database-backed token blacklist.

---

### Untrusted Data Ingestion

#### Finding #9 **[Severity: HIGH]** Certstream and crt.sh data flows to subprocess argv unsanitized

- **Location:** `src/easm/runners/registry.py:107-120`, `src/easm/runners/portscan_runner.py:24-42`
- **Evidence:** Hostnames from `entities` table (populated from certstream/crt.sh) flow directly into `nuclei`, `webanalyze`, and `nmap` commands without validation or sanitization.
  ```python
  # registry.py:107 — Nuclei hostnames from DB
  hostnames = await iterate_hostnames_x2(target, store.pool)
  # ... becomes nuclei -u <hostname> ...
  
  # portscan_runner.py:29-39 — Nmap hostnames from DB
  rows = await self.store.pool.fetch(
      "SELECT entity_value FROM entities WHERE target_id = $1 AND entity_type = 'hostname'"
  )
  ```
- **Attacker path:** 
  1. Attacker registers a domain with a malicious SAN value in a certificate (e.g., `--evil-flag.example.com`)
  2. crt.sh/certstream picks up the certificate
  3. The certstream runner inserts the hostname into the entities table
  4. Nuclei/nmap runs with the unsanitized hostname in argv
- **Blast radius:** Depends on how the target tool interprets the hostname string. Nmap treats positionals starting with `-` as flags. Nuclei/webanalyze use it as a flag value (safer, but unvalidated).
- **Recommendation:** 
  1. Add hostname validation on entity ingestion (RFC 1035 compliance check)
  2. Add `--` separator before hostnames where tools support it
  3. Strip leading `-` from hostnames before passing to subprocess

---

### Subprocess & External Tools

#### Finding #10 **[Severity: HIGH]** All binaries resolved by PATH — supply-chain risk

- **Location:** All 7 subprocess call sites (portscan_runner.py:70, github_scan_runner.py:55, registry.py:42,61,82,113,149)
- **Evidence:**
  ```python
  # Every binary is a bare name:
  cmd = ["nmap", "-Pn", "-sV", ...]
  cmd = ["nuclei", "-u", item, ...]
  cmd = ["gitleaks", "detect", "--no-git", ...]
  ```
- **Attacker path:** If an attacker can write to a directory earlier in PATH than `/usr/local/bin/` (e.g., in a shared container), they can substitute any binary.
- **Blast radius:** Arbitrary code execution under the runner user.
- **Recommendation:** Pin binaries to absolute paths (e.g., `/usr/local/bin/nmap`). Validate binary exists and is the expected version at startup (already partially done in `check_binaries()`).

#### Finding #11 **[Severity: MEDIUM]** Only portscan runner uses network guard

- **Location:** `src/easm/network_guard.py:43` (definition), `src/easm/runners/portscan_runner.py:58` (only caller)
- **Evidence:**
  ```python
  # portscan_runner.py:58 — Only caller
  guard = resolve_and_validate(hostname)
  if not guard.safe:
      continue
  
  # nuclei/webanalyze — NO guard call anywhere
  ```
- **Attacker path:** A target hostname that resolves to `127.0.0.1` is stored in the entities table. When nuclei or webanalyze scans, it hits internal services.
- **Blast radius:** SSRF — internal port scanning, internal service interaction.
- **Recommendation:** Extend `resolve_and_validate()` to nuclei and webanalyze at minimum. Better: filter hostnames at entity ingestion time.

---

### SSRF Surface

#### Finding #12 **[Severity: MEDIUM]** No outbound HTTP URL validation — private IPs reachable

- **Location:** `src/easm/runners/engine.py:606-758` (`standard_http_run`), `src/easm/pivot/handlers.py` (7+ HTTP endpoints)
- **Evidence:** Every outbound HTTP call constructs URLs from config or DB values with no private-IP validation:
  ```python
  # engine.py:767 — No IP check before fetch
  resp = await http.get(url)
  
  # handlers.py:910 — Reverse WHOIS, no URL validation
  resp = await client.get(f"https://reversewhois.io/?searchterm={domain}")
  
  # handlers.py:135 — Dehashed with email/domain in URL
  resp = await http.get(DEHASHED_API, params={"query": query, ...})
  ```
- **Attacker path:** Configure a target domain like `localhost` or `169.254.169.254` in config.yaml → trigger a runner that makes HTTP requests → SSRF to metadata endpoints or internal services.
- **Blast radius:** Internal network reconnaissance, metadata endpoint access (AWS, GCP, Azure).
- **Recommendation:** 
  1. Add `httpx.AsyncClient` with a custom transport that rejects private/reserved/loopback IPs
  2. Apply the same `resolve_and_validate()` logic to HTTP-based runners (most already only hit known external APIs, but custom ones could be dangerous)
  3. Document that `allow_external_network: false` should be the starting posture

---

### YAML / Config Trust

#### Finding #13 **[Severity: LOW]** Correlation rules use `yaml.safe_load()` — safe from code exec

- **Location:** `src/easm/correlation/loader.py:15`
- **Evidence:**
  ```python
  raw = yaml.safe_load(path.read_text())
  ```
- **Attacker path:** N/A — `safe_load` prevents arbitrary Python code execution from YAML. Rules are then validated through Pydantic `CorrelationRule.model_validate(raw)`.
- **Blast radius:** None. Good practice.
- **Recommendation:** No change needed.

#### Finding #14 **[Severity: MEDIUM]** PUT /api/config writes untrusted YAML to disk using `yaml.dump`

- **Location:** `src/easm/api/routes/config.py:46`
- **Evidence:**
  ```python
  yaml_text = yaml.dump(current, allow_unicode=True, sort_keys=False)
  Path(config_path).write_text(yaml_text)
  ```
- **Attacker path:** User-submitted `targets`/`alerts`/`saas_providers` dict is validated through Pydantic but then serialized and written to disk. No additional output sanitization.
- **Blast radius:** Configuration tampering that persists across restarts.
- **Recommendation:** Add an audit log entry when config is modified via API. Validate that `config_path` doesn't escape the expected directory.

---

### Filesystem Exposure

#### Finding #15 **[Severity: MEDIUM]** Screenshots stored in predictable path; no cleanup

- **Location:** `src/easm/runners/screenshot_runner.py:17,50-51`
- **Evidence:**
  ```python
  SCREENSHOT_DIR = Path("data/screenshots")
  # ...
  filepath = SCREENSHOT_DIR / f"{domain}.png"
  await page.screenshot(path=str(filepath), full_page=False)
  ```
- **Attacker path:** Screenshots of scanned websites stored on disk. If the web server serves static files from this directory, they're accessible.
- **Blast radius:** Information disclosure (screenshots of scanned targets).
- **Recommendation:** Ensure `data/screenshots/` is not served by the web server. Add retention policy.

#### Finding #16 **[Severity: LOW]** Config history exposes target definitions

- **Location:** `src/easm/api/routes/config.py:56-69`
- **Evidence:**
  ```python
  @router.get("/config/history")
  async def config_history(store=Depends(get_store)):
      rows = await store.pool.fetch(
          "SELECT id, raw_config->'targets' AS targets, loaded_at FROM config_snapshots..."
      )
  ```
- **Blast radius:** Config history (20 snapshots) includes full target definitions. In multi-tenant setups, all tenants see all snapshots.
- **Recommendation:** Scope config history by `org_id`.

---

### Database / Tenant Isolation

#### Finding #17 **[Severity: HIGH]** No tenant isolation in findings, entities, or config queries

- **Location:** `src/easm/store.py:1127-1182` (`list_findings`), `src/easm/store.py:73-164` (`list_entities` equivalent in routes)
- **Evidence:**
  ```python
  # store.py:1127 — No org_id parameter at all
  async def list_findings(self, target_id=None, risk=None, status=None, ...):
      conditions = []
      if target_id:
          conditions.append(f"target_id = ${idx}")
      # No org_id filter anywhere!
  ```
- **Attacker path:** In a multi-tenant deployment, User from org A calls `GET /api/findings?target_id=org-b-target` and sees findings from org B.
- **Blast radius:** Complete cross-tenant data leakage. All entities, findings, runs, certificates visible across orgs.
- **Recommendation:** Add `org_id` as a mandatory filter on all DB queries. The current code has `org_id` in the schema and in the middleware's `request.state.user` but never enforces it in read queries.

#### Finding #18 **[Severity: LOW]** Dehashed breach data stores plaintext credentials in DB

- **Location:** `src/easm/runners/breach_monitor_runner.py:143-155`
- **Evidence:**
  ```python
  raw = {
      "source": "dehashed",
      "email": entry.get("email", ""),
      "password": entry.get("password", ""),     # ❌ Plaintext password
      "hashed_password": entry.get("hashed_password", ""),
      ...
  }
  ```
- **Blast radius:** Breached credentials stored in plaintext in `raw_events.raw` JSONB column. Any user with DB read access can view them.
- **Recommendation:** Redact or hash breach passwords before storage, or add access-control on raw_events with `is_sensitive` flag.

---

### Docker & Network Defaults

#### Finding #19 **[Severity: MEDIUM]** Default database credentials in docker-compose.yml

- **Location:** `docker-compose.yml:7-9`
- **Evidence:**
  ```yaml
  environment:
    POSTGRES_DB: ${POSTGRES_DB:-easm}
    POSTGRES_USER: ${POSTGRES_USER:-easm}
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-easm}  # ⚠️ Default = "easm"
  ```
- **Attacker path:** An attacker who can reach the PostgreSQL port (5432, exposed on all interfaces at `docker-compose.yml:5`) can use default credentials.
- **Blast radius:** Full database compromise.
- **Recommendation:** Don't expose port 5432 to host unless needed. Use Docker secrets or require env vars without defaults.

#### Finding #20 **[Severity: MEDIUM]** PostgreSQL port exposed to host

- **Location:** `docker-compose.yml:4-5`
- **Evidence:**
  ```yaml
  ports:
    - "5432:5432"
  ```
- **Blast radius:** PostgreSQL accessible from host network (and potentially from other containers on the same Docker network).
- **Recommendation:** Only expose 5432 if needed for local development. Remove from production compose, or bind to `127.0.0.1:5432:5432`.

#### Finding #21 **[Severity: INFO]** Config file mounted read-only — good

- **Location:** `docker-compose.yml:28-29`
- **Evidence:**
  ```yaml
  volumes:
    - ./config.yaml:/app/config.yaml:ro    # ✅ ro
  ```
- **Blast radius:** None. Good practice. But the API can still overwrite it via `PUT /api/config` since the app writes through the filesystem, not the Docker mount.
- **Note:** The `PUT /api/config` writes to `os.environ.get("EASM_CONFIG_PATH", "config.yaml")` which may resolve to `/app/config.yaml` inside the container — this CAN overwrite a Docker `:ro` mount because the write happens *inside* the container at the mounted path.

---

### Supply-Chain & Binary Trust

#### Finding #22 **[Severity: MEDIUM]** Binary versions pinned in Dockerfile but verified via PATH at runtime

- **Location:** `Dockerfile:47-84` (pinned versions), `src/easm/api/routes/health.py:38-50` (PATH check)
- **Evidence:**
  ```dockerfile
  # Dockerfile:47 — Pinned versions in Docker
  RUN SUBFINDER_VER="v2.14.0" && curl -L "...subfinder_${SUBFINDER_VER#v}_linux_amd64.zip" ...
  
  # health.py:38 — But runtime check uses PATH
  path = shutil.which(binary)
  ```
- **Attacker path:** If an attacker compromises the build pipeline or the container registry, they can substitute binaries. PATH-based resolution at runtime means the wrong binary could be invoked.
- **Blast radius:** Depends on which binary is compromised.
- **Recommendation:** Verify binary checksums at startup. Use absolute paths from Dockerfile locations.

---

## Top 5 Surface Reductions

| # | Change | Impact | Effort |
|---|--------|--------|--------|
| 1 | **Add `request.state.user` checks on `PUT /api/config`, `POST /api/config/reload`, `POST /api/runs/{id}/{runner}`** | Eliminates critical config/run bypass in default posture | **Low** (3 lines each) |
| 2 | **Add `org_id` filter to all DB read queries (list_findings, list_entities, etc.)** | Closes complete cross-tenant data leakage | **Medium** (update 10+ queries) |
| 3 | **Restrict CORS origins to deployment URL** | Closes cross-origin data theft | **Low** (1 line config) |
| 4 | **Extend `resolve_and_validate()` to nuclei, webanalyze, and all HTTP-based runners** | Closes SSRF vector for internal scanning | **Medium** (add guard to 3+ runners) |
| 5 | **Add hostname validation on entity ingestion (RFC 1035 + strip leading `-`)** | Prevents subprocess flag injection from external data | **Low** (1 validation function + 1 call site) |

---

## Scorecard

| Dimension | Score (1-10) | Justification |
|-----------|-------------|---------------|
| **Auth Boundary Discipline** | **4/10** | JWT/API-key components are well-implemented individually, but the default `"none"` mode and missing route-level checks on dangerous endpoints negate much of the auth boundary. |
| **Default Posture** | **2/10** | `mode=none`, `*` CORS origins, ephemeral API-key pepper, default DB password `easm`, PostgreSQL port exposed — the product has minimal hardening out of the box. |
| **Untrusted-Data Handling** | **5/10** | JSON/stdout parsers are tolerant of malformed input. But externally-derived hostnames flow unsanitized to subprocess argv. YAML uses `safe_load` (good). No content-type validation on ingested data. |
| **Subprocess Containment** | **4/10** | No `shell=True` (good), but all binaries are PATH-resolved, hostnames pass through without validation, and only 1 of 3 active-scan runners uses the network guard. |
| **SSRF Controls** | **3/10** | `network_guard.py` is well-designed but only applied to `portscan`. No outbound HTTP IP validation. No DNS rebinding protection. |
| **Tenant Isolation** | **2/10** | Schema supports `org_id` but read queries don't filter by it. `list_findings()` has no `org_id` parameter at all. |
| **Secret Management** | **4/10** | bcrypt for passwords (good), HMAC-SHA256 with pepper for API keys (good, but pepper ephemeral by default). No session secret requirement in `.env.example`. Enrichment keys leak through config endpoint. |

---

*Report generated via static code analysis of 100% of route files, auth modules, runner files, and infrastructure configuration. No active testing performed.*
