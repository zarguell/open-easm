# Open EASM — Product Roadmap

## Current State

**What's working:** Passive discovery pipeline (asnmap, certstream, subfinder, crt.sh, reverse DNS, forward DNS, domain extraction), automated pivot chaining (ASN → IP ranges → hostnames → domains → certificates), D3-force graph explorer, entity inventory with filters, run tracking, pivot queue, per-target YAML configuration, Docker single-binary deployment, enrichment pipeline (DNS mail records, mail provider classification, TLS cert grab, RDAP domain enrichment, geo-IP, Shodan InternetDB, DNSTwist lookalikes).

**Tech stack:** Python 3.14 / FastAPI / asyncpg / APScheduler, React 18 / TypeScript / Vite / Tailwind CSS 4, PostgreSQL 18, D3-force.

**Reference architecture:** [SpiderFoot](https://github.com/smicallef/spiderfoot) — 231-module OSINT engine with event-driven pub/sub architecture and YAML correlation rules. Our pivot handler + parser pattern mirrors their module system; their correlation engine and enrichment integrations are direct reference implementations we can adapt.

---

## Phase 1 — Quick Wins

High ROI, low effort. Each can ship independently.

### 1.1 Org vs. SaaS Provider Taxonomy

**Problem:** Every discovered host is treated as "yours." Pivoting on `amazonaws.com` as a whole is noise — a Netskope static IP is useful research, but an AWS S3 bucket isn't your infrastructure.

**Scope:**
- Add asset classification: `org-owned`, `saas-hosted`, `third-party-integrated`
- Config-driven SaaS provider list (e.g. `amazonaws.com`, `cloudfront.net`, `azurewebsites.net`) with per-provider rules
- Only `org-owned` assets trigger active discovery (future phases); `saas-hosted` gets metadata enrichment only
- UI: show classification badge on entities

**Why first:** This taxonomy is load-bearing for every future phase. Without it, active scanning would hit SaaS infrastructure you don't own.

---

### 1.2 Paste Site Monitoring

**Problem:** Public paste sites (Pastebin, paste.ee) are the most accessible source of leaked credentials and internal references. Real leaks appear here constantly.

**Scope:**
- Poll Pastebin scrape API (`scrape.pastebin.com`) for new public pastes
- Add additional paste sources: paste.ee, dpaste, Ghostbin
- Regex/keyword matching against org domains, email patterns (`@yourorg.com`), IP ranges, internal hostnames, API key patterns
- Emit structured findings into existing entity pipeline
- Runner config in `config.yaml`:
  ```yaml
  runners:
    paste_monitor:
      enabled: true
      sources: [pastebin, paste_ee]
      schedule: "*/5 * * * *"
      keywords_from_target: true  # uses match_rules + labels
  ```

**SpiderFoot reference:** `sfp_pastebin` (Google API search), `sfp_psbdmp` (Pastebin dump checker). Their approach is search-based; ours is polling-based for real-time coverage.

**Why quick:** Pastebin's scraping API is a straightforward HTTP poll + regex match. Minimal dependencies, immediate value.

---

### 1.3 GitHub/GitLab Code Search

**Problem:** Developers accidentally push credentials, internal hostnames, and config files to public repos. Tools like trufflehog and gitleaks already solve this.

**Scope:**
- Integrate `gitleaks` as a scheduled scan module
- GitHub code search API for org domains, internal naming conventions
- Emit structured findings: `{source, keyword_matched, raw_context, severity, timestamp}`
- Runner config:
  ```yaml
  runners:
    github_scan:
      enabled: true
      schedule: "0 */4 * * *"
      scan_public_repos: true
      rules: [credential_patterns, domain_matches, internal_hostnames]
  ```

**SpiderFoot reference:** `sfp_github` (repo discovery), `sfp_tool_trufflehog` (secret scanning), `sfp_searchcode` (code search across repos).

**Why quick:** `gitleaks` is a single binary. GitHub's code search API is well-documented. Wire them into the existing runner framework.

---

### 1.4 Keyword Alert Architecture

**Problem:** Every monitor (paste, GitHub, Telegram, stealer logs) needs the same keyword matching logic. Without a unified system, each source reimplements matching.

**Scope:**
- Define a keyword library derived from config: org domains, `@yourorg.com` email patterns, internal hostnames, executive names, product names, cloud account IDs, known API key prefixes
- Shared matching engine: regex + exact match + fuzzy match
- Unified finding schema:
  ```json
  {
    "source": "paste_monitor",
    "keyword_matched": "internal-git.yourorg.com",
    "raw_context": "...surrounding text...",
    "severity": "high",
    "timestamp": "2026-05-16T12:00:00Z"
  }
  ```
- Feed findings into existing enrichment pipeline — correlate leaked credentials against known asset inventory to determine if the associated service is still live

**Why quick:** This is the architecture note from the PRD discussion. It's a shared module that all future monitors consume. Build it once, every monitor after this is plug-and-play.

---

### 1.5 Threat Intel Enrichment Pipeline

**Problem:** We discover IPs, domains, and hostnames but can't tell you whether they're malicious, clean, or unknown. An EASM tool without risk scoring is half a product.

**Scope:**
- Build a generic enrichment handler pattern: API call → entity attributes with risk scores
- Start with free-tier sources:
  - **GreyNoise** (community API, free) — "is this IP part of mass-scanning noise?"
  - **AbuseIPDB** (free tier, 1000 checks/day) — crowdsourced abuse reports
  - **URLScan.io** (free API) — recent HTTP scan results for domains/IPs
- Store results as entity attributes:
  ```json
  {
    "threat_intel": {
      "greynoise": { "classification": "benign", "noise": false },
      "abuseipdb": { "score": 0, "total_reports": 0 },
      "urlscan": { "last_scan": "2026-05-16T...", "malicious": false }
    }
  }
  ```
- New pivot types: `greynoise_enrich`, `abuseipdb_enrich`, `urlscan_enrich`
- Config:
  ```yaml
  enrichment:
    threat_intel:
      greynoose: { enabled: true, api_key: "" }
      abuseipdb: { enabled: true, api_key: "${ABUSEIPDB_KEY}" }
      urlscan: { enabled: true }
  ```

**SpiderFoot reference:** They have 60 reputation/blacklist modules. We don't need 60 — we need 3-5 high-signal sources. Their `sfp_greynoise`, `sfp_greynoise_community`, `sfp_abuseipdb`, and `sfp_urlscan` are direct references for our enrichment handlers.

**Why here:** Threat intel enrichment on every discovered IP and domain is foundational. Every future feature (correlation rules, alerts, risk dashboards) depends on having risk scores.

---

### 1.6 Breach Data Monitoring

**Problem:** Knowing which of your domains and email patterns appear in public breach databases is one of the highest-signal intelligence sources for external risk.

**Scope:**
- Integrate breach data APIs as enrichment handlers:
  - **HaveIBeenPwned** (paid API) — check email patterns against breach data
  - **Dehashed** (API key required) — broader breach search, includes passwords, IPs, usernames
- Run against email patterns derived from target config (`*@yourorg.com`)
- Store breach metadata on entities, emit findings when new breaches match
- Runner config:
  ```yaml
  runners:
    breach_monitor:
      enabled: true
      sources: [hibp, dehashed]
      schedule: "0 6 * * *"  # daily at 6am
      email_patterns_from_target: true
  ```

**SpiderFoot reference:** `sfp_haveibeenpwned` (breach-by-email lookup), `sfp_dehashed` (broad breach search), `sfp_citadel` (Leak-Lookup.com), `sfp_leakix` (host data leaks). Their breach modules are straightforward API wrappers — easy to replicate.

**Why here:** Directly actionable intelligence. "Your credentials appeared in this breach, and the service is still live" is the highest-priority finding a security team can get.

---

### 1.7 Cloud Asset Discovery

**Problem:** Misconfigured cloud storage buckets (S3, GCS, Azure Blob) are a top attack vector. SpiderFoot can find these; we can't.

**Scope:**
- Enumerate cloud storage buckets by combining org keywords, domain prefixes, and known naming patterns
- Providers: Amazon S3, Google Cloud Storage, Azure Blob Storage, DigitalOcean Spaces
- Anonymous access check: can this bucket be listed/read without auth?
- Store as entities with `cloud_storage` type and `provider`, `public_access`, `region` attributes
- New pivot type: `cloud_bucket_enum`
- Config:
  ```yaml
  runners:
    cloud_enum:
      enabled: true
      providers: [s3, gcs, azure]
      schedule: "0 4 * * 1"  # weekly
      prefixes_from_target: true
  ```

**SpiderFoot reference:** `sfp_s3bucket`, `sfp_azureblobstorage`, `sfp_googleobjectstorage`, `sfp_digitaloceanspace`, `sfp_grayhatwarfare`. Their bucket discovery is simple: construct URLs from target keywords, check HTTP response codes.

**Why here:** Passive (no active scanning needed — just HTTP HEAD requests to constructed URLs). High-severity findings. Low effort.

---

## Phase 2 — Platform, Intelligence & Configuration

Operational foundation and the intelligence layer that turns raw data into actionable findings.

### 2.1 Correlation / Detection Engine

**Problem:** We discover hundreds of entities but can't tell the user which ones actually matter. We need automated detection logic that composes raw entities into high-level findings.

**Scope:**
- YAML-defined correlation rules that query the entity graph and emit findings
- Rule structure (modeled after SpiderFoot's correlation engine):
  ```yaml
  id: dev_or_test_system
  meta:
    name: "Development or test system found on public internet"
    risk: medium
  collect:
    - method: exact
      field: entity_type
      value: hostname
    - method: regex
      field: value
      patterns: [".*dev.*", ".*test.*", ".*staging.*", ".*uat.*", ".*internal.*"]
  aggregation:
    field: value
  headline: "Development system exposed: {value}"
  ```

- Initial rule set (adapted from SpiderFoot's 37 rules — their logic is our reference):
  - `dev_or_test_system` — hostnames matching dev/test/staging/uat patterns
  - `remote_desktop_exposed` — RDP (3389) or VNC (5900) ports open
  - `cloud_bucket_open` — public cloud storage bucket discovered
  - `email_in_breach` — org email pattern found in breach database
  - `stale_certificate` — TLS cert expiring within 30 days or expired
  - `subdomain_takeover_risk` — CNAME pointing to deleted/delegated service
  - `high_risk_port_exposed` — database (5432, 3306, 27017) or management (22, 8080) ports open
  - `outlier_country` — IP in unexpected geography
  - `defaced_host` — hostname in defacement databases
  - `vulnerable_software` — identified software version with known CVEs

- Findings stored as first-class entities with `finding` type, linked to source entities
- API: `GET /api/findings` with severity filtering
- UI: findings panel on dashboard, severity badge on affected entities

**SpiderFoot reference:** `correlations/` directory contains 37 YAML rules. `spiderfoot/correlation.py` implements the engine. Their rule DSL (collect → aggregation → analysis → headline) is clean and we can adapt it directly. Rules like `dev_or_test_system.yaml`, `remote_desktop_exposed.yaml`, `email_in_multiple_breaches.yaml` are directly reusable.

**Why critical:** This is the layer between "we discovered an IP" and "here's what you should care about." Without it, we're a data collector, not a security tool.

### 2.2 Config Editing from Web UI

**Scope:**
- Read/write `config.yaml` from the UI
- Edit target definitions, runner settings, schedules, match rules
- Validate changes before saving (reuse existing Pydantic validation)
- Config change history (diff view)

### 2.3 Config Sync (Bidirectional YAML ↔ DB)

**Scope:**
- YAML remains source of truth on disk
- UI edits write back to YAML
- DB stores current config snapshot (already exists as `config_snapshots`)
- Hot-reload: detect YAML changes on disk, reload without restart
- Conflict resolution: last-write-wins with audit trail

### 2.4 Watch Alerts

**Scope:**
- Configurable alert rules in `config.yaml` and UI:
  - Risky ports detected (e.g., 22, 3389, 5432 publicly exposed)
  - Domain matches (no `dev`/`test`/`staging` publicly accessible)
  - New entity types appearing for the first time
  - Certificate changes on monitored domains
  - Findings from correlation engine (Phase 2.1)
- Alert delivery: in-app notification feed (future: email, Slack, webhook)
- Alert config:
  ```yaml
  alerts:
    rules:
      - name: "No dev/test public"
        condition: "hostname matches *(dev|test|staging)*.yourorg.com"
        severity: critical
      - name: "Risky ports"
        condition: "port in [22, 3389, 5432, 6379, 9200, 27017]"
        severity: high
  ```

---

## Phase 3 — Active Discovery (Opt-In, Not Default)

These features are OFF by default. Demo data and local instances should not actively scan.

### 3.1 Service Fingerprinting

**Scope:**
- Beyond banner grabbing — identify actual products/services (nginx vs Apache, WordPress vs Ghost, etc.)
- **Wappalyzer** CLI integration for web technology identification (frameworks, CMS, analytics, JS libraries)
- HTTP fingerprinting: headers, body patterns, favicon hashes
- TLS fingerprinting: cipher suites, certificate details
- Store `technologies` attribute on hostname entities:
  ```json
  {
    "technologies": [
      { "name": "nginx", "version": "1.24.0", "categories": ["Web Servers"] },
      { "name": "WordPress", "version": "6.4", "categories": ["CMS"] }
    ]
  }
  ```
- Enable per-target, not globally

**SpiderFoot reference:** `sfp_tool_wappalyzer` (Wappalyzer CLI), `sfp_tool_whatweb` (WhatWeb), `sfp_tool_cmseek` (CMS detection), `sfp_whatcms` (WhatCMS.org API), `sfp_builtwith` (BuiltWith.com), `sfp_webframework` (jQuery/YUI detection), `sfp_webserver` (banner extraction). Wappalyzer covers the most ground with a single tool.

### 3.2 Web Screenshot Indexing

**Scope:**
- Screenshot each discovered HTTP/HTTPS service once
- Configurable refresh interval (e.g., weekly)
- Store screenshots in configurable storage (local disk, S3)
- Visual delta detection: "this login page changed"
- Thumbnail in entity detail slide-over

### 3.3 Port Scanning

**Scope:**
- `nmap` or `masscan` integration (start with `python-nmap` wrapper)
- Per-target opt-in only
- Scan profiles: quick (top 100 ports), standard (top 1000), full (all)
- Results feed into entity model (open ports, services, versions)
- Config:
  ```yaml
  runners:
    port_scan:
      enabled: false  # OFF by default
      profile: standard
      schedule: "0 3 * * 0"  # weekly, Sunday 3am
  ```

### 3.4 Nuclei Vulnerability Templates

**Problem:** Port scanning tells you what's open; Nuclei tells you what's vulnerable. 5000+ community templates for exposures, misconfigs, default credentials, known CVEs.

**Scope:**
- Integrate `nuclei` CLI as an opt-in active runner
- Template categories: exposures, misconfigurations, vulnerabilities, default-logins
- Results feed into entity model as vulnerability findings
- Per-target opt-in only, OFF by default
- Config:
  ```yaml
  runners:
    nuclei_scan:
      enabled: false
      templates: [exposures, misconfigurations]
      severity: [critical, high]
      schedule: "0 3 * * 0"
  ```

**SpiderFoot reference:** `sfp_tool_nuclei` — direct reference for nuclei integration pattern. Also `sfp_tool_testsslsh` (TLS weakness detection), `sfp_tool_retirejs` (vulnerable JS library detection).

---

## Phase 4 — Exposure Monitoring (Continuous, Passive)

Higher-signal, higher-maintenance sources.

### 4.1 Telegram Channel Monitoring

**Scope:**
- `telethon` (Python MTProto client) for public channel indexing
- Monitor known threat actor channels, stealer log dump channels, initial access broker channels
- Keyword matching through the shared keyword library (Phase 1.4)
- Channel management: add/remove channels via config
- Opsec considerations: account requirements, rate limiting

### 4.2 Stealer Log Monitoring

**Scope:**
- Monitor stealer log dump channels (highest-value Telegram source)
- Fresh credential dumps, almost all public
- Correlate leaked credentials against known asset inventory
- "Is the leaked service still live and exposed?" — cross-reference with entity graph

### 4.3 Additional Paste Sources

**Scope:**
- Expand beyond Phase 1.2 with: GitHub Gists, StackOverflow posts, Discord public channels
- RSS/API-based monitoring where available
- All sources emit the unified finding schema

---

## Phase 5 — Deep Enrichment

Extended intelligence sources that add depth to discovered entities.

### 5.1 Full Shodan API

**Problem:** We use Shodan InternetDB (free, no API key) which only returns basic data. The full Shodan API provides ports, banners, vulnerabilities, SSL data, org info, and hostnames.

**Scope:**
- Expand existing Shodan pivot handler to use full API when key is configured
- Fallback to InternetDB when no key
- Store full Shodan data as entity attributes: open ports, service banners, CVEs, SSL info
- Config:
  ```yaml
  enrichment:
    shodan:
      api_key: "${SHODAN_KEY}"  # optional, falls back to free InternetDB
  ```

**SpiderFoot reference:** `sfp_shodan` — full Shodan API integration with API key support, netblock expansion, and port/service data extraction.

### 5.2 Censys Integration

**Scope:**
- Censys.io REST API for complementary internet-wide scan data
- Different scan coverage than Shodan — catches things Shodan misses
- Free tier available (2.5 queries/hr)
- New pivot type: `censys_enrich`

**SpiderFoot reference:** `sfp_censys` — direct reference. Censys provides host data, certificate data, and search capabilities.

### 5.3 Reverse WHOIS / Domain Discovery

**Problem:** We discover domains through passive DNS and certificates, but we can't find other domains registered by the same organization or person. "You own example.com? Here are 14 other domains registered by your CFO's email."

**Scope:**
- Reverse WHOIS lookup: given org name or registrant email, find related domains
- Sources: Whoxy API, Whoisology, ViewDNS
- New pivot type: `reverse_whois`
- Results feed into entity graph as new domain entities

**SpiderFoot reference:** `sfp_reversewhois`, `sfp_whoxy`, `sfp_whoisology`, `sfp_viewdns`. All are API-based reverse WHOIS lookups.

### 5.4 Passive DNS History

**Problem:** We see current DNS state but not historical. "What IPs did this domain resolve to last month?" reveals infrastructure changes, failover patterns, and sometimes shadow IT.

**Scope:**
- Historical DNS records from Farsight DNSDB or SecurityTrails
- Store DNS history as entity attributes with timestamps
- New pivot type: `passive_dns_history`

**SpiderFoot reference:** `sfp_dnsdb` (Farsight DNSDB), `sfp_securitytrails` (SecurityTrails passive DNS + domain history), `sfp_mnemonic` (PassiveDNS.mnemonic.no).

### 5.5 Subdomain Takeover Detection

**Problem:** Dangling CNAME records pointing to deleted cloud services (S3 buckets, GitHub Pages, Heroku apps) can be claimed by attackers.

**Scope:**
- Check CNAME targets against known vulnerable service fingerprints
- Fingerprint database: GitHub Pages, Heroku, S3, Ghost.io, Pantheon, etc.
- New pivot type: `subdomain_takeover_check`
- Emit findings when vulnerable takeover detected

**SpiderFoot reference:** `sfp_subdomain_takeover` — checks CNAME resolution against fingerprint database of takeable services.

### 5.6 CommonCrawl URL Discovery

**Problem:** Web crawling is active and slow. CommonCrawl has already crawled the internet — we can query their index passively for URLs matching our domains.

**Scope:**
- Query CommonCrawl CDX API for URLs matching target domains
- Extract paths, parameters, and linked resources
- New runner: `commoncrawl` with scheduled polling
- Passive — no active crawling, no contact with target infrastructure

**SpiderFoot reference:** `sfp_commoncrawl` — queries CDX API for historical URLs related to target domains.

### 5.7 Search Engine Discovery

**Problem:** Subfinder uses passive DNS sources. Search engines discover subdomains and URLs that don't have DNS records yet (internal tools referenced in public pages, staging environments in sitemaps).

**Scope:**
- Google Custom Search API for subdomain enumeration
- Bing Search API for complementary results
- DuckDuckGo for additional coverage (no API key needed)
- Extract subdomains, URLs, and page titles from results
- New runner: `searchengine_enum`

**SpiderFoot reference:** `sfp_googlesearch` (Google Custom Search), `sfp_bingsearch` (Bing API), `sfp_duckduckgo` (DDG API). All enumerate subdomains and links via search engine results.

---

## Dependency Graph

```
Phase 1.1 (Taxonomy)          ← no dependencies, unblocks everything
Phase 1.4 (Keyword Engine)    ← no dependencies, unblocks all monitors
Phase 1.5 (Threat Intel)      ← no dependencies, unblocks correlation
Phase 1.6 (Breach Data)       ← depends on 1.4 (keyword engine for email patterns)
Phase 1.7 (Cloud Assets)      ← no dependencies
Phase 1.2 (Paste Monitor)     ← depends on 1.4 (uses keyword engine)
Phase 1.3 (GitHub Scan)       ← depends on 1.4 (uses keyword engine)

Phase 2.1 (Correlation)       ← depends on 1.5 (threat intel for risk scores)
Phase 2.2-2.4 (Platform)      ← independent of Phase 1, parallel track

Phase 3.x (Active Discovery)  ← depends on 1.1 (taxonomy for what to scan)
Phase 4.x (Exposure Monitor)  ← depends on 1.4 (keyword engine)
Phase 5.x (Deep Enrichment)   ← independent, can start anytime
```

**Recommended order:** 1.1 → 1.4 → 1.5 + 1.7 (parallel) → 1.2 + 1.3 + 1.6 (parallel) → 2.1 → 2.2-2.4 → 3.x → 4.x → 5.x

---

## SpiderFoot as Reference

[SpiderFoot](https://github.com/smicallef/spiderfoot) (cloned locally at `spiderfoot/`) serves as a primary reference for all enrichment and detection work. Key reference areas:

| What We're Building | SpiderFoot Reference Files |
|---|---|
| Correlation engine | `correlations/*.yaml` (38 rules), `spiderfoot/correlation.py` |
| Threat intel enrichment | `modules/sfp_greynoise.py`, `sfp_abuseipdb.py`, `sfp_urlscan.py` |
| Breach monitoring | `modules/sfp_haveibeenpwned.py`, `sfp_dehashed.py`, `sfp_leakix.py` |
| Cloud asset discovery | `modules/sfp_s3bucket.py`, `sfp_azureblobstorage.py`, `sfp_googleobjectstorage.py` |
| Tech fingerprinting | `modules/sfp_tool_wappalyzer.py`, `sfp_whatcms.py`, `sfp_builtwith.py` |
| Reverse WHOIS | `modules/sfp_reversewhois.py`, `sfp_whoxy.py`, `sfp_whoisology.py` |
| Passive DNS history | `modules/sfp_dnsdb.py`, `sfp_securitytrails.py` |
| Subdomain takeover | `modules/sfp_subdomain_takeover.py` |
| Search engine enum | `modules/sfp_googlesearch.py`, `sfp_bingsearch.py` |
| Nuclei integration | `modules/sfp_tool_nuclei.py` |
| Module architecture | `spiderfoot/plugin.py` (base class), `modules/sfp_template.py` (template) |
| Event type system | `spiderfoot/db.py` (173 canonical event types in `eventDetails`) |

**How to use SpiderFoot as reference:**
1. Find the relevant `sfp_*.py` module(s) in their `modules/` directory
2. Read `handleEvent()` — this is where the API call and data extraction happens
3. Read `watchedEvents()` and `producedEvents()` — this defines what triggers the module and what it outputs
4. Adapt the logic into our `PivotHandler.execute()` + `BaseParser.parse()` pattern
5. Their correlation rules in `correlations/*.yaml` are directly adaptable to our YAML detection engine

---

## Not Planned (Yet)

- Auth / RBAC / multi-user
- Notification routing (email, Slack, PagerDuty)
- API token management
- Source-specific confidence scoring
- Historical delta classification beyond dedup
- Mobile UI
- Multi-tenancy

---

## Explicitly Out of Scope

Capabilities SpiderFoot has that don't fit our EASM mission:

| SpiderFoot Capability | Why We Skip It |
|---|---|
| 60+ DNS-blocking reputation checks (AdBlock, Quad9, Cloudflare DNS, etc.) | Content filtering, not attack surface. We need 2-3 high-signal threat intel sources, not 60 blocklist booleans |
| Bitcoin / Ethereum tracking | Niche, only relevant if target uses cryptocurrency |
| Phone number / physical address OSINT | People-centric social engineering defense, not infrastructure EASM |
| Social media profiling (Flickr, MySpace, Venmo, Gravatar) | Brand monitoring, not attack surface |
| Dark web search engines (Ahmia, Torch, OnionCity) | Requires Tor infrastructure; low signal-to-noise for most EASM use cases |
| Credit card / IBAN extraction | Compliance tooling, not attack surface management |
| Web spidering / full content crawling | Our architecture is passive-first. Spidering is active and noisy |
| DNS brute force / zone transfer attempts | Invasive active techniques; subfinder covers passive subdomain discovery |
| Human name extraction from content | People-centric OSINT, not infrastructure |
