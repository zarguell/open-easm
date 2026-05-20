# Open EASM — Product Backlog

Two categories of work: **Verified Bugs** (things that are claimed to work but don't) and **Capability Gaps** (things that aren't built yet). Verified bugs are higher priority because they erode trust in the platform's output.

See [ROADMAP.md](ROADMAP.md) for the phased development plan already in progress.

---

## P0 — Verified Bugs (Claimed Features That Don't Work)

These are architecturally broken — not missing features, but features that exist in the codebase and appear to work but silently produce wrong or empty results.

### BUG-01: UI Count Displays Are Incorrect

**Claimed**: Dashboard metrics show accurate asset counts and risk distributions.

**Reality**: 6 of 12 count displays derive totals from truncated datasets. The platform can have 50,000 assets but the UI reports counts based on the first 500.

**Affected components**:

| Component | Bug | File |
|---|---|---|
| AssetRiskOverview | Counts from `limit: 500` query | `ui/src/components/dashboard/AssetRiskOverview.tsx:52` |
| CascadeVisualization | Counts from `limit: 500` query | `ui/src/components/dashboard/CascadeVisualization.tsx` |
| GeoMap | Only plots first 500 IPs | `ui/src/components/GeoMap.tsx` |
| Asset export NDJSON | Silently truncates at 500 rows | `src/easm/api/assets.py:63` |
| Risk scoring | `_findings_for_entity` caps at 200 findings | `src/easm/store.py:542` |
| All list endpoints | No `total_count` returned — only triage inbox uses `COUNT(*) OVER()` | `src/easm/store.py` (multiple) |

**Not affected**: `MetricCards.tsx` uses `useEntityCounts()` → proper `COUNT(*) GROUP BY` — correct.

**Root cause**: `store.py:730` hard-caps asset inventory queries at 500: `limit = max(1, min(limit, 500))`. Frontend components treat truncated results as complete datasets.

**Fix approach**:
1. Add `total_count` to all paginated list responses (triage inbox already proves the pattern works)
2. Change dashboard components to use dedicated count endpoints instead of counting array length
3. Remove the 500 cap from `store.py` or make it configurable
4. Fix asset export to stream all results, not just first 500
5. Remove the 200 cap from `_findings_for_entity`

---

### BUG-02: Search Functionality Is Non-Functional

**Claimed**: Global search across the attack surface inventory.

**Reality**: The TopBar search input is a placebo — no event handlers, no state, no API call. There is no backend text search. All existing "search" is client-side filtering of already-fetched paginated data.

**Specific findings**:

| Issue | Detail |
|---|---|
| TopBar "Search…" | `<input placeholder="Search…" />` with zero event handlers. Purely decorative. |
| No backend text search | Zero API endpoints accept a `search`/`q` parameter. |
| Client-side search is broken | Text search filters locally-loaded pages. Results beyond the fetched page are invisible. |
| Alerts feed has zero filters | `/api/findings` supports rich filtering but `AlertsView` passes zero params. No search, no dropdowns, no pagination. |
| Findings API has no UI | `/api/findings` fully built with filtering but no `FindingsView` exists. Dead endpoint. |
| Inconsistent filter models | Different views use different pagination (cursor vs offset vs none), different filter capabilities, no cross-view consistency. |

**Fix approach**:
1. Add `q` parameter to `/api/entities`, `/api/findings`, `/api/runs` for full-text search (PostgreSQL `tsvector` or `ILIKE` on entity_value)
2. Wire TopBar to a global search API
3. Add filter controls to AlertsView using the existing `/api/findings` filter params
4. Create a FindingsView component that uses the existing findings API

---

### BUG-03: Certstream Pipeline Is Disconnected

**Claimed**: Real-time Certificate Transparency monitoring.

**Reality**: Certstream is a raw event collector. It inserts events into `raw_events` but never creates entities. The OUTPUT_SCHEMA at `schemas.py:184` is well-written code that transforms certstream events into entities — but the legacy adapter bypasses it entirely.

**Code path**:
1. `main.py:162` → `execute_runner("certstream", ...)` 
2. `runners/__init__.py:25` → `_make_legacy_adapter(CertStreamRunner)` wraps it
3. `certstream_runner.py` → `run_once()` calls `store.insert_raw_event()` only
4. `engine.py` → `execute_runner()` does NOT invoke output_schema
5. Only `standard_subprocess_run` and `standard_http_run` invoke output schemas — certstream uses neither

**Result**: Certstream events accumulate in `raw_events` as an audit log. They never become entities in the graph. No enrichment, no correlation, no alerts.

**Fix approach**:
1. Option A: Refactor certstream to use `standard_http_run` (or a new `standard_websocket_run`) that invokes the output schema
2. Option B: Add a post-processing step in `execute_runner` that invokes `output_schema` when present, even for legacy adapters
3. Option C: Add a `raw_events → entities` processor that reads unprocessed certstream events and runs them through OUTPUT_SCHEMAS

---

### BUG-04: Scanner Runners Silent-Fail

**Claimed**: 18 discovery runners, all operational.

**Reality**: Multiple runners silently fail because required binaries are not installed in the Docker image, or because the pipeline catches and swallows all errors.

| Runner | Status | Why |
|---|---|---|
| **gitleaks** | Never runs | `github_scan_runner.py:55` runs `gitleaks detect` but Dockerfile never installs gitleaks binary. `FileNotFoundError` is silently caught at line 59. |
| **dnstwist** | Never runs | Binary not in Docker image. Falls back to `"binary not found: dnstwist"` error message that's caught and returned as `(0, 0, 0)`. |
| **commoncrawl** | Time-bomb | Hardcoded crawl index `"2026-17"`. Will break when CommonCrawl rotates this index out. |
| **discord_monitor** | Paper feature | `add_message()` is never called anywhere. Always returns `(0, 0, 0)`. No Discord API connection exists. |
| **Google/Bing search** | Non-functional | API keys are constructor defaults (empty strings), never wired from config. Only DuckDuckGo HTML scraping works. |

**Fix approach**:
1. Add gitleaks and dnstwist binary installation to Dockerfile
2. Parametrize CommonCrawl index or auto-resolve latest
3. Remove discord_monitor or implement it properly
4. Wire Google/Bing API keys from config.yaml
5. Add health-check logging: runners should log a warning (not silently return) when they can't execute

---

### BUG-05: 5 of 9 Correlation Rules Never Fire Correctly

**Claimed**: 7 built-in correlation rules for attack surface detection.

**Reality**: Only 2 of 9 rules produce meaningful results. The rest have logic errors that prevent them from matching or cause them to fire on every entity.

| Rule | Status | Bug |
|---|---|---|
| `cloud_bucket_open` | ✅ Works | — |
| `dev_or_test_system` | ✅ Works | — |
| `high_risk_port_exposed` | ❌ Never matches | Regex matches `entity_value` (e.g., `"1.2.3.4"`), not port attributes. IP values don't contain `:3389`. |
| `email_in_breach` | ❌ Never matches | Depends on breach monitor producing entities (it doesn't — only raw events). Even if it did, hostname entity values don't contain `@`. |
| `stale_certificate` | ❌ Never matches | Regex matches `entity_value` against `.*expired.*`, but certificate entity values are hex fingerprints, not human-readable text. |
| `outlier_country` | ❌ Fires for every IP | Collects ALL IP entities with no expected-country filter. Produces massive noise. |
| `subdomain_takeover_risk` | ❌ Fires for every hostname | Collects ALL hostname entities. No pre-filter for vulnerable CNAME patterns. |
| `certificate_expiry` | ⚠️ Partial | May work if certificate entities have `not_after` in attributes, but depends on cert pipeline (BUG-03). |
| `high_risk_service` | ⚠️ Partial | Depends on portscan results reaching entities. |

**Fix approach**:
1. `high_risk_port_exposed`: Match on port entity attributes, not on `entity_value`
2. `email_in_breach`: Fix breach monitor entity creation first (BUG-03 pattern), then fix regex to match email entities
3. `stale_certificate`: Match on certificate `not_after` attribute date, not on `entity_value` text
4. `outlier_country`: Add expected-country whitelist per target. Only fire for IPs outside expected countries.
5. `subdomain_takeover_risk`: Pre-filter hostnames for dangling CNAME records before running takeover fingerprints

---

### BUG-06: Certificate Findings Pipeline Is Dead Code

**Claimed**: Certificate analysis producing findings for expired, expiring, weak crypto, and unobserved certificates.

**Reality**: `certificates/findings.py` contains a well-written `certificate_inventory_to_findings()` function that produces 5 types of certificate findings. It has tests. It is exported. **No production code path calls it.**

**Fix approach**:
1. Wire `certificate_inventory_to_findings()` into the correlation engine or a scheduled job
2. Add a scheduled re-analysis of existing certificates (currently only analyzed once at discovery time)

---

### BUG-07: Enrichment API Keys Are Hardcoded Empty

**Claimed**: 6 external enrichment integrations (Shodan, AbuseIPDB, GreyNoise, Censys, SecurityTrails, Dehashed).

**Reality**: All 6 handlers hardcode API keys as `""` in the handler code. They are never read from config.yaml or environment variables. Users cannot configure them. The handlers silently no-op when the key is empty.

**Fix approach**:
1. Read API keys from config.yaml (enrichment section) or environment variables
2. Log a warning at startup when enrichment handlers have no configured keys
3. Surface enrichment key status in `/api/healthz`

---

## P0 — Capability Gaps (Blocking for Production Team Use)

### GAP-01: Authentication & API Token Management (was AUTH-01)

**Problem**: Zero access control. Anyone who can reach the UI can see the entire attack surface, trigger scans, modify config, and acknowledge alerts.

**Scope**:
- User accounts with password or OIDC login (start with single-admin, extend to multi-user)
- API token generation for programmatic access (read-only, read-write, admin scopes)
- Session management with token expiry
- Audit log of who triggered what (extend `runs` table with `user_id`)
- Auth middleware that doesn't block future RBAC extension

**Why P0**: The attack surface data IS an attack surface. Unauthorized access to your EASM inventory gives adversaries a roadmap.

---

### GAP-02: External Notification Routing (was NOTIFY-01)

**Problem**: Findings appear in the in-app alert feed and stay there. Critical findings (new subdomain takeover, CISA KEV vulnerability) have response times proportional to how often someone opens the dashboard.

**Scope**:
- Webhook dispatch on new findings (configurable per severity: critical/high → immediate, medium → digest)
- Slack/Teams integration via webhook (rich message with finding headline, severity, entity link)
- Email notification via SMTP (daily digest for medium, immediate for critical/high)
- PagerDuty/OpsGenie integration for critical findings
- Configurable routing rules: per-target, per-severity, per-rule-id notification channels
- Rate limiting to prevent alert fatigue (max N notifications per hour per channel)

**Config surface**:
```yaml
notifications:
  channels:
    - name: security-slack
      type: slack
      url: "${SLACK_WEBHOOK_URL}"
      min_severity: high
    - name: oncall-pagerduty
      type: pagerduty
      routing_key: "${PD_ROUTING_KEY}"
      min_severity: critical
    - name: daily-digest
      type: email
      to: ["security@example.com"]
      schedule: "0 9 * * *"
      min_severity: medium
```

**Why P0**: A security tool that requires manual checking is a security tool that gets ignored.

---

## P1 — Required for Team Adoption

### GAP-03: Remediation Workflow & Ticketing Integration (was REMED-01)

**Problem**: Findings get discovered, triaged, and then sit in the system. No accountability loop to drive them to resolution.

**Scope**:
- Jira integration: auto-create issue from finding with headline, severity, evidence, entity link
- GitHub Issues integration: same, for engineering teams
- ServiceNow integration: same, for enterprise IT
- Generic webhook: POST finding payload to any endpoint
- Finding ownership assignment (`assigned_to` field)
- SLA timers: configurable per severity (critical = 24h, high = 72h, medium = 7d)
- SLA breach detection and escalation
- Re-scan after remediation: trigger targeted re-evaluation of the entity's correlation rules
- Dashboard: open findings by age, SLA compliance rate, mean time to acknowledge, mean time to resolve

**Why P1**: The discovery-to-fix loop is the entire point of EASM. Without it, you're just cataloging risk, not reducing it.

---

### GAP-04: Real-Time Finding Forwarding (was SIEM-01)

**Problem**: The NDJSON export is batch-oriented. No real-time feed for SIEM/SOAR correlation.

**Scope**:
- Server-Sent Events (SSE) endpoint for new findings: `GET /api/findings/stream`
- Webhook registration: `POST /api/webhooks` with URL, secret, event types, min severity
- Structured finding payload compatible with common SIEM schemas
- Retry with exponential backoff for failed deliveries
- Delivery status tracking (last success, failure count, last error)

**Why P1**: Most security teams have existing SIEM/SOAR workflows. Open EASM findings need to flow INTO those systems, not require teams to check a separate dashboard.

---

### GAP-05: Alert-Level Confidence Scoring (was CONF-01)

**Problem**: The data layer has sophisticated confidence scoring (0-100 multi-factor), but findings don't reflect source reliability. A finding from Shodan (high-confidence infrastructure data) carries the same weight as a finding from a single DuckDuckGo result.

**Scope**:
- Propagate entity confidence score to findings
- Weight correlation rule output by source confidence: finding from high-confidence entity = higher priority
- Alert fatigue reduction: auto-suppress findings below configurable confidence threshold
- UI: show confidence badge on findings, filter by confidence level
- Finding priority formula: `priority = risk_score * confidence_weight`

**Why P1**: As attack surface grows, unweighted findings will drown analysts. Confidence scoring exists at the data layer — surface it at the finding layer.

---

### GAP-06: First-Seen vs. Stable Asset Classification (was DELTA-01)

**Problem**: Cannot distinguish "this port has been open for two years" from "this database port appeared at 3am last night." Both produce the same finding with the same severity.

**Scope**:
- `first_seen_at` already tracked on entities — surface it in finding evidence
- Asset lifecycle states: `new` (first 24h), `recent` (1-7d), `stable` (>7d), `changed` (attribute delta detected), `disappeared` (not re-observed after configurable window)
- Finding novelty scoring: finding on a `new` entity = higher priority than same finding on `stable` entity
- Delta detection: attribute-level change tracking (new port opened, technology changed, certificate renewed)
- Dashboard: "New this week" view showing only findings on recently-discovered or recently-changed assets

**Why P1**: Novel attack surface is always higher risk than long-standing infrastructure. Analysts need to know what's NEW, not just what EXISTS.

---

## P2 — Depth & Maturity

### GAP-07: Attack Path Modeling & MITRE ATT&CK Mapping (was ATTACK-01)

**Problem**: The platform knows WHAT is exposed but not HOW an adversary would chain findings into a compromise path.

**Scope**:
- Map correlation rules to MITRE ATT&CK techniques (e.g., `high_risk_port_exposed` → T1021.001 Remote Services, `subdomain_takeover_risk` → T1584.001 Compromise Infrastructure)
- Chain findings into attack paths: exposed SSH port + weak credential in breach data + no MFA indicator → full compromise path
- Risk score for attack paths: chain of medium findings can be higher risk than isolated critical finding
- Visualization: attack path overlay on the D3-force graph
- Report: "Top 5 most likely attack paths for target X"

**Why P2**: Moves from data ("here's what's exposed") to intelligence ("here's how an adversary would exploit it").

---

### GAP-08: Exploit Prediction Scoring Integration (was EPSS-01)

**Problem**: Vulnerability prioritization uses CVSS severity + CISA KEV only. A CVSS 9.8 with 0% EPSS (nobody's exploiting it) is treated the same as a CVSS 7.5 with 97% EPSS (actively being exploited).

**Scope**:
- Integrate FIRST EPSS API (free, daily-updated scores for all CVEs)
- Store EPSS scores alongside CVSS in `cve_cache` table
- Vulnerability priority formula: `vuln_priority = max(cvss_weight, kev_flag, epss_percentile)`
- EPSS threshold in correlation rules: finding severity boosted if EPSS > 0.5 (top 50th percentile)
- Dashboard: show EPSS percentile on vulnerability findings

**Why P2**: EPSS is the single most predictive metric for whether a CVE will be exploited. It's free, it's daily-updated, and it materially improves prioritization over CVSS alone.

---

### GAP-09: Supply Chain / Third-Party Risk Monitoring (was SUPPLY-01)

**Problem**: The platform monitors YOUR attack surface but not the attack surface of your dependencies. Third-party breach is a primary risk vector for most enterprises.

**Scope**:
- Third-party vendor tracking: configure vendor domains, SaaS providers, and critical dependencies
- Monitor vendor attack surface using existing discovery runners (subdomain, cert, port scanning — same pipeline, different target)
- Vendor security posture: track certificate hygiene, exposed services, breach mentions for vendors
- Alert when a vendor's attack surface changes (new subdomain, new exposed port, certificate expiry)
- Supply chain mapping: which of YOUR assets depend on which vendors (relationship graph)

**Config surface**:
```yaml
vendors:
  - id: aws
    name: Amazon Web Services
    domains: [amazonaws.com, aws.amazon.com]
    criticality: critical
  - id: okta
    name: Okta
    domains: [okta.com, login.okta.com]
    criticality: critical
```

**Why P2**: Your attack surface is only as secure as your weakest critical vendor.

---

## P3 — Polish & Enterprise Readiness

### GAP-10: Forensic Evidence Preservation (was EVIDENCE-01)

**Problem**: Screenshots are captured but there's no tamper-evident evidence storage. Cannot prove to regulators or legal counsel what the external attack surface looked like on a specific date.

**Scope**:
- Response header archiving for all HTTP-based discoveries
- Screenshot storage with content hash (SHA-256) and capture timestamp
- Hash chain: each new evidence artifact chained to previous for tamper detection
- Export package: zip/archive of all evidence for a finding with chain of custody metadata
- Retention policy: configurable retention per evidence type (screenshots: 90d, headers: 30d, raw events: indefinite)

**Why P3**: Necessary for regulated industries and incident response. Not blocking for most teams.

---

### GAP-11: API Attack Surface Discovery (was APISEC-01)

**Problem**: The platform discovers URLs from CommonCrawl and search engines but doesn't understand them as API endpoints. API attack surface is the fastest-growing category of external risk.

**Scope**:
- API endpoint fingerprinting: detect REST, GraphQL, gRPC, SOAP from response headers and content patterns
- OpenAPI/Swagger document discovery: scan for `/swagger.json`, `/openapi.json`, `/api-docs`
- API parameter extraction: from OpenAPI docs, from CommonCrawl URL patterns, from JavaScript bundle analysis
- API-specific correlation rules: unauthenticated API endpoint, excessive data exposure, missing rate limiting
- API inventory view: group endpoints by service, method, authentication requirement

**Why P3**: High-value but high-effort. Requires dedicated API parsing logic beyond current URL discovery.

---

### GAP-12: Multi-Tenancy & Business Unit Isolation (was MULTI-01)

**Problem**: Single `org_id` column exists but the API hardcodes a "default" org. Cannot isolate business units, subsidiaries, or clients.

**Scope**:
- Organization CRUD API: create, update, delete organizations
- Per-org target isolation: entities, findings, runs scoped to org
- Per-org user membership: users belong to one or more orgs with role-based access
- Per-org config: each org has its own targets, runners, alert rules
- Super-admin role: cross-org visibility for security leadership
- Data isolation: ensure no cross-org data leakage in API responses or graph views

**Why P3**: Architecturally prepped (org_id exists) but full multi-tenancy is a large surface area. Needed for MSSPs or large enterprises with subsidiaries.

---

### GAP-13: Historical Trending & Program Effectiveness Dashboards (was TREND-01)

**Problem**: No way to measure whether the security program is improving. "Are we finding things faster? Are we fixing things faster? Is our attack surface growing or shrinking?"

**Scope**:
- Time-series data: entity counts by type over time (daily/weekly/monthly)
- Finding metrics: mean time to acknowledge, mean time to resolve, finding volume by severity over time
- Attack surface trend: total assets, new assets, resolved assets per period
- Coverage metrics: percentage of assets with enrichment, percentage with risk scoring
- Dashboard: trend charts with configurable date ranges
- Export: CSV/JSON of trend data for executive reporting

**Why P3**: Important for program maturity and executive reporting, but not blocking daily operations.

---

### GAP-14: Compliance Framework Mapping (was COMPLY-01)

**Problem**: Cannot map findings to compliance frameworks. Security teams must manually translate EASM findings into CIS, NIST, or SOC2 language.

**Scope**:
- Map correlation rules to compliance controls:
  - `high_risk_port_exposed` → CIS 9.1, NIST SC-7, SOC2 CC6.1
  - `stale_certificate` → CIS 4.5, NIST SC-8, SOC2 CC6.7
  - `email_in_breach` → NIST IA-5, SOC2 CC6.1
- Compliance dashboard: findings grouped by framework and control
- Gap report: which controls have open findings vs. all-clear
- Export: compliance-ready finding report with control mapping

**Why P3**: Valuable for regulated industries but can be approximated manually in the near term.

---

## Explicitly Out of Scope

These were assessed and deliberately excluded:

| Capability | Reason |
|---|---|
| **Cloud API enumeration** (AWS DescribeInstances, Azure Resource Graph, GCP Cloud Asset Inventory) | Per product decision — cloud-native discovery outside current mission |
| Dark web monitoring | Requires Tor infrastructure; low signal-to-noise; explicitly out of scope in ROADMAP |
| Active web crawling/spidering | Architecture is passive-first; spidering is noisy and slow |
| DNS brute force / zone transfer | Invasive active techniques; subfinder covers passive subdomain discovery |
| Mobile app discovery | Separate discipline from infrastructure EASM |
