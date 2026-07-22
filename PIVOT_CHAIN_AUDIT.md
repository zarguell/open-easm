# Open EASM — Pivot Chain Audit Report

**Auditor:** Offensive Security Engineer / Attack Surface Mapping Specialist
**Scope:** Automated pivot chaining logic in `/Users/zach/localcode/open-easm`
**Date:** 2026-07-21
**Verdict:** The marketing claim — *"ASN → IP ranges → reverse DNS → hostnames → domain extraction → certificate search → new domains → repeat up to configurable depth"* — is **structurally accurate** for the happy path, but the pivot graph has **several dead-ends, one functional bug, and a class of standard EASM pivots that are entirely missing**. Real-world attack surface coverage is closer to **65–70%** of what a commercial EASM platform (Bitsight, Randori, Censys ASM) would produce.

---

## 1. Pivot Chain Graph

### 1.1 Edges Declared in `config.yaml.example` (`allowed_pivots`, lines 174–248)

```
                          ┌─────────────────────────────────────────────┐
                          │                                             │
                          │   RUNNERS (depth=0, seed via match_rules)   │
                          │                                             │
                          │   asnmap     → ASN, ip_range                │
                          │   subfinder  → hostname                     │
                          │   certstream → certificate, domain          │
                          │   crtsh      → certificate, domain          │
                          │   certspotter→ certificate, domain          │
                          │   commoncrawl→ domain (apex only — see §6.3)│
                          │   searchengine→ domain                      │
                          │   dnstwist   → domain (lookalike)           │
                          │   cloud_enum → domain (bucket hostname)     │
                          │   portscan   → hostname (open_ports attr)    │
                          │   screenshot → hostname (screenshot_path)   │
                          │   wappalyzer → hostname (technologies attr) │
                          │   nuclei     → hostname (vulnerability att) │
                          └────────────────────┬────────────────────────┘
                                               │
                                               ▼
┌──────────────┐  reverse_dns   ┌──────────────┐  dns_resolve  ┌──────────────┐
│     ASN      │ ◄───────────── │   IP_RANGE   │ ─────────────► │     IP       │
└──────────────┘                └──────────────┘                └──────┬───────┘
       ▲                                                              │
       │ ip_to_asn                                                    │
       │ (creates link only,                                          │
       │  no expansion)                                               │
       │                                                              │
       │    ┌─────────────────────────────────────────────────────────┤
       │    │                                                         │
       │    │  geoip_enrich       (self-loop, attr-only)              │
       │    │  shodan_enrich      (→ also hostnames, domains)         │
       │    │  greynoise_enrich   (self-loop, attr-only)              │
       │    │  abuseipdb_enrich   (self-loop, attr-only)              │
       │    │  censys_enrich      (self-loop, attr-only)              │
       │    │  cpe_vuln_enrich    (self-loop, attr-only,              │
       │    │                      auto-fired after shodan)           │
       │    │  reverse_dns        (cooldown 24h, → hostname)          │
       │    │                                                         │
       │    ▼                                                         │
       │  ┌──────────────┐                                           │
       │  │     IP       │  (self-enrichment; produces hostnames     │
       │  └──────────────┘   via shodan/reverse_dns only)            │
       │                                                              │
       │                                  dns_resolve (CNAME+A)      ▼
       │                              ┌────────────────────────────────┐
       │                              │           HOSTNAME             │
       │                              └────────────┬───────────────────┘
       │                                           │
       │             ┌─────────────────────────────┼──────────────────────────┐
       │             │                             │                          │
       │       domain_extract              tls_cert_grab             subdomain_takeover
       │             │                             │                  (cooldown 168h)
       │             ▼                             ▼
       │      ┌──────────────┐              ┌──────────────┐
       │      │    DOMAIN    │ ◄─────────── │  CERTIFICATE │
       │      └──────┬───────┘   SAN inline └──────────────┘
       │             │             (no cert→dom rule)
       │             │
       │     ┌───────┼─────────────────────────────────┐
       │     │       │                                 │
       │ crtsh_search  dns_mail_records              passive_dns
       │  (→ cert)   (→ MX hostnames inline)        (→ IPs inline)
       │     │                                         │
       │     ▼                                         ▼
       │  ┌──────────────┐                       ┌──────────────┐
       │  │  CERTIFICATE │                       │      IP      │
       │  └──────────────┘                       └──────────────┘
       │
       │  domain_rdap (self-loop, attr-only, cooldown 168h)
       │  reverse_whois (self-loop, cooldown 168h) — ⚠ OUTPUT SCHEMA MISSING (see §3.1)
       │  urlscan_enrich (self-loop, attr-only)
       ▼
   (terminal — no domain→domain expansion except crtsh SAN side-effect)
```

### 1.2 Edge Inventory (18 declared pivots, 4 source entity types)

| # | from | via | to | source_name | handler file:line | output_schema |
|---|------|-----|----|-------------|-------------------|---------------|
| 1 | `ip_range` | `reverse_dns` | `ip` | `reverse_dns` | `pivot/handlers/dns.py:66` | `schemas.py:278` ✓ |
| 2 | `hostname` | `dns_resolve` | `ip` | `dns` | `pivot/handlers/dns.py:29` | `schemas.py:240` ✓ |
| 3 | `hostname` | `domain_extract` | `domain` | `domain_extract` | `pivot/handlers/dns.py:95` | `schemas.py:293` ✓ |
| 4 | `domain` | `crtsh_search` | `certificate` | `crtsh` | `pivot/handlers/cert.py:156` | `schemas.py:89` ✓ |
| 5 | `domain` | `dns_mail_records` | `domain` | `dns_mail_records` | `pivot/handlers/dns.py:104` | `schemas.py:351` ✓ |
| 6 | `hostname` | `tls_cert_grab` | `certificate` | `tls_cert` | `pivot/handlers/cert.py:132` | `schemas.py:319` ✓ |
| 7 | `domain` | `domain_rdap` | `domain` | `domain_rdap` | `pivot/handlers/enrichment.py:259` | `schemas.py:602` ✓ |
| 8 | `ip` | `geoip_enrich` | `ip` | `geoip` | `pivot/handlers/enrichment.py:66` | `schemas.py:311` ✓ |
| 9 | `ip` | `greynoise_enrich` | `ip` | `greynoise` | `pivot/handlers/enrichment.py:439` | `schemas.py:424` ✓ |
| 10 | `ip` | `abuseipdb_enrich` | `ip` | `abuseipdb` | `pivot/handlers/enrichment.py:394` | `schemas.py:408` ✓ |
| 11 | `domain` | `urlscan_enrich` | `domain` | `urlscan` | `pivot/handlers/enrichment.py:478` | `schemas.py:437` ✓ |
| 12 | `ip` | `censys_enrich` | `ip` | `censys` | `pivot/handlers/enrichment.py:520` | `schemas.py:457` ✓ |
| 13 | `domain` | `reverse_whois` | `domain` | `reverse_whois` | `pivot/handlers/enrichment.py:227` | **✗ MISSING** (see §3.1) |
| 14 | `domain` | `passive_dns` | `ip` | `securitytrails` | `pivot/handlers/enrichment.py:107` | `schemas.py:470` ✓ |
| 15 | `hostname` | `subdomain_takeover` | `hostname` | `takeover` | `pivot/handlers/takeover.py:351` | `schemas.py:514` ✓ |
| 16 | `ip` | `shodan_enrich` | `ip` | `shodan` | `pivot/handlers/enrichment.py:336` | `schemas.py:377` ✓ |
| 17 | `ip` | `cpe_vuln_enrich` | `ip` | `cpe_vuln_enrich` | `vuln_enrichment.py` (auto-fired) | `schemas.py:618` ✓ |
| 18 | `ip` | `ip_to_asn` | `asn` | `ripe_stat` | `pivot/handlers/dns.py:166` | `schemas.py:559` ✓ |
| 19 | `ip` | `reverse_dns` | `hostname` | `reverse_dns` | (same handler as #1) | (same) ✓ |

### 1.3 Edges that SHOULD Exist but Don't

| Missing edge | What's lost |
|--------------|-------------|
| `certificate → domain via san_extract` | SAN domains discovered via `tls_cert_grab` are inlined by the output schema, but certs discovered by other means (manual upload, future runners) cannot re-pivot. |
| `asn → ip_range via asn_expand` | If `ip_to_asn` discovers a new ASN (e.g., a shadow ASN your org uses), there is no rule to expand it. The new ASN is a dead-end entity. |
| `hostname → port via port_probe` | Portscan output is a hostname attribute, never a `port` entity — no per-port pivots (e.g., grab TLS from 8443, probe 9200 Elasticsearch). |
| `hostname → technology via tech_extract` | Wappalyzer output is an attribute. No `technology` entity means no "find all assets running nginx 1.17 (CVE-2021-23017)" queries. |
| `domain → cloud_bucket via bucket_perms_probe` | `cloud_enum` finds a bucket but never enumerates contents, checks ACLs, or tests write access. |
| `ip → hostname via http_virtualhost_probe` | No reverse-vhost enumeration — `1.2.3.4` might serve 50 different vhosts; only PTR hostname is captured. |
| `hostname → js_endpoint via js_link_extract` | No JS file download/parsing; no endpoint extraction from bundles. |
| `hostname → favicon_hash via favhash` | No favicon extraction → no Shodan favhash search for sibling assets. |

---

## 2. Completeness Assessment by Phase

### ASN Coverage — **FULL** (with one caveat)
- `asnmap` runner enumerates all CIDR ranges for each configured ASN (`runners/registry.py:42`, `OUTPUT_SCHEMAS["asnmap"]` at `schemas.py:37`).
- Output produces ASN + ip_range entities + `owns` relationships (`schemas.py:42–53`).
- Pivot resolver fires on each new ip_range → enqueues `reverse_dns` per hop.
- **Caveat:** No `from: asn` pivot rule. If `ip_to_asn` (`pivot/handlers/dns.py:166`) discovers that an IP belongs to an ASN not in `match_rules.asns`, the new ASN entity is created but never expanded into ip_ranges. Shadow ASNs are dead-ends.

### IP Range Coverage — **PARTIAL**
- `reverse_dns` walks every host in a CIDR via `network.hosts()` with a 50-concurrency semaphore (`pivot/handlers/dns.py:73,90`).
- PTR records produce hostname entities with `reverse_of` relationship.
- **Gap:** No AXFR / DNS zone transfer attempt anywhere in the codebase. AXFR on misconfigured nameservers can reveal *internal* DNS records that passive PTR won't.
- **Gap:** No active ICMP/ARP sweep to find alive hosts in range before PTR — relies on DNS provider having reverse records configured (most cloud IPs don't).

### IP Coverage — **FULL** (enrichment), **PARTIAL** (expansion)
- Six enrichment pivots fire per IP: geoip, shodan, greynoise, abuseipdb, censys, cpe_vuln_enrich (auto-fired after shodan, `pivot/resolver.py:139–154`).
- `reverse_dns` (IP → hostname) fires with 24h cooldown.
- `ip_to_asn` creates ASN linkage.
- **Gap:** No `http_probe` pivot. A discovered IP with no PTR record and no open ports known is a dead-end unless Shodan has data. Real EASM tools actively probe top-100 ports.

### Hostname Coverage — **FULL** (DNS), **PARTIAL** (active)
- `dns_resolve` does both A and CNAME in one handler (`pivot/handlers/dns.py:29`).
- `domain_extract` derives apex domain.
- `tls_cert_grab` does live TLS handshake, parses full cert, extracts SAN (`pivot/handlers/cert.py:132`).
- `subdomain_takeover` collects a comprehensive DNS graph + HTTP probe + RDAP check (`pivot/handlers/takeover.py:351`).
- **Gap:** `dns_resolve` only does ONE CNAME lookup. The full CNAME chain traversal is only inside `takeover_detect._dns_chain` (`pivot/handlers/takeover.py:159`), which stores it as an *attribute*, not as separate hostname entities with relationships. So if `www.example.com → lb.example.net → cdn.fastly.net`, only the first hop feeds back into the pivot graph.
- **Gap:** No HTTP probe pivot to capture redirect chains, response headers (Server, X-Powered-By), or body content.
- **Gap:** Screenshot runner only iterates `target.match_rules.domains`, NOT discovered hostnames (`screenshot_runner.py:41`). 95% of discovered subdomains never get screenshotted.

### Domain Coverage — **PARTIAL**
- `crtsh_search` returns historical certs; output schema extracts SAN domains as new entities (`schemas.py:111–116`).
- `dns_mail_records` extracts MX exchange hostnames (`schemas.py:368–373`).
- `passive_dns` (SecurityTrails) returns historical A records with IPs (`schemas.py:479–487`).
- **Gap:** `reverse_whois` is functionally broken — see §3.1.
- **Gap:** No SPF `include:` recursive expansion. If SPF is `v=spf1 include:_spf.google.com include:mailgun.org ~all`, the include targets are stored as a string, not parsed into lookups. Mail-provider attribution is done (`schemas.py:365` via `classify_mail_provider`), but the SPF-INCLUDED domains are never pivoted.
- **Gap:** No DMARC `rua=`/`ruf=` report URI parsing — these reveal third-party mail vendors.

### Certificate Coverage — **FULL** (data), **PARTIAL** (graph)
- Two pivots produce certs: `crtsh_search` and `tls_cert_grab`. Both extract full profile: subject/issuer, SAN, key info, EKU, signature algorithm, basic constraints (`pivot/handlers/cert.py:28–129`).
- Certificate profile analysis via `analyze_certificate_profile` runs at schema time.
- **Gap:** No `certificate → domain` pivot rule. SAN domain extraction happens *inline* in the cert output schema (`schemas.py:111–116` for crtsh, `schemas.py:343–347` for tls_cert). If a cert entity is laterally discovered by any other means (manual, future runner), no SAN extraction fires.

### Cloud Coverage — **PARTIAL**
- `cloud_enum` checks AWS S3, GCS, Azure Blob with prefix permutations (`cloud_bucket_runner.py:17–46`).
- Buckets are stored as `domain` entities with provider/public_access attributes (`schemas/cloud_enum.yaml`).
- **Gap:** No bucket content enumeration. `public_list=True` is recorded but no pivot fetches the actual object listing (which is what reveals sensitive data exposures).
- **Gap:** No follow-up to check bucket write access, versioning configuration, or bucket policy.
- **Gap:** The bucket hostname (`bucket.s3.amazonaws.com`) is created as a `domain` entity. Domain-level pivots (`crtsh_search`, `dns_mail_records`) fire uselessly on this. No recognition that this is a bucket, not a domain.

### Port Scan Coverage — **PARTIAL**
- `portscan` runner uses `nmap -Pn -sV --open` with a quick port list (`portscan_runner.py:74–77`).
- Output stored as `open_ports` attribute on hostname entity; ip entity also created with ports (`schemas.py:163–175`).
- **Gap:** No `port` entity type in `EntityType` enum (`models.py:19–26`). Cannot model "find all assets with port 9200 open."
- **Gap:** No per-port pivots. When 443 is found, no automatic TLS cert grab fires (a separate `tls_cert_grab` pivot will eventually run from the hostname, but the correlation isn't explicit).
- **Gap:** Correlation rule `high_risk_port_exposed.yaml` exists, but ports are never correlated with CVEs / service versions in a structured way.

### Technology Fingerprinting — **PARTIAL**
- `wappalyzer` (actually `webanalyze` binary) runs against discovered hostnames (`registry.py:149`).
- Technologies stored as a list attribute (`schemas.py:138–143`).
- **Gap:** No `technology` entity. Cannot model "all assets running nginx 1.17."
- **Gap:** `cpe_vuln_enrich` is auto-fired after `shodan_enrich` only (`pivot/resolver.py:139`). When `wappalyzer` discovers a tech, no CPE→CVE enrichment fires. Major miss — wappalyzer is the most accurate source for tech versions, but its findings never reach the vuln-enrichment pipeline.

---

## 3. Gap Analysis: Missing or Broken Pivot Types

### 3.1 **BUG: `reverse_whois` output schema is missing** — Critical

**File:** `src/easm/runners/schemas.py` (and absence in `src/easm/runners/schemas/`)

The `reverse_whois` handler returns valid data (`pivot/handlers/enrichment.py:255–256`):
```python
return [{"domain": domain, "reverse_whois": {
    "related_domains": list(set(domains)), "dates_found": registrars}}]
```

But `OUTPUT_SCHEMAS` has **no `"reverse_whois"` key**. The python `python_schemas` dict (`schemas.py:666–678`) and `_python_schemas` dict (`schema_engine.py:254–273`) both omit it. No YAML file exists at `schemas/reverse_whois.yaml`.

**Impact:** In `tasks/pivot.py:150–152`, `schema_fn = OUTPUT_SCHEMAS.get("reverse_whois")` returns `None`, the `if schema_fn:` branch is skipped, and the discovered related domains **never become entities**. The raw_event is saved (audit-logged) but the graph is never updated. The pivot silently does nothing visible.

**Why it matters:** Reverse WHOIS is one of the highest-signal pivots in EASM — it discovers related domains registered by the same email, which is how shadow IT, acquisition domains, and lookalike domains are typically found.

**Fix effort:** 30 minutes. Add a python schema:
```python
def reverse_whois(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    rw = raw.get("reverse_whois", {})
    related = rw.get("related_domains", [])
    if not domain or not related:
        return [], []
    nd = normalize_entity_value("domain", domain)
    entities = [EntityCandidate("domain", nd, {
        "source": "reverse_whois",
        "reverse_whois_dates": rw.get("dates_found", []),
    })]
    rels = []
    for d in related:
        nd_rel = normalize_entity_value("domain", d)
        entities.append(EntityCandidate("domain", nd_rel, {"source": "reverse_whois"}))
        rels.append(RelationshipCandidate("domain", nd, "domain", nd_rel, "reverse_whois_match", "pivot"))
    return entities, rels
```
Then register in `_python_schemas` dict.

### 3.2 Missing: HTTP Body / Link Extraction Pivot

**What it would discover:** URLs, endpoints, JS file URLs, email addresses, API endpoints referenced in HTML/JS, comments containing internal hostnames, `robots.txt`/`sitemap.xml` content.

**Why it matters:** A single HTTP GET to a discovered hostname typically exposes 10–100× more attack surface than passive DNS. This is the foundational technique behind tools like `katana`, `hakrawler`, `gospider`. Without it, Open EASM cannot discover:
- API endpoints referenced in single-page apps
- Internal hostnames leaked in comments or JS bundles
- Staging URLs in `robots.txt`
- S3 bucket URLs in image src tags
- Trackers/analytics IDs (see §3.5)

**Current behavior:** `http_runner.standard_http_run` (`http_runner.py:22`) discards response body — only JSON-parsable records from APIs are processed. CommonCrawl runner (`registry.py:379`) only extracts URLs that Common Crawl already indexed, not live HTTP responses.

**Fix effort:** Medium (2–3 days). New `http_probe` pivot handler that fetches the URL, parses for:
- `<a href>`, `<script src>`, `<link>`, `<form action>`
- `robots.txt`, `sitemap.xml`, `crossdomain.xml`, `clientaccesspolicy.xml`
- Regex for endpoints in inline JS
- Regex for cloud bucket URLs (S3, GCS, Azure)
- Regex for tracker IDs (UA-, GTM-, AW-, facebook pixel)

### 3.3 Missing: DNS Zone Transfer (AXFR) Pivot

**What it would discover:** Full DNS zone contents, including internal-only hostnames, when nameservers are misconfigured to allow zone transfer.

**Why it matters:** AXFR is a high-severity finding on its own (it's an information disclosure) AND produces the most complete hostname enumeration possible for a zone. Commercial EASM platforms attempt AXFR against all authoritative nameservers for in-scope domains.

**Current behavior:** Nowhere in the codebase is `dns.query.xfr` or `dns.zone.from_xfr` called. Searched: no occurrences.

**Fix effort:** Small (4–6 hours). New `axfr_attempt` pivot handler that:
1. Resolves NS records for the domain
2. Attempts TCP AXFR against each NS
3. If successful, parses the zone and creates hostname entities for every record

### 3.4 Missing: Favicon Hash Pivot

**What it would discover:** Sibling assets across the internet that share the same favicon hash. Shodan indexes favicons and supports `http.favicon.hash:<int>` search.

**Why it matters:** Favicon hash is one of the strongest attribution signals in EASM. If your company's main site has favicon hash `-12345678`, a Shodan search for that hash typically reveals 5–50 additional assets (dev environments, acquisition properties, third-party-hosted landing pages) that have no other obvious link to your org.

**Current behavior:** No favicon extraction. Searched: zero occurrences of "favicon" in `src/easm/`.

**Fix effort:** Small (1 day). New `favicon_hash` pivot:
1. From hostname, fetch `/favicon.ico`
2. Compute mmh3 hash (the format Shodan expects)
3. Query Shodan `search` API for `http.favicon.hash:<hash>`
4. Create new IP/hostname entities for each result

### 3.5 Missing: Tracker / Advertising ID Pivot

**What it would discover:** Google Analytics IDs (`UA-XXXX`, `G-XXXX`), Google Tag Manager containers (`GTM-XXXX`), Facebook Pixels, Adobe Analytics IDs, Bing Webmaster verification codes.

**Why it matters:** Assets that share a tracker ID are owned by the same organization. This is how security researchers find acquisitions, shadow IT, and dev environments. For example: a single GA tracker `UA-12345-6` appearing on 50 different hostnames proves org ownership of all 50.

**Current behavior:** Not implemented. Searched: zero occurrences.

**Fix effort:** Small (1 day). Best implemented as part of the HTTP body extraction pivot (§3.2). Trackers are extracted via regex from the response body and become `tracker_id` entities with relationships to the hostnames where they appear.

### 3.6 Missing: CNAME Chain as Graph Edges

**What it would discover:** CDN/WAF intermediaries, SaaS hosting providers, takeover-vulnerable terminal targets.

**Current behavior:** `takeover_detect._dns_chain` (`pivot/handlers/takeover.py:159–198`) follows the full CNAME chain (up to 10 hops) but stores the result as an attribute on a single hostname entity. The intermediate and terminal hostnames do not become separate entities with relationships.

**Fix effort:** Small (4 hours). Update the `subdomain_takeover` output schema to:
1. Create a hostname entity for each CNAME hop
2. Create `cname_to` relationships between consecutive hops
3. The terminal hostname (often a SaaS domain like `xxx.amazonaws.com`) becomes a first-class entity

### 3.7 Missing: Bucket Content Enumeration Pivot

**What it would discover:** Public S3/GCS/Azure object listings — typically reveals database backups, credentials files, source code, PII.

**Current behavior:** `cloud_enum` records `public_list=True` but never lists contents (`cloud_bucket_runner.py:103–114`).

**Fix effort:** Small (6 hours). New `bucket_list` pivot:
- `from: domain` (where attributes indicate cloud_enum source)
- Fetches the bucket's XML object listing (`?list-type=2`)
- Parses keys, creates `bucket_object` entities (or stores as attribute)
- Tags sensitive file extensions (`.sql`, `.bak`, `.env`, `.pem`) for correlation alerts

### 3.8 Missing: Wappalyzer → CPE → CVE Pivot Bridge

**What it would discover:** Known-vulnerable software versions running on discovered hostnames.

**Current behavior:** `cpe_vuln_enrich` is auto-fired only after `shodan_enrich` (`pivot/resolver.py:139`). When `wappalyzer` detects "nginx 1.17.0", the CPE (`cpe:2.3:a:nginx:nginx:1.17.0`) is never computed, and the CVE match never runs.

**Fix effort:** Small (2 hours). Either:
- Add a `wappalyzer_cpe` output to the wappalyzer schema that computes CPEs from technology name+version, or
- Fire `cpe_vuln_enrich` as a post-runner pivot on any hostname that has wappalyzer tech data.

### 3.9 Missing: SPF Include Recursion

**What it would discover:** Third-party mail vendors (Google, Microsoft, Mailgun, SendGrid) and their infrastructure.

**Current behavior:** SPF is parsed for `v=spf1` prefix only (`pivot/handlers/dns.py:117–122`). The `include:` mechanisms are not recursively resolved.

**Fix effort:** Small (4 hours). When `dns_mail_records` encounters SPF with `include:domain.com`, the include target should become a domain entity that re-fires `dns_mail_records`.

---

## 4. Blind Spots — Assets the Pivot Chain WILL NOT Discover

| Asset class | Why it's missed | Example |
|-------------|-----------------|---------|
| **Virtual hosts on shared IPs** | No HTTP `Host:` header probing against discovered IPs. A single AWS ELB IP may serve 200 vhosts; only the PTR hostname is captured. | `1.2.3.4` serves `app.example.com` (captured) + `api-staging.example.com` (NOT captured) + `marketing-landing.example.com` (NOT captured) |
| **JS-bundled endpoints** | No JS file extraction. Single-page apps hide 90% of their endpoints in `main.js`. | `https://app.example.com/main.js` contains `fetch('/api/v2/internal/users')` — never discovered |
| **Cloud resources via tracker IDs** | No tracker ID extraction. | `UA-12345-67` on `shadow-site.example.com` proves org ownership but is never parsed |
| **Internal hostnames leaked via AXFR** | No zone transfer attempt. | `internal-db.corp.example.com` exists in zone file, never in PTR |
| **Acquisition domains via reverse WHOIS** | Pivot runs but output schema is missing (§3.1). | `newco-acquired.com` registered by same email — handler fetches the data, schema drops it |
| **S3 bucket contents** | Bucket found but never listed. | `company-backups.s3.amazonaws.com` is detected as public_list=True but contents (5GB of SQL dumps) never examined |
| **Sibling assets via favicon** | No favicon hash search. | `dev.internal.corp` shares favicon hash with public `corp.com` — invisible to current pivots |
| **Subdomains behind WAF** | Passive DNS only; WAF-proxied subdomains rarely appear in PTR or CT logs. | `protected.example.com` is fronted by Cloudflare; its real origin IP never appears in any passive source |
| **Non-standard ports** | Quick nmap profile only scans 11 ports (`portscan_runner.py:15`). | Elasticsearch on port 9200 is in default list, but Solr (8983), CouchDB (5984), and many others are not |
| **Discovered hostnames (visual)** | Screenshot runner iterates only `match_rules.domains`, not the discovered hostname table (`screenshot_runner.py:41`). | `staging.example.com` is discovered by subfinder but never screenshotted |
| **Cert SANs from non-CT sources** | Only crtsh and live TLS are sources. Certs from internal CAs or non-CT-logged CAs are invisible. | Internal CA-issued cert for `intranet.example.com` |
| **IPs from passive DNS without forward records** | Reverse DNS requires PTR configured. Cloud IPs (AWS, GCP) usually don't have PTR. | EC2 instance `3.4.5.6` running `staging-api.example.com` — never found via reverse DNS |

---

## 5. Chain Depth & Loop Protection

### 5.1 Configurable Max Depth — **Implemented correctly**

- **Config:** `PivotConfig.max_depth` defaults to 3 (`config.py:89`), example config sets 4 (`config.yaml.example:172`).
- **Check:** `pivot/resolver.py:25` — `if depth > pivot_config.max_depth: return`. Clean early-return, no orphaned state.
- **Increment:** `tasks/pivot.py:268` — recursive `check_and_enqueue` call uses `depth=depth + 1`.
- **Initial depth:** Runner ingestion calls resolver with `depth=1` (`runners/ingestion.py:215`). So `max_depth=4` permits 4 levels of post-runner pivots.

### 5.2 Diamond Dependencies (A→B→C→A) — **Handled**

- `tasks/pivot.py:262` — `if is_new and target_config:` — pivots only fire when `store.upsert_entity` returns `is_new=True`.
- First-write-wins semantics on entity uniqueness (per `org_id + target_id + entity_type + entity_value`).
- If A is rediscovered via a longer path, the upsert returns `is_new=False` and no pivot fires.

### 5.3 Same-Entity Rediscovery (A→B→A) — **Handled**

- Same mechanism as §5.2. When B's pivot produces A, A already exists, `is_new=False`, no pivot.
- **Bonus:** `_check_cooldown` (`pivot/resolver.py:175–189`) adds a time-based guard — even if the entity is new, the same `(entity_type, entity_value, pivot_type)` triple won't re-run within `cooldown_hours`.

### 5.4 Queue Overflow — **Handled**

- `pivot/resolver.py:38–54` — checks pivot queue depth against `max_queue_depth` (default 10000, `config.py:93`).
- At capacity, logs warning and skips enqueue. No crash, no memory growth.

### 5.5 Apex Coverage Optimization — **Implemented**

- `pivot/resolver.py:82–99` — if `CoverageConfig.apex_covers_subdomains=True` and the apex domain has already been pivoted via `via`, subdomains of that apex skip the same pivot.
- **Default is `False`** (`config.py:75`), so this opt-in only helps users who explicitly enable it.

### 5.6 Source-Based Skipping — **Implemented**

- `pivot/resolver.py:60–80` — `skip_on_source` allows a pivot rule to skip entities whose `source` attribute matches (e.g., skip `crtsh_search` for domains already discovered by `certstream`, since the cert data is already in hand).
- Not configured by default in `config.yaml.example`.

### 5.7 What Happens at Max Depth — **Clean stop**

- Resolver returns without enqueueing. The discovered entity is already saved in DB (upsert happened before resolver call). The raw_event is already saved. No orphaned state.
- The entity's `is_first_discovery=True` flag is preserved, so it still counts in run statistics.
- **Minor issue:** No explicit logging when max_depth blocks a pivot. If a user is confused why pivots stopped, there's no log entry to explain. The `logger.debug` calls in resolver use `exc_info` liberally but never log "depth limit reached" specifically.

### 5.8 Priority System — **Implemented**

- `pivot/resolver.py:112–121` — hard-coded priority map:
  ```python
  _priority = {
      "dns_resolve": 100, "reverse_dns": 80,
      "takeover_detect": 70, "subdomain_takeover": 70,
      "domain_extract": 60, "geoip_enrich": 50,
      "dns_mail_records": 40, "ip_to_asn": 40,
  }.get(pivot_rule.via, 10)
  ```
- Fast/cheap pivots (DNS) get priority 100; slow API calls default to 10.
- Procrastinate respects priority when dequeuing from the `pivot` queue.
- **Gap:** The priority is hard-coded, not configurable. Users with slow Shodan but fast SecurityTrails cannot reorder.

### 5.9 Concurrency — **Limited**

- Worker runs with `concurrency=3` across three queues (`worker.py:48–52`).
- `PivotConfig.max_concurrent=3` is defined (`config.py:90`) but **never enforced** — searched the codebase, no usage of `max_concurrent` outside the model definition.
- Per-handler rate limiters exist for external APIs (Shodan, AbuseIPDB, etc. — see `rate_limiter.py`).
- DNS handlers use semaphores: 50 concurrent for reverse_dns (`dns.py:73`), 50 for `_ptr`.

---

## 6. Scope Evaluator Analysis

**File:** `src/easm/pivot/scope.py` (31 lines total)

### 6.1 Implemented Entity Types

| Entity type | Scope logic | Behavior |
|-------------|-------------|----------|
| `domain` | Suffix match against `match_rules.domains` | In/out of scope |
| `hostname` | Suffix match against `match_rules.domains` | In/out of scope |
| `asn` | Normalized equality against `match_rules.asns` | In/out of scope |
| `ip`, `ip_range` | `subnet_of` check against `match_rules.ip_ranges` | In/out of scope |

### 6.2 Unhandled Entity Types (returns `UNKNOWN`)

| Entity type | Returned | Effect (strict mode) | Effect (permissive mode) |
|-------------|----------|---------------------|--------------------------|
| `certificate` | UNKNOWN | Treated as in-scope (not OUT_OF_SCOPE) | Treated as in-scope |
| `org` | UNKNOWN | Same | Same |

Since `EntityType` has only 7 values (`models.py:19–26`) and 4 are handled, only `certificate` and `org` fall through. Both default to allowed.

### 6.3 Scope Mode Interaction

- `scope_mode: strict` (default, `config.py:92`) — only blocks pivots when scope evaluator returns `OUT_OF_SCOPE`. `UNKNOWN` is permitted.
- `scope_mode: permissive` — never blocks.
- **Behavior is correct** for most cases. However, if a user adds a custom entity type in the future, it will silently bypass scope.

### 6.4 Other Resolver-Level Guards

In addition to scope, the resolver checks (`pivot/resolver.py:34–36`):
```python
classification = await self._get_classification(entity_id)
if classification and classification != "org-owned":
    return
```

This means **any entity classified as `saas-hosted` or `third-party-integrated` is blocked from pivoting**, regardless of scope. This is intentional — it prevents pivoting into AWS/Azure/GCP infrastructure and burning quota on Shodan lookups for `*.cloudfront.net`. But it's aggressive: a SaaS-hosted asset that's still owned by the org (e.g., a Heroku app the org controls) won't get pivoted.

---

## 7. Priority Fixes — Ranked by Threat Surface Impact

### Priority 1: **Fix the `reverse_whois` output schema** (§3.1)
- **Impact:** Reverse WHOIS is one of the highest-signal EASM pivots. It's currently running, fetching data, and silently discarding the results.
- **Effort:** 30 minutes.
- **File:** `src/easm/runners/schemas.py` — add `reverse_whois()` function and register in both `_init_output_schemas()` and `build_output_schemas()`.

### Priority 2: **Add HTTP body / link extraction pivot** (§3.2)
- **Impact:** Single highest-yield pivot in real EASM engagements. Discovers JS-bundled endpoints, leaked internal hostnames, cloud bucket URLs, and tracker IDs in one pass.
- **Effort:** 2–3 days.
- **Implementation:** New `http_probe` pivot handler + new `endpoint`, `tracker_id` entity types (or attributes if entity type expansion is undesirable).

### Priority 3: **Fix `screenshot` runner scope** (§3.3 — discovery gap)
- **Impact:** Currently screenshots only the configured root domains, missing 95%+ of discovered subdomains. The visual inventory is essentially useless for the discovered attack surface.
- **Effort:** 1 hour.
- **File:** `src/easm/runners/screenshot_runner.py:41` — change `for domain in target.match_rules.domains:` to query discovered hostnames (mirror `portscan_runner._get_scan_targets`).

### Priority 4: **Add favicon hash pivot** (§3.4)
- **Impact:** Discovers sibling assets with no other observable connection to the org. Often reveals acquisitions, dev environments, and shadow IT in a single Shodan query.
- **Effort:** 1 day.
- **Implementation:** New `favicon_hash` pivot from `hostname`; query Shodan `search` API.

### Priority 5: **Bridge `wappalyzer` → `cpe_vuln_enrich`** (§3.8)
- **Impact:** Wappalyzer is the most accurate technology detection source, but its findings never reach the CVE-matching pipeline. vuln coverage is limited to whatever Shodan's InternetDB returns.
- **Effort:** 2 hours.
- **Implementation:** Either fire `cpe_vuln_enrich` after `wappalyzer` runner completes, or compute CPE strings in the wappalyzer output schema and let the existing enrichment pick them up.

---

## 8. Summary

| Aspect | Rating | Notes |
|--------|--------|-------|
| ASN → IP enumeration | **FULL** | asnmap + reverse_dns chain works. No AXFR. |
| IP enrichment | **FULL** | 6 enrichment pivots + cooldown + rate limit. |
| Hostname enrichment | **FULL** | DNS, cert, takeover, geo, threat intel all covered. |
| Domain pivoting | **PARTIAL** | reverse_whois broken; SPF recursion missing. |
| Certificate pivoting | **PARTIAL** | SAN extraction inline only; no `cert → domain` rule. |
| Cloud enumeration | **PARTIAL** | Finds buckets but doesn't list contents. |
| Port-level modeling | **MISSING** | No port entities; no per-port pivots. |
| Tech fingerprinting | **PARTIAL** | wappalyzer runs but doesn't bridge to vuln enrichment. |
| HTTP content analysis | **MISSING** | No link/JS/tracker extraction. |
| Favicon hash | **MISSING** | Standard EASM technique, absent. |
| AXFR | **MISSING** | Standard EASM technique, absent. |
| Chain depth control | **FULL** | max_depth + is_new + cooldown + apex_coverage. |
| Loop protection | **FULL** | Diamond and rediscovery handled via first-write-wins. |
| Scope evaluation | **ADEQUATE** | 4/7 entity types handled; UNKNOWN permitted. |
| Queue/capacity protection | **FULL** | max_queue_depth guard + per-handler rate limiters. |

**Bottom line:** The pivot chain is architecturally sound and the loop/depth/capacity protections are well-designed. The two real defects are (1) a silent data-loss bug in `reverse_whois` and (2) a discovery gap where the screenshot runner ignores its own discovered asset table. The strategic gaps are HTTP body analysis (which would unlock several other missing pivots as side effects) and the absence of `port`/`technology` entity types, which limits the ability to model the attack surface at the granularity that commercial EASM platforms achieve.
