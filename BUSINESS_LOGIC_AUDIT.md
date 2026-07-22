# Open EASM — Business Logic Efficacy Audit

> **Does the product actually do what it claims?**
> Synthesized from 4 specialist reports: Takeover Detection, Correlation Rules, Pivot Chain, Runner Schemas.

---

## Executive Summary

**The product has the right plumbing but produces a significantly wrong picture of the attack surface.** It finds *some* of the right things but drowns defenders in noise and misses structural attack vectors.

Three categories of issue:

| Category | Count | Impact |
|---|---|---|
| **Confirmed bugs** (code does the wrong thing) | 8 | Silently corrupt data or produce garbage findings |
| **Structural blind spots** (standard EASM techniques absent) | 12 | 30-40% of typical attack surface invisible |
| **Noise amplifiers** (design patterns that bury real signals) | 7 | Estimated 80%+ of HIGH findings are false positives |

**Scorecard:**

| Dimension | Score | vs Commercial EASM |
|---|---|---|
| Discovery coverage | 5/10 | Missing JS endpoints, favicon, SPF graph, bucket content, AXFR |
| Pivot graph completeness | 6/10 | reverse_whois output lost, screenshot misses 95% of surface |
| Data accuracy | 3/10 | 5 broken YAML schemas, garbage cert entities, no IP canonicalization |
| Detection actionability | 2/10 | Always HIGH, no dedup, stale_certificate fires on everything |
| Real-world deployability | 4/10 | outlier_country broken, dev regex too greedy, SSH 22 = high risk |

---

## Confirmed Bugs (8)

These are not design tradeoffs — the code does the wrong thing.

### Bug 1: 5 YAML schemas silently shadow working Python schemas with broken data

**Location:** `src/easm/runners/schemas/` (all 5 files), `src/easm/runners/schema_engine.py:99-102`

**Root cause:** `_init_output_schemas()` loads YAML schemas first, then only adds Python schemas for names NOT already in the dict. YAML always wins. The YAML engine uses `$raw.X` placeholders that silently produce literal strings when the field doesn't exist (`schema_engine.py:99-102`: `raw.get(raw_key, ref)` returns the literal placeholder string as fallback).

| YAML file | Bug | What's lost |
|---|---|---|
| `nuclei.yaml` | `vulnerability: "$raw.vulnerability"` — nuclei JSON has no `vulnerability` field | `template-id`, `info.name`, `info.severity`, `info.description`, `info.cvss-score`, `matched-at`, `extracted-results`, `curl-command`. **Entire vuln scanner output reduced to a hostname with junk attribute.** |
| `rdap.yaml` | `rdap: "$raw.rdap"` — RDAP handler returns flat dict, no `rdap` key | ASN name, country, CIDR range, handle, org. **WHOIS enrichment produces no data.** |
| `cpe_vuln_enrich.yaml` | `type: hostname` hardcoded — ignores `raw.entity_type` | CPE/CVE enrichments for IPs (most common case) create `hostname` entities with IP values. |
| `commoncrawl.yaml` | `value_from: domain` where `domain` is the **seed domain** queried, not the URL host | Never extracts subdomains from page URLs. **Runner produces zero new entities.** |
| `cloud_enum.yaml` | `value_from: bucket_url` with `normalize: false` | Stores entire URLs like `https://s3.amazonaws.com/x/` as domain entity values. |

**Verification:** All confirmed by running the actual schema engine against sample data. All 5 YAML files were created in this remediation (commit `31e4329`) and have never been tested against real tool output.

**Priority:** 🔴 **Critical** — Fix immediately. YAML schemas should verify required raw fields exist or fall through to Python functions.

---

### Bug 2: CertStream parser creates garbage domain entities

**Location:** `src/easm/runners/schemas.py:194-207`

**Root cause:** Real CertStream `subjectAltName` entries include `"IP Address:1.2.3.4"` strings. The parser splits on `,`, strips `DNS:` prefix, but does not strip `IP Address:` or `ip address:` prefixes.

**Verified output from real CertStream data:**
```
Entity: domain, value: "ip address:1.2.3.4"
Entity: domain, value: "*.wildcard.example.com"
Entity: domain, value: "ip address:5.6.7.8"
```

These are stored as real `domain` entities, trigger pivots, and go through correlation rules. Every certstream cycle (real-time, continuous) adds garbage to the entity store.

**Priority:** 🔴 **Critical** — Filter out `IP Address:` entries and expand wildcards.

---

### Bug 3: reverse_whois pivot runs but silently discards results

**Location:** `src/easm/pivot/handlers/__init__.py:41` (registered as handler), `src/easm/runners/schemas.py:687` (OUTPUT_SCHEMAS dict — no `"reverse_whois"` key)

**Root cause:** The `reverse_whois` handler (`enrichment.py:245-265`) fetches and returns related domains. The pivot worker (`tasks/pivot.py:150`) calls `OUTPUT_SCHEMAS.get(source_name)` which returns `None` because no schema is registered for `"reverse_whois"`. The related domains are saved as `raw_events` (audit log) but never become entities — no graph edges, no pivots, no findings.

**Priority:** 🔴 **Critical** — Add a 3-line output schema that extracts related domains as `domain` entities.

---

### Bug 4: Screenshot runner ignores discovered hostnames

**Location:** `src/easm/runners/screenshot_runner.py:41`

**Root cause:** The `iterate_over` parameter is `"domains"` which iterates `target.match_rules.domains` — the seed domains from config. Discovered subdomains from subfinder, crtsh, commoncrawl, etc. are never screenshotted. An organization with 1,000 discovered hostnames and 3 seed domains screenshots only 3 pages.

**Verified:** `ScreenshotRunner` defines `iterate_over(iterate_config)` which calls `iterate_domains(target)` not `iterate_hostnames_x2(target)`.

**Priority:** 🟡 **High** — Change to `iterate_hostnames_x2` to cover the full attack surface.

---

### Bug 5: outlier_country rule is broken — field path mismatch

**Location:** `correlations/outlier_country.yaml:9` (checks `attributes.country_code`)

**Root cause:** The geoip enrichment stores country at `attributes.geo.country_code` (nested), but the rule checks `attributes.country_code` (top-level). The `_field_to_sql` function (`engine.py:191-193`) converts `attributes.country_code` to `attributes->>'country_code'` — which is always NULL because the data is at `attributes->'geo'->>'country_code'`.

**Priority:** 🟡 **High** — Fix field path. Also make allowed countries per-target configurable (currently hardcoded US/CA/GB).

---

### Bug 6: stale_certificate rule fires on EVERY certificate

**Location:** `correlations/stale_certificate.yaml:10` (just checks `entity_type = certificate`)

**Root cause:** The YAML rule matches ANY certificate entity regardless of expiration state. The real certificate analysis lives in `src/easm/certificates/findings.py` which produces 5 distinct findings with proper risk levels (expired→critical, expiring within 7d→high, weak crypto→high, etc.). The YAML rule is a duplicate that fires on all certs.

**Priority:** 🟡 **High** — Delete the YAML rule. The Python-side analysis is correct.

---

### Bug 7: normalize_entity_value() has no IP canonicalization

**Location:** `src/easm/entity_store.py:8-26`

**Verified issues:**
- `203.0.113.005` and `203.0.113.5` → different entities (same IP)
- `2001:db8::1` and `2001:0db8::1` → different entities (same IPv6, not RFC 5952-canonicalized)
- `1.2.3.4:443` and `1.2.3.4` → different entities (IP:port not stripped)
- `AS15169` and `ASN15169` → different entities (ASN prefix not normalized)
- `*.example.com` → literal entity value (wildcard not expanded)
- `"example.com"` → literal entity value with quotes (not stripped)

**Priority:** 🟡 **High** — Add proper canonicalization per entity type.

---

### Bug 8: portscan schema creates disconnected graph

**Location:** `src/easm/runners/schemas.py:163-175`

**Root cause:** The `portscan()` schema creates a `hostname` entity AND an `ip` entity but returns no `RelationshipCandidate` linking them. The graph shows a hostname and an IP with no edge between them.

**Priority:** 🟢 **Medium** — Add `< hostname >--[resolves_to]--> < ip >` relationship.

---

## Structural Blind Spots (12)

Standard EASM operations that are **not implemented** in any form:

| Missing capability | Why it matters | Effort |
|---|---|---|
| **HTTP body / JS endpoint extraction** | Discovers API endpoints, hidden paths, internal hostnames, leaked secrets from page HTML and JS bundles | 2-3 days |
| **Favicon hash matching** | Most reliable technique for finding org-related assets (Shodan favicon hash search) | 1 day |
| **SPF include: recursive expansion** | v=spf1 include:_spf.google.com → discovers Google Apps tenant, GCP usage | 2 days |
| **DNS zone transfer (AXFR)** | Discovers internal DNS records when misconfigured | few hours |
| **Tracker/advertising IDs** | Google Analytics / Facebook Pixel IDs identify related properties across domains | 1 day |
| **Screenshot of ALL hostnames** | Currently only seed domains. Misses 95%+ of visual coverage | few hours |
| **Cloud bucket content enumeration** | Checking if bucket listing is enabled, scanning for sensitive files | 2 days |
| **Port → service → vulnerability bridge** | portscan finds open ports but no deeper service probing (banner grab, TLS version check) | 3-5 days |
| **CNAME chain full unrolling** | DNS resolver only follows 1 hop. Takeover handler follows up to 10 but stores as attribute | 1 day |
| **Technology → CVE matching bridge** | wappalyzer detects tech but doesn't auto-fire cpe_vuln_enrich (only shodan_enrich does) | 1 day |
| **WHOIS graph expansion** | reverse_whois data is collected but schema is missing — no domain graph is built | few hours |
| **HSTS / SPF / DMARC / TLS version rule** | Data is collected but no correlation rule checks it | 1 day |

Total estimated effort to close all blind spots: **~3-4 weeks** for a single engineer.

---

## Noise Amplifiers (7)

Design patterns that produce HIGH-severity findings for non-exploitable conditions:

| Amplifier | Mechanism | Noise estimate |
|---|---|---|
| **takeover_risk = ANY signal** | `provider:aws_cloudfront` (perfectly healthy CDN) → HIGH takeover finding | 70-85% of takeover findings are FP |
| **No finding deduplication** | Findings table has no `ON CONFLICT` upsert — same finding re-inserted every pivot cycle | 10-100x volume amplification |
| **saas_hosted_infrastructure regex `.+`** | Every hostname with a CNAME matches | ~95% of findings are noise |
| **dev_or_test_system regex `.*dev.*`** | Matches `developer.mozilla.org`, `devastating.com`, etc. | ~80% of findings are noise |
| **high_risk_port_exposed includes SSH 22** | SSH on port 22 is standard practice, not high risk | ~90% volume reduction (SSH alone) |
| **stale_certificate matches ALL certs** | No expiry check — every cert is a finding | 100% of findings are meaningless |
| **Always HIGH / confidence=unknown** | No severity gradation — scanner-side DNS failure = same severity as confirmed RCE | Defenders can't triage by severity |

---

## What Works Well

It's not all bad. These are genuinely correct and well-implemented:

- **Subprocess containment**: `shell=False`, list-based argv, timeouts, async execution
- **Loop protection**: first-write-wins entity upsert prevents diamond rediscovery
- **Apex-coverage optimization**: skips subdomain pivots when apex already processed
- **Cooldown system**: per-entity-type per-pivot-type cooldown prevents aggressive re-scanning
- **Priority queueing**: DNS resolve (100) >> enrichment (10) — cheap pivots before expensive ones
- **Classification gate**: saas-hosted / third-party entities don't burn Shodan quota
- **SQL parameterization**: Every query uses `$N` placeholders — no injection
- **asyncpg for all DB work**: Non-blocking throughout
- **Subfinder / crtsh / shodan handlers**: Correctly parse well-known API output formats

---

## Priority Fix Roadmap

| Priority | Fix | Effort | Impact |
|---|---|---|---|
| 🔴 P0 | Fix 5 broken YAML schemas (add `$raw.X` fallthrough to Python) | 2 hours | Restores nuclei, RDAP, CPE, CommonCrawl, cloud_enum output |
| 🔴 P0 | Add `reverse_whois` output schema | 30 min | Restores highest-signal domain-discovery pivot |
| 🔴 P0 | Filter IP Address entries from certstream SAN parsing | 15 min | Stops garbage entities from entering the graph |
| 🟡 P1 | Switch takeover severity: `http_unconfirmed` = LOW, `http_fingerprint` = HIGH | 1 hour | Eliminates 70-85% of HIGH takeover FPs |
| 🟡 P1 | Add finding dedup (`INSERT ... ON CONFLICT` with rule_id+entity_ids fingerprint) | 1 day | Eliminates 90%+ of volume amplification |
| 🟡 P1 | Delete `stale_certificate.yaml` and `saas_hosted_infrastructure.yaml` | 15 min | Two highest-volume noise sources gone |
| 🟡 P1 | Fix `outlier_country.yaml` field path + make countries configurable | 1 hour | Fixes broken rule |
| 🟢 P2 | Fix `normalize_entity_value` for IP/ASN/wildcards/quotes | 1 day | Removes duplicate entity pollution |
| 🟢 P2 | Fix screenshot runner to iterate hostnames | 1 hour | Restores visual coverage to 95%+ of surface |
| 🟢 P2 | Remove SSH 22 from high_risk_port rule | 5 min | 90% volume reduction on port exposure |

---

## How to Read the Specialist Reports

Each specialist agent produced a full standalone report with file:line references for every claim:

- **Takeover Detection** — Inline in orchestrator turn. Covers Types A-G FP classification, substring match bug, RDAP data unused.
- **Correlation Rules** — `CORRELATION_AUDIT.md`. Per-rule signal/noise analysis (9 rules), engine limitations, field path bugs.
- **Pivot Chain** — `PIVOT_CHAIN_AUDIT.md`. Full graph diagram, 18-edge inventory, 12 gap analyses, chain depth tracing.
- **Runner Schemas** — `SCHEMA_AUDIT_REPORT.md`. All 35+ schemas evaluated, 5 broken YAML files confirmed via sample data, normalization bugs, entity type drift.
